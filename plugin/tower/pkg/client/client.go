/*
Copyright 2021 The Everoute Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"k8s.io/apimachinery/pkg/util/uuid"
	"k8s.io/klog"

	"github.com/everoute/everoute/plugin/tower/pkg/schema"
	"github.com/everoute/everoute/plugin/tower/pkg/utils"
)

type Client struct {
	URL      string    `yaml:"url"`
	UserInfo *UserInfo `yaml:"user_info"`

	// AllowInsecure set whether to check the server certificates
	AllowInsecure bool

	// Dialer dial websocket connecting to graphql server for subscription.
	// If nil, websocket.DefaultDialer will be used.
	Dialer *websocket.Dialer

	// HTTPClient dial http connecting to graphql server for query.
	// If nil, http.DefaultClient will be used.
	HTTPClient *http.Client

	// If set, mutation will wait task down.
	TaskMonitor TaskMonitor

	tokenLock sync.RWMutex
	token     string
}

const (
	responseChanLenth = 10
)

// Subscription subscribe change of objects, subscribe will stop when get response error, subscribe
// also could be stopped by run return function stopWatch().
func (c *Client) Subscription(req *Request) (respCh <-chan Response, stopWatch func(), err error) {
	var respChan = make(chan Response, responseChanLenth)

	msg := Message{
		ID:   string(uuid.NewUUID()),
		Type: StartMsg,
	}

	msg.PayLoad, err = json.Marshal(req)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal request: %s", err)
	}

	conn, err := c.newWebsocketConn()
	if err != nil {
		return nil, nil, err
	}

	if err = conn.WriteJSON(msg); err != nil {
		conn.Close()
		return nil, nil, fmt.Errorf("failed to write message %v: %s", msg, err)
	}

	var stopChan = make(chan struct{})
	go loopReadMessage(conn, respChan, stopChan)

	return respChan, closeChanFunc(stopChan), nil
}

// Query send query request to tower
func (c *Client) Query(req *Request) (*Response, error) {
	var reqBody, respBody bytes.Buffer
	var resp Response
	var contentType string

	if err := encodeRequest(req, &contentType, &reqBody); err != nil {
		return nil, fmt.Errorf("failed to encode request: %s", err)
	}

	klog.V(10).Infof("query request body %s", reqBody.String())

	r, err := http.NewRequestWithContext(context.TODO(), http.MethodPost, c.URL, &reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed call http.NewRequest: %s", err)
	}
	c.setScheme(r.URL, false)
	c.setHeader(r.Header, contentType, false)

	httpResp, err := c.httpClient().Do(r)
	if err != nil {
		return nil, err
	}
	defer httpResp.Body.Close()

	if _, err := io.Copy(&respBody, httpResp.Body); err != nil {
		return nil, fmt.Errorf("failed to read response body: %s", err)
	}

	if err := json.NewDecoder(&respBody).Decode(&resp); err != nil {
		return nil, fmt.Errorf("server response code: %d, err: %s", httpResp.StatusCode, err)
	}

	if taskID := httpResp.Header.Get("x-task-id"); taskID != "" && c.TaskMonitor != nil {
		task, err := c.TaskMonitor.WaitForTask(context.Background(), taskID)
		if err != nil {
			return nil, err
		}
		if task.ErrorCode != nil && task.ErrorMessage != nil {
			return nil, &ResponseError{
				Message: *task.ErrorMessage,
				Code:    ErrorCode(*task.ErrorCode),
			}
		}
	}

	return &resp, nil
}

func encodeRequest(req *Request, contentType *string, w io.Writer) error {
	m := LoadJSONPathUploadMap("variables", req.Variables)
	if len(m) == 0 {
		return json.NewEncoder(w).Encode(req)
	}

	indexJSONPathMap := map[string][]string{}
	index := 0
	for jsonPath := range m {
		indexJSONPathMap[strconv.Itoa(index)] = []string{jsonPath}
		index++
	}

	multipartWriter := multipart.NewWriter(w)
	defer multipartWriter.Close()

	// Content-Disposition: form-data; name="operations"
	fw, err := multipartWriter.CreateFormField("operations")
	if err != nil {
		return fmt.Errorf("encode request: %s", err)
	}
	err = json.NewEncoder(fw).Encode(req)
	if err != nil {
		return fmt.Errorf("encode request: %s", err)
	}

	// Content-Disposition: form-data; name="map"
	fw, err = multipartWriter.CreateFormField("map")
	if err != nil {
		return fmt.Errorf("encode request: %s", err)
	}
	err = json.NewEncoder(fw).Encode(indexJSONPathMap)
	if err != nil {
		return fmt.Errorf("encode request: %s", err)
	}

	// Content-Disposition: form-data; name="0"; filename="fileName"
	// Content-Type: application/octet-stream
	for index, jsonPath := range indexJSONPathMap {
		upload := m[jsonPath[0]]
		fw, err = multipartWriter.CreateFormFile(index, upload.FileName)
		if err != nil {
			return fmt.Errorf("encode request: %s", err)
		}
		_, err = io.Copy(fw, upload.File)
		if err != nil {
			return fmt.Errorf("encode request: %s", err)
		}
	}

	*contentType = multipartWriter.FormDataContentType()
	return nil
}

// Auth send login request to tower, and save token
func (c *Client) Auth() (string, error) {
	var token string

	if c.UserInfo == nil {
		return "", fmt.Errorf("anonymous login to server not allow")
	}

	authRequest := &Request{
		Query:     "mutation($data: LoginInput!) {login(data: $data) {token}}",
		Variables: map[string]interface{}{"data": c.UserInfo},
	}
	resp, err := c.Query(authRequest)
	if err != nil {
		return "", fmt.Errorf("failed to login tower: %s", err)
	}

	if len(resp.Errors) != 0 {
		return "", fmt.Errorf("receive unexpected errors: %v", resp.Errors)
	}

	tokenRaw := utils.LookupJSONRaw(resp.Data, "login", "token")
	err = json.Unmarshal(tokenRaw, &token)
	if err != nil {
		return "", fmt.Errorf("failed to unmarshal %s to token: %s", tokenRaw, err)
	}

	c.setToken(token)
	return token, nil
}

func (c *Client) newWebsocketConn() (*websocket.Conn, error) {
	header := http.Header{}
	u, err := url.Parse(c.URL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse url %s: %s", c.URL, err)
	}

	c.setScheme(u, true)
	c.setHeader(header, "", true)

	conn, resp, err := c.dialer().Dial(u.String(), header)
	if err != nil {
		return nil, fmt.Errorf("failed to dialer %s: %s", u, err)
	}
	resp.Body.Close()

	err = c.initWebsocketConn(conn)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to init connection: %s", err)
	}

	return conn, nil
}

func (c *Client) initWebsocketConn(conn *websocket.Conn) error {
	initMsg := Message{Type: ConnectionInitMsg}
	initPayload := make(map[string]interface{})

	if token := c.getToken(); token != "" {
		initPayload["Authorization"] = token
	}

	if err := conn.WriteJSON(initMsg); err != nil {
		return fmt.Errorf("send connection init message: %s", err)
	}

	var msg Message
	if err := conn.ReadJSON(&msg); err != nil {
		return fmt.Errorf("read connection ack message: %s", err)
	}

	if msg.Type != ConnectionAckMsg {
		return fmt.Errorf("expect receieve ack message")
	}

	return nil
}

func (c *Client) setHeader(header http.Header, contentType string, websocket bool) {
	if contentType == "" {
		contentType = "application/json"
	}

	header.Set("Content-Type", contentType)
	header.Set("Accept", "application/json")

	if token := c.getToken(); token != "" {
		header.Set("Authorization", token)
	}

	if websocket {
		header.Set("Sec-Websocket-Protocol", "graphql-ws")
	}
}

// when use http, set scheme https/http; when use ws, set scheme wss/ws.
func (c *Client) setScheme(u *url.URL, websocket bool) {
	var secure bool

	switch u.Scheme {
	case "https", "wss":
		secure = true
	}

	u.Scheme = "http"
	if websocket {
		u.Scheme = "ws"
	}

	if secure {
		u.Scheme = fmt.Sprintf("%ss", u.Scheme)
	}
}

func (c *Client) setToken(token string) {
	c.tokenLock.Lock()
	defer c.tokenLock.Unlock()
	c.token = token
}

func (c *Client) getToken() string {
	c.tokenLock.RLock()
	defer c.tokenLock.RUnlock()
	return c.token
}

func (c *Client) dialer() *websocket.Dialer {
	if c.Dialer == nil {
		// #nosec G402
		return &websocket.Dialer{
			Proxy:            http.ProxyFromEnvironment,
			HandshakeTimeout: 45 * time.Second,
			TLSClientConfig:  &tls.Config{InsecureSkipVerify: c.AllowInsecure},
		}
	}
	return c.Dialer
}

// we reuse the insecureClient to reuse the underlay tcp connection
var insecureClient = func() *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} // #nosec G402
	return &http.Client{Transport: transport}
}()

func (c *Client) httpClient() *http.Client {
	if c.HTTPClient == nil {
		if c.AllowInsecure {
			return insecureClient
		}
		return http.DefaultClient
	}
	return c.HTTPClient
}

// loopReadMessage loop read message from conn until read error or get signal from stopChan
func loopReadMessage(conn *websocket.Conn, respChan chan<- Response, stopChan chan struct{}) {
	// we close the connection before return
	// goroutines read from the connection would get an error
	defer conn.Close()

	// we start a new goroutine to handle WebSocket response
	// make sure when stopChan close, we can return immediately
	go func() {
		// to make sure no data race happens, we should close respChan
		// and write to respChan in the same goroutine
		defer close(respChan)
		for {
			resp := readConnResponse(conn)
			select {
			case <-stopChan:
				// check if already stop before send to response chan
				return
			default:
				respChan <- resp
				if len(resp.Errors) != 0 {
					// stop watch when get response error
					closeChanFunc(stopChan)()
					return
				}
			}
		}
	}()

	<-stopChan
}

// readConnResponse would block until message from the connection or the connection closed
func readConnResponse(conn *websocket.Conn) Response {
	var msg Message
	var resp Response

loopread:
	for {
		if err := conn.ReadJSON(&msg); err != nil {
			return connectErrorMessage("error read response message: %s", err)
		}

		switch msg.Type {
		case ConnectionKeepAliveMsg:
			continue // ignore keepalived request message
		case DataMsg:
			break loopread
		case ErrorMsg, ConnectionErrorMsg:
			return connectErrorMessage(string(msg.PayLoad))
		case CompleteMsg:
			return connectErrorMessage("unexpect complete msg, payload: %+v", string(msg.PayLoad))
		default:
			return connectErrorMessage("unknow message type %s, payload: %+v", msg.Type, string(msg.PayLoad))
		}
	}

	if err := json.Unmarshal(msg.PayLoad, &resp); err != nil {
		return connectErrorMessage("error unmarshal json message: %s", err)
	}

	return resp
}

func connectErrorMessage(format string, a ...interface{}) Response {
	var resp Response
	resp.Errors = append(resp.Errors, ResponseError{
		Message: fmt.Sprintf(format, a...),
		Code:    WebsocketConnectError,
	})
	return resp
}

// closeChanFunc close chan once, prevent panic of multiple close chan.
func closeChanFunc(ch chan struct{}) func() {
	return func() {
		select {
		case _, ok := <-ch:
			// skipped when chan already closed
			if ok {
				close(ch)
			}
		default:
			close(ch)
		}
	}
}

type TaskMonitor interface {
	WaitForTask(ctx context.Context, taskID string) (*schema.Task, error)
}

// LoadJSONPathUploadMap get all upload from the object
func LoadJSONPathUploadMap(pathPrefix string, obj interface{}) map[string]Upload {
	m := make(map[string]Upload)
	if obj != nil {
		setJSONPathUploadMap(m, pathPrefix, reflect.ValueOf(obj))
	}
	return m
}

func setJSONPathUploadMap(m map[string]Upload, parentJSONPath string, obj reflect.Value) {
	switch obj.Type().Kind() {
	case reflect.Interface, reflect.Ptr:
		if !obj.IsNil() {
			setJSONPathUploadMap(m, parentJSONPath, obj.Elem())
		}

	case reflect.Array, reflect.Slice:
		for i := 0; i < obj.Len(); i++ {
			setJSONPathUploadMap(m, fmt.Sprintf("%s.%d", parentJSONPath, i), obj.Index(i))
		}

	case reflect.Map:
		for _, mapKey := range obj.MapKeys() {
			setJSONPathUploadMap(m, fmt.Sprintf("%s.%s", parentJSONPath, mapKey), obj.MapIndex(mapKey))
		}

	case reflect.Struct:
		if obj.Type() == reflect.TypeOf(Upload{}) {
			m[parentJSONPath] = obj.Interface().(Upload)
			return
		}
		for i := 0; i < obj.NumField(); i++ {
			jsonTagName := getFieldJSONTag(obj.Type().Field(i))
			if jsonTagName == "" {
				continue
			}
			setJSONPathUploadMap(m, fmt.Sprintf("%s.%s", parentJSONPath, jsonTagName), obj.Field(i))
		}
	}
}

func getFieldJSONTag(field reflect.StructField) string {
	jsonTag := field.Tag.Get("json")

	if field.PkgPath != "" || field.Anonymous || jsonTag == "-" {
		return ""
	}

	tag := strings.Split(jsonTag, ",")[0]
	if tag != "" {
		return tag
	}
	return field.Name
}
