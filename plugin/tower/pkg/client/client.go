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
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"k8s.io/apimachinery/pkg/util/uuid"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/klog/v2"

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

	TokenFile      string
	writeTokenLock sync.Mutex
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
func (c *Client) Query(ctx context.Context, req *Request) (*Response, error) {
	request, err := EncodeRequest(req)
	if err != nil {
		return nil, fmt.Errorf("failed to encode request: %s", err)
	}

	klog.V(10).Infof("query request body %s", request.String())

	r, err := http.NewRequestWithContext(ctx, http.MethodPost, c.URL, request.GetReader())
	if err != nil {
		return nil, fmt.Errorf("failed call http.NewRequest: %s", err)
	}
	c.setScheme(r.URL, false)
	c.setHeader(r.Header, request.ContentType(), false)

	httpResp, err := c.httpClient().Do(r)
	if err != nil {
		return nil, err
	}
	defer httpResp.Body.Close()

	var resp Response

	if err := json.NewDecoder(httpResp.Body).Decode(&resp); err != nil {
		return nil, fmt.Errorf("server response code: %d, err: %s", httpResp.StatusCode, err)
	}

	if taskID := httpResp.Header.Get("x-task-id"); taskID != "" && c.TaskMonitor != nil {
		task, err := c.TaskMonitor.WaitForTask(ctx, taskID)
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

// Auth send login request to tower, and save token
func (c *Client) Auth(ctx context.Context) (string, error) {
	var token string

	if c.UserInfo == nil {
		return "", fmt.Errorf("anonymous login to server not allow")
	}

	authRequest := &Request{
		Query:     "mutation($data: LoginInput!) {login(data: $data) {token}}",
		Variables: map[string]interface{}{"data": c.UserInfo},
	}
	resp, err := c.Query(ctx, authRequest)
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

	c.SetToken(token)
	go c.WriteToken(ctx)
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

func (c *Client) SetToken(token string) {
	c.tokenLock.Lock()
	defer c.tokenLock.Unlock()
	c.token = token
}

func (c *Client) WriteToken(ctx context.Context) {
	if c.TokenFile == "" {
		klog.Error("It doesn't set token file, can't write tower token")
		return
	}
	c.writeTokenLock.Lock()
	defer c.writeTokenLock.Unlock()

	_ = wait.PollUntilContextCancel(ctx, 3*time.Second, true, func(context.Context) (bool, error) {
		err := c.writeToken()
		return err == nil, nil
	})
}

func (c *Client) writeToken() error {
	data, err := os.ReadFile(c.TokenFile)
	oldToken := ""
	if err != nil {
		if !os.IsNotExist(err) {
			klog.Errorf("Failed to read old token from file %s: %s", c.TokenFile, err)
			return err
		}
	} else {
		oldToken = string(data)
	}

	newToken := c.getToken()
	if newToken == "" || oldToken == newToken {
		return nil
	}
	data = []byte(newToken)
	err = os.WriteFile(c.TokenFile, data, 0600)
	if err == nil {
		klog.Infof("Success write tower token %s to file %s", newToken, c.TokenFile)
	} else {
		klog.Errorf("Failed to write tower token to file %s: %s", c.TokenFile, err)
	}
	return err
}

func (c *Client) getToken() string {
	c.tokenLock.RLock()
	defer c.tokenLock.RUnlock()
	return c.token
}

//nolint:gosec
func (c *Client) dialer() *websocket.Dialer {
	if c.Dialer == nil {
		return &websocket.Dialer{
			Proxy:            http.ProxyFromEnvironment,
			HandshakeTimeout: 45 * time.Second,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: c.AllowInsecure,
			},
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
