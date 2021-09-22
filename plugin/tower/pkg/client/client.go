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
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"

	"github.com/gorilla/websocket"
	"k8s.io/apimachinery/pkg/util/uuid"
	"k8s.io/klog"

	"github.com/everoute/everoute/plugin/tower/pkg/utils"
)

type Client struct {
	URL      string    `yaml:"url"`
	UserInfo *UserInfo `yaml:"user_info"`

	// Dialer dial websocket connecting to graphql server for subscription.
	// If nil, websocket.DefaultDialer will be used.
	Dialer *websocket.Dialer

	// HTTPClient dial http connecting to graphql server for query.
	// If nil, http.DefaultClient will be used.
	HTTPClient *http.Client

	tokenLock sync.RWMutex
	token     string
}

const (
	responseChanLenth = 10
)

// subscription subscribe change of objects, subscribe will stop when get response error, subscribe
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
	go lookReadMessage(conn, respChan, stopChan)

	return respChan, closeChanFunc(stopChan), nil
}

// query send query request to tower
func (c *Client) Query(req *Request) (*Response, error) {
	var reqBody, respBody bytes.Buffer
	var resp Response

	if err := json.NewEncoder(&reqBody).Encode(req); err != nil {
		return nil, fmt.Errorf("failed to encode request: %s", err)
	}

	klog.V(10).Infof("query request body %s", reqBody.String())

	r, err := http.NewRequestWithContext(context.TODO(), http.MethodPost, c.URL, &reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed call http.NewRequest: %s", err)
	}
	c.setScheme(r.URL, false)
	c.setHeader(r.Header, false)

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

	return &resp, nil
}

// query send login request to tower, and save token
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
	c.setHeader(header, true)

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

func (c *Client) setHeader(header http.Header, websocket bool) {
	header.Set("Content-Type", "application/json")
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
		return websocket.DefaultDialer
	}
	return c.Dialer
}

func (c *Client) httpClient() *http.Client {
	if c.HTTPClient == nil {
		return http.DefaultClient
	}
	return c.HTTPClient
}

// lookReadMessage loop read message from conn until read error or get signal from stopChan
func lookReadMessage(conn *websocket.Conn, respChan chan<- Response, stopChan chan struct{}) {
	defer close(respChan)
	defer conn.Close()

	go func() {
		for {
			resp := readConnResponse(conn)
			select {
			case <-stopChan:
				// check if already stop before send to response chan
				return
			default:
				respChan <- resp
				if len(resp.Errors) != 0 {
					// stop watch if get response error
					closeChanFunc(stopChan)()
					return
				}
			}
		}
	}()

	<-stopChan
}

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
