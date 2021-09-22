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
	"encoding/json"
	"fmt"
)

type Request struct {
	Query         string                 `json:"query"`
	OperationName string                 `json:"operationName,omitempty"`
	Variables     map[string]interface{} `json:"variables,omitempty"`
}

type Response struct {
	Data   json.RawMessage `json:"data"`
	Errors []ResponseError `json:"errors,omitempty"`
}

type ResponseError struct {
	Message string    `json:"message"`
	Code    ErrorCode `json:"code,omitempty"`
}

type ErrorCode string

const (
	PermissionDenied      ErrorCode = "PERMISSION_DENIED"
	LoginFailed           ErrorCode = "LOGIN_FAILED"
	UserNotFound          ErrorCode = "USER_NOT_FOUND"
	UserPasswordIncorrect ErrorCode = "USER_PASSWORD_INCORRECT"
	NotMatchUser          ErrorCode = "NOT_MATCH_USER"
	LoadTokenFailed       ErrorCode = "LOAD_TOKEN_FAILED" // #nosec
	WebsocketConnectError ErrorCode = "WEBSOCKET_CONNECT_ERROR"
)

func (e ResponseError) Error() string {
	return fmt.Sprintf("message: %s, errcode: %s", e.Message, e.Code)
}

func HasAuthError(errors []ResponseError) bool {
	for _, err := range errors {
		switch err.Code {
		case PermissionDenied, LoginFailed, UserNotFound, UserPasswordIncorrect, NotMatchUser, LoadTokenFailed:
			return true
		}
	}
	return false
}

// Message is the request/response type when use the websocket connection
type Message struct {
	ID   string      `json:"id,omitempty"`
	Type MessageType `json:"type"`

	PayLoad json.RawMessage `json:"payload,omitempty"`
}

type MessageType string

const (
	ConnectionInitMsg      MessageType = "connection_init"      // Client -> Server
	ConnectionTerminateMsg MessageType = "connection_terminate" // Client -> Server
	StartMsg               MessageType = "start"                // Client -> Server
	StopMsg                MessageType = "stop"                 // Client -> Server
	ConnectionAckMsg       MessageType = "connection_ack"       // Server -> Client
	ConnectionErrorMsg     MessageType = "connection_error"     // Server -> Client
	DataMsg                MessageType = "data"                 // Server -> Client
	ErrorMsg               MessageType = "error"                // Server -> Client
	CompleteMsg            MessageType = "complete"             // Server -> Client
	ConnectionKeepAliveMsg MessageType = "ka"                   // Server -> Client
)

type UserInfo struct {
	Username string `json:"username" yaml:"username"`
	Password string `json:"password" yaml:"password"`
	Source   string `json:"source" yaml:"source"`
}

// MutationEvent is the event subscribed from tower
type MutationEvent struct {
	Mutation       MutationType    `json:"mutation"`
	PreviousValues json.RawMessage `json:"previousValues"`
	Node           json.RawMessage `json:"node"`
}

type MutationType string

const (
	CreateEvent MutationType = "CREATED"
	DeleteEvent MutationType = "DELETED"
	UpdateEvent MutationType = "UPDATED"
)
