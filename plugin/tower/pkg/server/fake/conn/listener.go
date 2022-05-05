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

package conn

import (
	"context"
	"fmt"
	"net"
	"time"

	"google.golang.org/grpc/test/bufconn"
)

// ListenerDialer embeds net.Listener and DialContext,
// DialContext create a new connection to the listener
type ListenerDialer interface {
	net.Listener
	DialContext(ctx context.Context, _, _ string) (net.Conn, error)
}

// TCP listens and dials on a TCP address
type TCP struct {
	net.Listener
	addr string
}

func (l *TCP) DialContext(ctx context.Context, _, _ string) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, "tcp", l.addr)
}

// NewTCP returns a ListenerDialer that listens and dial on TCP
func NewTCP(addr string) (ListenerDialer, error) {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	return &TCP{Listener: listener, addr: addr}, nil
}

// MustNewTCP returns a ListenerDialer or panic on error
func MustNewTCP(addr string) ListenerDialer {
	listener, err := NewTCP(addr)
	if err != nil {
		panic(err.Error())
	}
	return listener
}

// Buff implements ListenerDialer localed. It can use to start a mock server,
// client connect to server with its transport or dial func.
type Buff struct {
	*bufconn.Listener
	timeout time.Duration
}

func NewBuff() ListenerDialer {
	l := &Buff{timeout: 5 * time.Second, Listener: bufconn.Listen(1 << 12)} // 4 KB
	return l
}

// DialContext return new net.Conn connection to the Buff Listener
func (l *Buff) DialContext(ctx context.Context, _, _ string) (net.Conn, error) {
	var conn net.Conn
	var err error
	var done = make(chan struct{})

	go func() {
		conn, err = l.Dial()
		select {
		case done <- struct{}{}:
			close(done)
		default:
			if err == nil {
				_ = conn.Close()
			}
		}
	}()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-done:
		return conn, err
	case <-time.After(l.timeout):
		return nil, fmt.Errorf("dial timeout")
	}
}
