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
	"net/http"
	"time"

	"google.golang.org/grpc/test/bufconn"
)

// Listener implements net.Listener and http.RoundTripper localed. It can used to
// start a mock server, client connect to server with its transport or dial func.
type Listener struct {
	timeout time.Duration

	*bufconn.Listener
	http.RoundTripper
}

func Listen() *Listener {
	l := &Listener{timeout: 5 * time.Second, Listener: bufconn.Listen(1 << 12)} // 4 KB
	l.RoundTripper = &http.Transport{DialContext: l.DialContext}
	return l
}

// DialContext return new net.Conn connection to Listener.
func (l *Listener) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	var conn net.Conn
	var err error

	done := make(chan struct{})
	defer close(done)

	go func() {
		conn, err = l.Dial()
		select {
		case done <- struct{}{}:
		default:
			if err == nil {
				conn.Close()
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
