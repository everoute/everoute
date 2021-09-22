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

package fake

import (
	"context"
	"net/http"
	"sync"

	"github.com/99designs/gqlgen/graphql/handler"
	"github.com/gorilla/websocket"
	"k8s.io/klog"

	"github.com/everoute/everoute/plugin/tower/pkg/client"
	"github.com/everoute/everoute/plugin/tower/pkg/server/fake/conn"
	"github.com/everoute/everoute/plugin/tower/pkg/server/fake/graph/generated"
	"github.com/everoute/everoute/plugin/tower/pkg/server/fake/graph/resolver"
	"github.com/everoute/everoute/plugin/tower/pkg/server/fake/graph/resolver/tracker"
)

// Server mock the tower server, you can query, subscribe or login to the server.
// Use server.NewClient() connect to the mock server.
type Server struct {
	serveLock sync.Mutex
	stopCh    chan struct{}

	resolvers *resolver.Resolver
	listener  *conn.Listener
}

// NewServer creates a new instance of Server.
func NewServer() *Server {
	return &Server{
		resolvers: resolver.New(),
		listener:  conn.Listen(),
	}
}

// NewClient creates a client that can connect to the server.
func (s *Server) NewClient() *client.Client {
	return &client.Client{
		URL:        "ws://127.0.0.1:0",
		Dialer:     &websocket.Dialer{NetDialContext: s.listener.DialContext},
		HTTPClient: &http.Client{Transport: s.listener},
	}
}

// TrackerFactory let you can mock server resources.
func (s *Server) TrackerFactory() *tracker.Factory {
	return s.resolvers.TrackerFactory()
}

// Serve start Server if is stopped.
func (s *Server) Serve() {
	s.serveLock.Lock()
	defer s.serveLock.Unlock()

	if s.stopped() {
		s.stopCh = make(chan struct{})
		go func() {
			if err := s.start(); err != nil {
				klog.Fatalf("unable start server: %s", err)
			}
		}()
	}
}

// Serve stop Server if is running.
func (s *Server) Stop() {
	s.serveLock.Lock()
	defer s.serveLock.Unlock()

	if !s.stopped() {
		close(s.stopCh)
	}
}

func (s *Server) stopped() bool {
	if s.stopCh == nil {
		return true
	}

	select {
	case <-s.stopCh:
		return true
	default:
		return false
	}
}

func (s *Server) start() error {
	executable := generated.NewExecutableSchema(generated.Config{Resolvers: s.resolvers})

	server := http.Server{
		Handler: handler.NewDefaultServer(executable),
	}

	serveErr := make(chan error)
	defer close(serveErr)

	go func() {
		err := server.Serve(s.listener)
		select {
		case serveErr <- err:
		default:
		}
	}()

	select {
	case <-s.stopCh:
		return server.Shutdown(context.Background())
	case err := <-serveErr:
		return err
	}
}
