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

package conn_test

import (
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"testing"

	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/util/rand"

	"github.com/everoute/everoute/plugin/tower/pkg/server/fake/conn"
)

func TestBuffListenerDialer(t *testing.T) {
	tests := []conn.ListenerDialer{
		conn.NewBuff(),
		conn.MustNewTCP(fmt.Sprintf(":%d", rand.IntnRange(30000, 65535))),
	}

	for index, tt := range tests {
		t.Run(fmt.Sprintf("test%d", index), func(t *testing.T) {
			listenAndDialWithTestingT(t, tt)
		})
	}
}

func listenAndDialWithTestingT(t *testing.T, ld conn.ListenerDialer) {
	RegisterTestingT(t)
	server := newServer()

	go server.Serve(ld) // nolint: errcheck
	defer func() {
		Expect(server.Shutdown(context.Background())).Should(Succeed())
	}()

	resp, err := (&http.Client{
		Transport: &http.Transport{DialContext: ld.DialContext},
	}).Do(&http.Request{
		Method: "GET",
		URL:    &url.URL{Scheme: "http", Host: "localhost:0", Path: "/foo/bar"},
	})
	Expect(err).Should(Succeed())
	Expect(resp.StatusCode).Should(Equal(http.StatusOK))

	body, _ := ioutil.ReadAll(resp.Body)
	Expect(body).Should(Equal([]byte{'o', 'k'}))
	Expect(resp.Body.Close()).Should(Succeed())
}

func newServer() *http.Server {
	var handler = func(resp http.ResponseWriter, _ *http.Request) {
		resp.WriteHeader(http.StatusOK)
		_, _ = resp.Write([]byte("ok"))
	}
	return &http.Server{
		Handler: http.HandlerFunc(handler),
	}
}
