/*
Copyright 2021 The Lynx Authors.

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
	"io/ioutil"
	"net/http"
	"testing"

	. "github.com/onsi/gomega"
)

func TestListener(t *testing.T) {
	RegisterTestingT(t)

	server := fakeServer()
	listener := Listen()

	// run server with buff listener
	go server.Serve(listener)
	defer server.Shutdown(context.Background())

	client := http.Client{Transport: listener}

	resp, err := client.Get("http://localhost:0/fake")
	Expect(err).Should(Succeed())
	Expect(resp.StatusCode).Should(Equal(http.StatusOK))

	body, err := ioutil.ReadAll(resp.Body)
	Expect(err).Should(Succeed())
	Expect(body).Should(Equal([]byte("ok")))
}

func fakeServer() *http.Server {
	var fakeHandler = func(resp http.ResponseWriter, _ *http.Request) {
		resp.WriteHeader(http.StatusOK)
		resp.Write([]byte("ok"))
	}
	return &http.Server{
		Handler: http.HandlerFunc(fakeHandler),
	}
}
