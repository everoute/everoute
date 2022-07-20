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
	"testing"

	"k8s.io/apimachinery/pkg/util/rand"
)

func TestServer_ServeStop(t *testing.T) {
	server := NewServer(nil)

	for i := 0; i < 20; i++ {
		if rand.IntnRange(1, 2)%2 == 0 {
			server.Serve()
		} else {
			server.Stop()
		}
	}
}

func TestServeStop(t *testing.T) {
	server := NewServer(nil)
	// should no data race when server immediately stop, see issue: #430
	server.Serve()
	defer server.Stop()
}
