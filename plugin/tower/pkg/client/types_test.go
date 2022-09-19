/*
Copyright 2022 The Everoute Authors.

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

package client_test

import (
	"encoding/json"
	"fmt"
	"testing"

	. "github.com/onsi/gomega"

	"github.com/everoute/everoute/plugin/tower/pkg/client"
)

func TestResponseErrorUnmarshalJSON(t *testing.T) {
	testCases := []struct {
		data       string
		expectCode client.ErrorCode
	}{
		{
			data:       `{}`,
			expectCode: "",
		},
		{
			data:       `{"code":200}`,
			expectCode: client.ErrorCode("200"),
		},
		{
			data:       `{"code":"WEBSOCKET_CONNECT_ERROR"}`,
			expectCode: client.WebsocketConnectError,
		},
	}

	for index, tt := range testCases {
		t.Run(fmt.Sprintf("test%d", index), func(t *testing.T) {
			RegisterTestingT(t)

			var responseError client.ResponseError
			Expect(json.Unmarshal([]byte(tt.data), &responseError)).ShouldNot(HaveOccurred())
			Expect(responseError.Code).Should(Equal(tt.expectCode))
		})
	}
}
