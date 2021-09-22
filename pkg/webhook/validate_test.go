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

package webhook_test

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	admv1 "k8s.io/api/admission/v1"

	"github.com/everoute/everoute/pkg/webhook"
)

// validate implements handlers.Validate, with allowed always true.
type validate struct{}

func (validate) Validate(*admv1.AdmissionReview) *admv1.AdmissionResponse {
	return &admv1.AdmissionResponse{
		Allowed: true,
	}
}

func TestHandleValidate(t *testing.T) {
	ts := httptest.NewServer((&webhook.ValidateWebhook{}).Handler(validate{}))
	defer ts.Close()

	client := ts.Client()

	tests := []struct {
		name, url, body string
		code            int
		allowed         bool
	}{
		{
			name: "empty-request-body",
			url:  ts.URL,
			body: "",
			code: http.StatusBadRequest,
		},
		{
			name:    "unexpect-request-body",
			url:     ts.URL,
			body:    "xxxxx",
			code:    http.StatusOK,
			allowed: false,
		},
		{
			name: "validate-request",
			url:  ts.URL,
			body: func() string {
				ar, _ := json.Marshal(&admv1.AdmissionReview{
					Request: &admv1.AdmissionRequest{
						Name: "MockRequest",
					},
				})
				return string(ar)
			}(),
			code:    http.StatusOK,
			allowed: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			allowed := false
			got, _ := client.Post(tt.url, "application/json", strings.NewReader(tt.body))
			repsBody, _ := ioutil.ReadAll(got.Body)
			ar := admv1.AdmissionReview{}
			if got.StatusCode == http.StatusOK {
				_ = json.Unmarshal(repsBody, &ar)
			}
			if ar.Response != nil {
				allowed = ar.Response.Allowed
			}

			if !(got.StatusCode == tt.code && allowed == tt.allowed) {
				t.Errorf("HandleValidate result code: %d allowed: %v, want code: %d allowed: %v", got.StatusCode, allowed, tt.code, tt.allowed)
			}
		})
	}
}
