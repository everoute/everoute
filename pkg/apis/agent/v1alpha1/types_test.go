/*
Copyright 2024 The Everoute Authors.

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

package v1alpha1_test

import (
	"encoding/json"
	"testing"

	"github.com/everoute/everoute/pkg/apis/agent/v1alpha1"
)

func TestUnmarshalIPInfo(t *testing.T) {
	err := json.Unmarshal([]byte("\"2024-01-22T07:20:17Z\""), &v1alpha1.IPInfo{})
	if err != nil {
		t.Fatalf("must unmarshal datetime to IPInfo: %s", err)
	}

	err = json.Unmarshal([]byte("{}"), &v1alpha1.IPInfo{})
	if err != nil {
		t.Fatalf("must unmarshal IPInfo raw to IPInfo: %s", err)
	}
}
