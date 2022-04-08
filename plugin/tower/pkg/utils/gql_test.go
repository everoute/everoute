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

package utils_test

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/everoute/everoute/plugin/tower/pkg/utils"
)

type VM struct {
	ID          string  `json:"id"`
	Name        string  `json:"name"`
	Description string  `json:"description,omitempty"`
	Vcpu        int     `json:"vcpu,omitempty"`
	Memory      float64 `json:"memory,omitempty"`
	VMNics      []VMNic `json:"vm_nics,omitempty"`
}

type VMNic struct {
	ID      string `json:"id"`
	Enabled bool   `json:"enabled,omitempty"`
	Mirror  bool   `json:"mirror,omitempty"`
}

func TestGqlTypeMarshal(t *testing.T) {
	tests := []struct {
		t          reflect.Type
		skipFields map[string]string
		bracketed  bool
		want       string
	}{
		{
			t:         reflect.TypeOf(VM{}),
			bracketed: true,
			want:      "{id,name,description,vcpu,memory,vm_nics{id,enabled,mirror}}",
		},
		{
			t:          reflect.TypeOf(VM{}),
			skipFields: map[string]string{"vcpu": "VM"},
			bracketed:  true,
			want:       "{id,name,description,memory,vm_nics{id,enabled,mirror}}",
		},
		{
			t:          reflect.TypeOf(VM{}),
			skipFields: map[string]string{"enabled": "VMNic"},
			bracketed:  true,
			want:       "{id,name,description,vcpu,memory,vm_nics{id,mirror}}",
		},
		{
			t:          reflect.TypeOf(VM{}),
			skipFields: map[string]string{"vcpu": "VM", "vm_nics": "VM"},
			bracketed:  true,
			want:       "{id,name,description,memory}",
		},
	}

	for item, tt := range tests {
		t.Run(fmt.Sprintf("cause%d", item), func(t *testing.T) {
			if got := utils.GqlTypeMarshal(tt.t, tt.skipFields, tt.bracketed); got != tt.want {
				t.Errorf("GqlTypeMarshal() = %s, want %s", got, tt.want)
			}
		})
	}
}
