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

package utils

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/everoute/everoute/plugin/tower/pkg/schema"
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
			t:         reflect.TypeOf(schema.VM{}),
			bracketed: true,
			want:      "{id,name,description,vcpu,memory,status,vm_nics{id,vlan{id,vds{id},name,vlan_id,type},enabled,mirror,model,mac_address,ip_address,interface_id}}",
		},
		{
			t:          reflect.TypeOf(schema.VM{}),
			skipFields: map[string]string{"vds": "Vlan"},
			bracketed:  true,
			want:       "{id,name,description,vcpu,memory,status,vm_nics{id,vlan{id,name,vlan_id,type},enabled,mirror,model,mac_address,ip_address,interface_id}}",
		},
		{
			t:          reflect.TypeOf(schema.VM{}),
			skipFields: map[string]string{"vcpu": "VM"},
			bracketed:  true,
			want:       "{id,name,description,memory,status,vm_nics{id,vlan{id,vds{id},name,vlan_id,type},enabled,mirror,model,mac_address,ip_address,interface_id}}",
		},
		{
			t:          reflect.TypeOf(schema.VM{}),
			skipFields: map[string]string{"vcpu": "VM", "vm_nics": "VM"},
			bracketed:  true,
			want:       "{id,name,description,memory,status}",
		},
		{
			t:          reflect.TypeOf(schema.SecurityPolicy{}),
			skipFields: map[string]string{"egress": "SecurityPolicy", "policy_mode": "SecurityPolicy"},
			bracketed:  true,
			want:       "{id,name,everoute_cluster{id},apply_to{communicable,selector{id}},ingress{type,ports{port,protocol},ip_block,selector{id}}}",
		},
	}

	for item, tt := range tests {
		t.Run(fmt.Sprintf("cause%d", item), func(t *testing.T) {
			if got := GqlTypeMarshal(tt.t, tt.skipFields, tt.bracketed); got != tt.want {
				t.Errorf("GqlTypeMarshal() = %s, want %s", got, tt.want)
			}
		})
	}
}
