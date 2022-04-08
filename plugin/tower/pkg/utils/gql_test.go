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

func TestGqlTypeMarshal(t *testing.T) {
	tests := []struct {
		t          reflect.Type
		skipFields map[string]string
		bracketed  bool
		want       string
	}{
		{
			t:         reflect.TypeOf(schema.VM{}),
			bracketed: true,
			want:      "{id,name,description,vcpu,memory,status,vm_nics{id,vlan{id,name,vlan_id,type},enabled,mirror,model,interface_id}}",
		},
		{
			t:          reflect.TypeOf(schema.VM{}),
			skipFields: map[string]string{"vlan": "VMNic"},
			bracketed:  true,
			want:       "{id,name,description,vcpu,memory,status,vm_nics{id,enabled,mirror,model,interface_id}}",
		},
		{
			t:          reflect.TypeOf(schema.VM{}),
			skipFields: map[string]string{"vcpu": "VM"},
			bracketed:  true,
			want:       "{id,name,description,memory,status,vm_nics{id,vlan{id,name,vlan_id,type},enabled,mirror,model,interface_id}}",
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
			want:       "{id,everoute_cluster{id},apply_to{communicable,selector{id}},ingress{type,ports{port,protocol},ip_block,except_ip_block,selector{id}}}",
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
