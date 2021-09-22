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

package ipam

import (
	"fmt"
	"net"
	"testing"
)

func Test_cidrV4Range(t *testing.T) {
	optionsCases := []struct {
		cidr  string
		begin string
		end   string
	}{
		{cidr: "10.0.0.0/24", begin: "10.0.0.0", end: "10.0.0.255"},
		{cidr: "10.0.0.9/24", begin: "10.0.0.0", end: "10.0.0.255"},
		{cidr: "10.0.0.9/32", begin: "10.0.0.9", end: "10.0.0.9"},
		{cidr: "10.0.0.9/0", begin: "0.0.0.0", end: "255.255.255.255"},
	}

	for _, tt := range optionsCases {
		t.Run(fmt.Sprintf("test cidrV4Range %s", tt), func(t *testing.T) {
			_, cidr, _ := net.ParseCIDR(tt.cidr)
			begin, end := cidrV4Range(cidr)
			if !begin.Equal(net.ParseIP(tt.begin)) || !end.Equal(net.ParseIP(tt.end)) {
				t.Fatalf("expect cidr %s range %s-%s, got %s-%s", tt.cidr, tt.begin, tt.end, begin, end)
			}
		})
	}
}
