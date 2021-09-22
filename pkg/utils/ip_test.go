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

package utils

import (
	"fmt"
	"net"
	"testing"

	. "github.com/onsi/gomega"
	networkingv1 "k8s.io/api/networking/v1"
)

func TestParseIPBlock(t *testing.T) {
	RegisterTestingT(t)

	type args struct {
		ipBlock *networkingv1.IPBlock
	}
	tests := []struct {
		name    string
		args    args
		want    []*net.IPNet
		wantErr bool
	}{
		{
			name: "should exclude cidr in the except",
			args: args{ipBlock: &networkingv1.IPBlock{
				CIDR:   "192.168.0.0/24",
				Except: []string{"192.168.0.64/26"},
			}},
			want: []*net.IPNet{
				mustParseCIDR("192.168.0.0/26"),
				mustParseCIDR("192.168.0.128/25"),
			},
		},
		{
			name: "should parse ipBlock has no excepts",
			args: args{ipBlock: &networkingv1.IPBlock{
				CIDR: "192.168.0.0/24",
			}},
			want: []*net.IPNet{
				mustParseCIDR("192.168.0.0/24"),
			},
		},
		{
			name: "should ignore except that cidr not contains",
			args: args{ipBlock: &networkingv1.IPBlock{
				CIDR:   "192.168.0.0/24",
				Except: []string{"192.168.24.0/24"},
			}},
			want: []*net.IPNet{
				mustParseCIDR("192.168.0.0/24"),
			},
		},
		{
			name: "should error when input wrong cidr format",
			args: args{ipBlock: &networkingv1.IPBlock{
				CIDR: "192.168.0.1/33",
			}},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseIPBlock(tt.args.ipBlock)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseIPBlock() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			Expect(got).Should(ConsistOf(tt.want))
		})
	}
}

func mustParseCIDR(cidr string) *net.IPNet {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		panic(fmt.Sprintf("%s not valid cidr: %s", ipNet, err))
	}
	return ipNet
}
