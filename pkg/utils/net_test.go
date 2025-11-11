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

func TestIPv6(t *testing.T) {
	RegisterTestingT(t)

	t.Run("IsSameIPFamily", func(t *testing.T) {
		Expect(IsSameIPFamily("", "")).Should(BeTrue())
		Expect(IsSameIPFamily("192.168.1.1", "")).Should(BeTrue())
		Expect(IsSameIPFamily("", "fe80::dc13:10ff:fe24:8c7f/64")).Should(BeTrue())
		Expect(IsSameIPFamily("fe80::42:87ff:fecd:9198/64", "fe80::dc13:10ff:fe24:8c7f")).Should(BeTrue())
		Expect(IsSameIPFamily("192.168.1.1", "0.0.0.0")).Should(BeTrue())
		Expect(IsSameIPFamily("::", "192.168.1.1")).Should(BeFalse())
	})

	t.Run("IsIPv4 or IsIPv6", func(t *testing.T) {
		Expect(IsIPv4("")).Should(BeTrue())
		Expect(IsIPv4("192.168.1.1")).Should(BeTrue())
		Expect(IsIPv4("192.168.1.1/16")).Should(BeTrue())
		Expect(IsIPv4("0.0.0.0/0")).Should(BeTrue())
		Expect(IsIPv4("fe80::42:87ff:fecd:9198/64")).Should(BeFalse())

		Expect(IsIPv6("")).Should(BeTrue())
		Expect(IsIPv6("fe80::42:87ff:fecd:9198/64")).Should(BeTrue())
		Expect(IsIPv6("::")).Should(BeTrue())
		Expect(IsIPv6("fe80::dc13:10ff:fe24:8c7f")).Should(BeTrue())
		Expect(IsIPv6("192.168.1.1")).Should(BeFalse())
	})

	t.Run("IsIPv4Pair or IsIPv6Pair", func(t *testing.T) {
		Expect(IsIPv4Pair("", "")).Should(BeTrue())
		Expect(IsIPv4Pair("192.168.1.1", "")).Should(BeTrue())
		Expect(IsIPv4Pair("192.168.1.1", "0.0.0.0/0")).Should(BeTrue())
		Expect(IsIPv4Pair("fe80::42:87ff:fecd:9198/64", "")).Should(BeFalse())

		Expect(IsIPv6Pair("", "")).Should(BeTrue())
		Expect(IsIPv6Pair("192.168.1.1", "")).Should(BeFalse())
		Expect(IsIPv6Pair("192.168.1.1", "0.0.0.0/0")).Should(BeFalse())
		Expect(IsIPv6Pair("fe80::42:87ff:fecd:9198/64", "")).Should(BeTrue())
		Expect(IsIPv6Pair("fe80::42:87ff:fecd:9198/64", "fe80::dc13:10ff:fe24:8c7f")).Should(BeTrue())
	})
}

func TestFormatZeroIP(t *testing.T) {
	RegisterTestingT(t)

	t.Run("FormatZeroIP", func(t *testing.T) {
		Expect(FormatZeroIP("")).Should(Equal(""))
		Expect(FormatZeroIP("0.0.0.0")).Should(Equal("0.0.0.0"))
		Expect(FormatZeroIP("0.0.0.0/0")).Should(Equal(""))
		Expect(FormatZeroIP("0.0.0.0/16")).Should(Equal("0.0.0.0/16"))
		Expect(FormatZeroIP("0::0")).Should(Equal("0::0"))
		Expect(FormatZeroIP("0::0/0")).Should(Equal(""))
		Expect(FormatZeroIP("0:0:0::0/0")).Should(Equal(""))
		Expect(FormatZeroIP("0::0/64")).Should(Equal("0::0/64"))
		Expect(FormatZeroIP("1.1.1.1")).Should(Equal("1.1.1.1"))
		Expect(FormatZeroIP("fe80::dc13:10ff:fe24:8c7f")).Should(Equal("fe80::dc13:10ff:fe24:8c7f"))
		Expect(FormatZeroIP("1.1.0.0/16")).Should(Equal("1.1.0.0/16"))
		Expect(FormatZeroIP("1.1.0.0/0")).Should(Equal(""))
		Expect(FormatZeroIP("fe00::a1:b1/64")).Should(Equal("fe00::a1:b1/64"))
		Expect(FormatZeroIP("fe00::a1:b1/0")).Should(Equal(""))
	})
}
