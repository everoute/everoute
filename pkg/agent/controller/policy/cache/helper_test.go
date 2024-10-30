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

package cache

import (
	"context"
	"testing"

	"k8s.io/apimachinery/pkg/util/sets"

	groupv1alpha1 "github.com/everoute/everoute/pkg/apis/group/v1alpha1"
	securityv1alpha1 "github.com/everoute/everoute/pkg/apis/security/v1alpha1"
	"github.com/everoute/everoute/pkg/types"
)

func TestUnmarshalPortRange(t *testing.T) {
	testCases := map[string]struct {
		portRange string

		expectError bool
		expectBegin uint16
		expectEnd   uint16
	}{
		"should unmarshal empty portRange": {
			portRange:   "",
			expectError: false,
			expectBegin: 0,
			expectEnd:   0,
		},
		"should unmarshal single portRange": {
			portRange:   "80",
			expectError: false,
			expectBegin: 80,
			expectEnd:   80,
		},
		"should unmarshal multiple portRange": {
			portRange:   "80-8080",
			expectError: false,
			expectBegin: 80,
			expectEnd:   8080,
		},
		"should unmarshal multiple portRange with prefix '0'": {
			portRange:   "080-08080",
			expectError: false,
			expectBegin: 80,
			expectEnd:   8080,
		},
		"should not unmarshal portRange begin less than end": {
			portRange:   "8080-80",
			expectError: true,
		},
		"should not unmarshal portRange with wrong format": {
			portRange:   "10-80,90",
			expectError: true,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			begin, end, err := UnmarshalPortRange(tc.portRange)
			if tc.expectError && err == nil || !tc.expectError && err != nil {
				t.Fatalf("expect error: %t, but get error: %s", tc.expectError, err)
			}

			if begin != tc.expectBegin || end != tc.expectEnd {
				t.Fatalf("expect portrange from %d to %d, get portrange from %d to %d", tc.expectBegin, tc.expectEnd, begin, end)
			}
		})
	}
}

func TestGetIPCidr(t *testing.T) {
	testCases := map[string]struct {
		ipAddr     types.IPAddress
		expectCidr string
	}{
		"should add subnet mask 32 for ipv4": {
			ipAddr:     "192.168.1.1",
			expectCidr: "192.168.1.1/32",
		},
		"should add subnet mask 128 for ipv6": {
			ipAddr:     "fe80::10d4:3056:5621:a446",
			expectCidr: "fe80::10d4:3056:5621:a446/128",
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			if GetIPCidr(tc.ipAddr) != tc.expectCidr {
				t.Fatalf("expect %s get cidr %s, got cidr %s", tc.ipAddr, tc.expectCidr, GetIPCidr(tc.ipAddr))
			}
		})
	}
}

func TestAssembleStaticIPAndGroup(t *testing.T) {
	gCache := NewGroupCache()
	gCache.members["group-1"] = []groupv1alpha1.GroupMember{
		{
			EndpointReference: groupv1alpha1.EndpointReference{
				ExternalIDName:  "test",
				ExternalIDValue: "test",
			},
			IPs:           []types.IPAddress{"10.10.0.1", "10.10.0.2"},
			EndpointAgent: []string{"agent1"},
			Ports: []securityv1alpha1.NamedPort{
				{
					Name:     "ssh",
					Port:     22,
					Protocol: securityv1alpha1.ProtocolTCP,
				},
				{
					Name:     "ipip",
					Protocol: securityv1alpha1.ProtocolIPIP,
				},
			},
		},
		{
			EndpointAgent: []string{"agent1"},
			Ports: []securityv1alpha1.NamedPort{
				{
					Name:     "ftp",
					Port:     21,
					Protocol: securityv1alpha1.ProtocolTCP,
				},
			},
		},
		{
			IPs: []types.IPAddress{"10.10.0.3"},
		},
		{
			IPs:           []types.IPAddress{"10.10.0.4"},
			EndpointAgent: []string{"agent2"},
		},
		{
			IPs: []types.IPAddress{"10.10.0.5"},
			Ports: []securityv1alpha1.NamedPort{
				{
					Name:     "ftp",
					Port:     23,
					Protocol: securityv1alpha1.ProtocolTCP,
				},
			},
		},
	}
	gCache.members["group-empty"] = nil
	gCache.members["group-dup-ip"] = []groupv1alpha1.GroupMember{
		{
			IPs:           []types.IPAddress{"10.10.0.1"},
			EndpointAgent: []string{"agent3", "agent2"},
			Ports: []securityv1alpha1.NamedPort{
				{
					Name:     "http",
					Port:     80,
					Protocol: securityv1alpha1.ProtocolTCP,
				},
			},
		},
		{
			IPs:           []types.IPAddress{"10.10.0.3"},
			EndpointAgent: []string{"agent2"},
			Ports: []securityv1alpha1.NamedPort{
				{
					Name:     "http",
					Port:     80,
					Protocol: securityv1alpha1.ProtocolTCP,
				},
			},
		},
	}

	cases := []struct {
		name   string
		ips    sets.Set[string]
		groups sets.Set[string]
		exp    map[string]*IPBlockItem
		expErr bool
	}{
		{
			name:   "static ip is empty",
			ips:    sets.New[string](),
			groups: sets.New[string]("group-1"),
			expErr: false,
			exp: makeIPMap("10.10.0.1/32", &IPBlockItem{
				AgentRef: sets.NewString("agent1"),
				Ports: []securityv1alpha1.NamedPort{
					{
						Name:     "ssh",
						Port:     22,
						Protocol: securityv1alpha1.ProtocolTCP,
					},
					{
						Name:     "ipip",
						Protocol: securityv1alpha1.ProtocolIPIP,
					},
				},
			}, "10.10.0.2/32", &IPBlockItem{
				AgentRef: sets.NewString("agent1"),
				Ports: []securityv1alpha1.NamedPort{
					{
						Name:     "ssh",
						Port:     22,
						Protocol: securityv1alpha1.ProtocolTCP,
					},
					{
						Name:     "ipip",
						Protocol: securityv1alpha1.ProtocolIPIP,
					},
				},
			}, "10.10.0.3/32", &IPBlockItem{}, "10.10.0.4/32", &IPBlockItem{
				AgentRef: sets.NewString("agent2"),
			}, "10.10.0.5/32", &IPBlockItem{
				Ports: []securityv1alpha1.NamedPort{
					{
						Name:     "ftp",
						Port:     23,
						Protocol: securityv1alpha1.ProtocolTCP,
					},
				},
			}),
		},
		{
			name:   "group is empty",
			ips:    sets.New[string]("10.0.0.1/32", "12.12.0.1/25", ""),
			groups: sets.New[string]("group-empty"),
			expErr: false,
			exp:    makeIPMap("10.0.0.1/32", &IPBlockItem{}, "12.12.0.1/25", &IPBlockItem{}, "", &IPBlockItem{}),
		},
		{
			name:   "group and static ip is empty",
			ips:    sets.New[string](),
			groups: sets.New[string]("group-empty"),
			expErr: false,
			exp:    makeIPMap(),
		},
		{
			name:   "normal",
			ips:    sets.New[string]("10.10.0.4/32", "13.13.13.0/25"),
			groups: sets.New[string]("group-1", "group-empty", "group-dup-ip"),
			expErr: false,
			exp: makeIPMap("10.10.0.1/32", &IPBlockItem{
				AgentRef: sets.NewString("agent1", "agent2", "agent3"),
				Ports: []securityv1alpha1.NamedPort{
					{
						Name:     "ssh",
						Port:     22,
						Protocol: securityv1alpha1.ProtocolTCP,
					},
					{
						Name:     "ipip",
						Protocol: securityv1alpha1.ProtocolIPIP,
					},
					{
						Name:     "http",
						Port:     80,
						Protocol: securityv1alpha1.ProtocolTCP,
					},
				},
			}, "10.10.0.2/32", &IPBlockItem{
				AgentRef: sets.NewString("agent1"),
				Ports: []securityv1alpha1.NamedPort{
					{
						Name:     "ssh",
						Port:     22,
						Protocol: securityv1alpha1.ProtocolTCP,
					},
					{
						Name:     "ipip",
						Protocol: securityv1alpha1.ProtocolIPIP,
					},
				},
			}, "10.10.0.3/32", &IPBlockItem{
				Ports: []securityv1alpha1.NamedPort{
					{
						Name:     "http",
						Port:     80,
						Protocol: securityv1alpha1.ProtocolTCP,
					},
				},
			}, "10.10.0.4/32", &IPBlockItem{}, "10.10.0.5/32", &IPBlockItem{
				Ports: []securityv1alpha1.NamedPort{
					{
						Name:     "ftp",
						Port:     23,
						Protocol: securityv1alpha1.ProtocolTCP,
					},
				},
			}, "13.13.13.0/25", &IPBlockItem{}),
		},
		{
			name:   "group doesn't exist",
			ips:    sets.New[string]("10.10.0.1/32"),
			groups: sets.New[string]("group-1", "group-empty", "group-dup-ip", "group-unexist"),
			expErr: true,
			exp:    nil,
		},
	}

	for _, c := range cases {
		if c.name != "normal" {
			continue
		}
		res, err := AssembleStaticIPAndGroup(context.Background(), c.ips, c.groups, gCache)
		if (err == nil) == c.expErr {
			t.Errorf("test %s failed, expErr=%v, err is  %v", c.name, c.expErr, err)
		}
		if !equalIPMap(res, c.exp) {
			t.Errorf("test %s failed, exp is %v, real is %v", c.name, c.exp, res)
		}
	}
}

func makeIPMap(args ...interface{}) map[string]*IPBlockItem {
	res := make(map[string]*IPBlockItem)
	for i := 0; i < len(args)-1; i += 2 {
		ip := args[i].(string)
		item := args[i+1].(*IPBlockItem)
		res[ip] = item
	}

	return res
}

func equalIPMap(i1, i2 map[string]*IPBlockItem) bool {
	if len(i1) != len(i2) {
		return false
	}
	if len(i1) == 0 {
		return true
	}
	for k, v := range i1 {
		v2 := i2[k]
		if v == nil && v2 == nil {
			continue
		}
		if v == nil || v2 == nil {
			return false
		}
		if len(v.AgentRef) != len(v2.AgentRef) {
			return false
		}
		if len(v.AgentRef) != 0 {
			if !v.AgentRef.Equal(v2.AgentRef) {
				return false
			}
		}
		if len(v.Ports) != len(v2.Ports) {
			return false
		}
		if len(v.Ports) == 0 {
			continue
		}
		for i := range v.Ports {
			equal := false
			for j := range v2.Ports {
				if v.Ports[i] == v2.Ports[j] {
					equal = true
					break
				}
			}
			if !equal {
				return false
			}
		}
	}
	return true
}
