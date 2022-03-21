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
	"testing"

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
