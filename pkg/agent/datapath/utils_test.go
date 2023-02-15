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

package datapath

import (
	"fmt"
	"net"
	"reflect"
	"testing"
)

func TestMatchIP(t *testing.T) {
	testCases := []struct {
		ipRaw       string
		ip          string
		shouldMatch bool
	}{
		{
			ipRaw:       "192.168.16.1/20",
			ip:          "192.168.20.1",
			shouldMatch: true,
		},
		{
			ipRaw:       "192.168.16.1/20",
			ip:          "192.168.31.255",
			shouldMatch: true,
		},
		{
			ipRaw:       "192.168.16.1/20",
			ip:          "192.168.32.1",
			shouldMatch: false,
		},
		{
			ipRaw:       "192.168.16.1",
			ip:          "192.168.20.1",
			shouldMatch: false,
		},
		{
			ipRaw:       "192.168.16.1",
			ip:          "192.168.16.1",
			shouldMatch: true,
		},
	}

	for index, tc := range testCases {
		t.Run(fmt.Sprintf("tc%2d", index), func(t *testing.T) {
			if tc.shouldMatch != matchIP(tc.ipRaw, net.ParseIP(tc.ip)) {
				t.Fatalf("expect matchIP = %t, got matchIP = %t", tc.shouldMatch, !tc.shouldMatch)
			}
		})
	}
}

func TestMatchPort(t *testing.T) {
	testCases := []struct {
		portMask    uint16
		port1       uint16
		port2       uint16
		shouldMatch bool
	}{
		{
			port1:       20,
			port2:       20,
			shouldMatch: true,
		},
		{
			port1:       20,
			port2:       22,
			shouldMatch: false,
		},
		{
			portMask:    65520,
			port1:       20,
			port2:       22,
			shouldMatch: true,
		},
		{
			portMask:    65520,
			port1:       20,
			port2:       32,
			shouldMatch: false,
		},
	}

	for index, tc := range testCases {
		t.Run(fmt.Sprintf("tc%2d", index), func(t *testing.T) {
			if tc.shouldMatch != matchPort(tc.portMask, tc.port1, tc.port2) {
				t.Fatalf("expect matchPort = %t, got matchPort = %t", tc.shouldMatch, !tc.shouldMatch)
			}
		})
	}
}

func TestUintToByteBigEndian(t *testing.T) {
	tests := []struct {
		name string
		src  interface{}
		res  []byte
	}{
		{
			name: "uint16 to []byte",
			src:  uint16(0x11),
			res:  []byte{0, 17},
		}, {
			name: "uint32 to []byte",
			src:  uint32(0x27080c09),
			res:  []byte{39, 8, 12, 9},
		}, {
			name: "uint64 to []byte",
			src:  uint64(0xff16),
			res:  []byte{0, 0, 0, 0, 0, 0, 255, 22},
		}, {
			name: "invalid type",
			src:  uint8(2),
			res:  nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			real := uintToByteBigEndian(test.src)
			if !reflect.DeepEqual(real, test.res) {
				t.Errorf("the expect value is %v, the real value is %v", test.res, real)
			}
		})

	}
}

func TestGetVlanTrunkMask(t *testing.T) {
	idMaskMap := map[uint16]uint16{
		// 0x0: 0xfff,
		// 0x03e8: 0xfff8,
		// 0x03f0: 0xfff0,
		// 0x0400: 0xfe00,
		// 0x0600: 0xff00,
		// 0x0700: 0xff80,
		// 0x0780: 0xffc0,
		// 0x07c0: 0xfff0,
		0:    4095,
		1000: 65528,
		1008: 65520,
		1024: 65024,
		1536: 65280,
		1792: 65408,
		1920: 65472,
		1984: 65520,
	}
	var trunks []uint16 = make([]uint16, 1001)
	for i := 0; i <= 1000; i++ {
		if i == 0 {
			trunks[i] = uint16(0)
			continue
		}
		trunks[i] = uint16(999 + i)
	}

	t.Run("trunks to trunk mask list", func(t *testing.T) {
		actualIDMaskMap := getVlanTrunkMask(trunks)
		if !reflect.DeepEqual(idMaskMap, actualIDMaskMap) {
			t.Errorf("the expect value is %v, actual value is %v", idMaskMap, actualIDMaskMap)
		}
	})

}
