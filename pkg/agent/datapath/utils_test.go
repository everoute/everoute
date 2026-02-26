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
	"reflect"
	"testing"
)

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
