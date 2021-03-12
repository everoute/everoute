/*
Copyright 2021 The Lynx Authors.

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
	"crypto/sha1"
	"encoding/json"
	"fmt"
	"reflect"
	"regexp"
	"strconv"
	"strings"

	"github.com/smartxworks/lynx/pkg/types"
)

const (
	matchIPV4    = `^((([1]?\d)?\d|2[0-4]\d|25[0-5])\.){3}(([1]?\d)?\d|2[0-4]\d|25[0-5])$`
	emptyPort    = `^$`
	singlePort   = `^(\d{1,5})$`
	multiplePort = `^(\d{1,5}-\d{1,5})$`
	allowRunes   = "abcdefghijklmnopqrstuvwxyz1234567890"
)

func GetIPCidr(ip types.IPAddress) string {
	var ipCidr string

	if regexp.MustCompile(matchIPV4).Match([]byte(ip)) {
		ipCidr = fmt.Sprintf("%s/%d", ip, 32)
	} else {
		ipCidr = fmt.Sprintf("%s/%d", ip, 128)
	}

	return ipCidr
}

// HashName return a Name with keys hash, length should <= 20.
func HashName(length int, keys ...interface{}) string {
	jsonKey, _ := json.Marshal(keys)
	var name string

	for _, char := range sha1.Sum(jsonKey) {
		name += string(allowRunes[int(char)%len(allowRunes)])
	}

	return name[:length]
}

func UnmarshalPortRange(portRange string) (uint16, uint16, error) {
	var begin, end uint16

	switch {
	case regexp.MustCompile(emptyPort).Match([]byte(portRange)):
		begin, end = 0, 0
	case regexp.MustCompile(singlePort).Match([]byte(portRange)):
		dstPort, _ := strconv.Atoi(portRange)
		begin, end = uint16(dstPort), uint16(dstPort)
	case regexp.MustCompile(multiplePort).Match([]byte(portRange)):
		port := strings.Split(portRange, "-")
		portBegin, _ := strconv.Atoi(port[0])
		portEnd, _ := strconv.Atoi(port[1])

		if portBegin > portEnd {
			return 0, 0, fmt.Errorf("portrange %s begin must <= end", portRange)
		}
		begin, end = uint16(portBegin), uint16(portEnd)
	default:
		return 0, 0, fmt.Errorf("couldn't unmarshal portrange %s", portRange)
	}

	return begin, end, nil
}

func DeepCopyMap(theMap interface{}) interface{} {
	maptype := reflect.TypeOf(theMap)

	srcMap := reflect.ValueOf(theMap)
	dstMap := reflect.MakeMapWithSize(maptype, srcMap.Len())

	for _, key := range srcMap.MapKeys() {
		dstMap.SetMapIndex(key, srcMap.MapIndex(key))
	}
	return dstMap.Interface()
}
