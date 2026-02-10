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
//nolint:lll
package types

import (
	"net"
	"time"
)

// IPAddress is net ip address, can be ipv4 or ipv6. Format like 192.168.10.12 or fe80::488e:b1ff:fe37:5414
type IPAddress string

func (ip IPAddress) String() string {
	return string(ip)
}

func (ip IPAddress) Valid() bool {
	return net.ParseIP(string(ip)) != nil
}

type EndpointIP struct {
	BridgeName string
	OfPort     uint32
	VlanID     uint16
	IP         net.IP
	Mac        net.HardwareAddr
	UpdateTime time.Time
}
