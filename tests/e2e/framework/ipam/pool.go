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
	"sync"

	"k8s.io/apimachinery/pkg/util/rand"

	"github.com/everoute/everoute/tests/e2e/framework/config"
)

// Pool assign and manage ip addr
type Pool interface {
	Assign() (string, error)
	AssignFromSubnet(string) (string, error)
	Release(string) error
}

// NewPool create an Pool instance
func NewPool(config *config.IPAMConfig) (Pool, error) {
	_, ipNet, err := net.ParseCIDR(config.IPRange)
	if err != nil {
		return nil, err
	}

	// ignore the network and broadcast addresses
	network, broadcast := cidrV4Range(ipNet)

	begin := net.IPNet{IP: network, Mask: ipNet.Mask}
	end := net.IPNet{IP: broadcast, Mask: ipNet.Mask}

	return &pool{cidr: ipNet, ipUsed: map[string]bool{
		begin.String(): true,
		end.String():   true,
	}}, nil
}

type pool struct {
	lock sync.RWMutex
	// assignable address range
	cidr *net.IPNet
	// list of ips has been assigned
	ipUsed map[string]bool
}

func (f *pool) Assign() (string, error) {
	return f.AssignFromSubnet("")
}

func (f *pool) AssignFromSubnet(subnet string) (string, error) {
	var cidr = f.cidr

	if subnet != "" {
		var err error
		_, cidr, err = net.ParseCIDR(subnet)
		if err != nil {
			return "", fmt.Errorf("invalid subnet %s: %s", subnet, err)
		}
	}

	return f.randomIPv4(cidr)
}

func (f *pool) Release(ipnet string) error {
	f.lock.Lock()
	defer f.lock.Unlock()
	delete(f.ipUsed, ipnet)
	return nil
}

func (f *pool) randomIPv4(subnet *net.IPNet) (string, error) {
	f.lock.Lock()
	defer f.lock.Unlock()

	if !containsSubnet(f.cidr, subnet) {
		return "", fmt.Errorf("subnet %s not in ip pool %s", subnet, f.cidr)
	}

	// todo: replace retry with check has available IP first
	for i := 0; i < 10; i++ {
		ipv4 := randomIPv4FromSubnet(subnet)
		ipNet := (&net.IPNet{IP: ipv4, Mask: f.cidr.Mask}).String()

		if !f.ipUsed[ipNet] {
			f.ipUsed[ipNet] = true
			return ipNet, nil
		}
	}

	return "", fmt.Errorf("can't found valid ip addr")
}

func randomIPv4FromSubnet(subnet *net.IPNet) net.IP {
	maskSize, _ := subnet.Mask.Size()
	randIP := i32ToIP(ipToI32(subnet.IP) + int32(rand.Intn(1<<(32-maskSize))))
	return randIP
}

func cidrV4Range(subnet *net.IPNet) (net.IP, net.IP) {
	ones, bits := subnet.Mask.Size()
	return subnet.IP, i32ToIP(ipToI32(subnet.IP) + int32(1<<(bits-ones)-1))
}

func ipToI32(ip net.IP) int32 {
	ip = ip.To4()
	return int32(ip[0])<<24 | int32(ip[1])<<16 | int32(ip[2])<<8 | int32(ip[3])
}

func i32ToIP(a int32) net.IP {
	return net.IPv4(byte(a>>24), byte(a>>16), byte(a>>8), byte(a))
}

func containsSubnet(subnet1, subnet2 *net.IPNet) bool {
	maskSize1, _ := subnet1.Mask.Size()
	maskSize2, _ := subnet2.Mask.Size()

	if maskSize1 > maskSize2 {
		return false
	}

	return subnet1.Contains(subnet1.IP)
}
