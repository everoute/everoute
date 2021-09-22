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
	"net"

	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/everoute/everoute/pkg/types"
	"github.com/everoute/everoute/third_party/netutil"
)

// EqualIPs return true when two IP set have same IPaddresses.
func EqualIPs(ips1, ips2 []types.IPAddress) bool {
	toset := func(ips []types.IPAddress) sets.String {
		set := sets.NewString()
		for _, ip := range ips {
			set.Insert(ip.String())
		}
		return set
	}

	return len(ips1) == len(ips2) && toset(ips1).Equal(toset(ips2))
}

// ParseIPBlock parse ipBlock to list of IPNets.
func ParseIPBlock(ipBlock *networkingv1.IPBlock) ([]*net.IPNet, error) {
	var (
		cidrIPNet    *net.IPNet
		exceptIPNets []*net.IPNet
		err          error
	)

	_, cidrIPNet, err = net.ParseCIDR(ipBlock.CIDR)
	if err != nil {
		return nil, err
	}

	// parse all except into exceptIPNets
	for _, exceptCIDR := range ipBlock.Except {
		_, exceptIPNet, err := net.ParseCIDR(exceptCIDR)
		if err != nil {
			return nil, err
		}
		exceptIPNets = append(exceptIPNets, exceptIPNet)
	}

	return netutil.DiffFromCIDRs(cidrIPNet, exceptIPNets)
}
