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

package proxy

import (
	"net"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/vishvananda/netlink"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var _ = Describe("Test route.go", func() {
	var node1 *corev1.Node
	var route1, route2, route3, route4, route5 netlink.Route
	BeforeEach(func() {
		node1 = &corev1.Node{
			ObjectMeta: metav1.ObjectMeta{
				Name: "node1",
			},
			Spec: corev1.NodeSpec{
				PodCIDR:  "10.244.1.0/24",
				PodCIDRs: []string{"10.244.1.0/24"},
			},
			Status: corev1.NodeStatus{
				Addresses: []corev1.NodeAddress{{
					Type:    corev1.NodeInternalIP,
					Address: "192.168.1.1",
				}, {
					Type:    corev1.NodeHostName,
					Address: "node1",
				}},
			}}

		_, dst1, _ := net.ParseCIDR("10.244.1.0/24")
		_, dst2, _ := net.ParseCIDR("10.244.2.0/24")
		route1 = netlink.Route{
			Src: net.ParseIP("192.168.2.100"),
			Dst: dst2,
			Gw:  net.ParseIP("192.168.2.1"),
		}
		route2 = netlink.Route{
			Src: net.ParseIP("192.168.2.100"),
			Dst: dst1,
			Gw:  net.ParseIP("192.168.2.1"),
		}
		route3 = netlink.Route{
			Src: net.ParseIP("192.168.2.101"),
			Dst: dst1,
			Gw:  net.ParseIP("192.168.2.1"),
		}
		route4 = netlink.Route{
			Src: net.ParseIP("192.168.2.100"),
			Dst: dst2,
			Gw:  net.ParseIP("192.168.2.1"),
		}
		route5 = netlink.Route{
			Src: net.ParseIP("192.168.2.100"),
			Dst: dst1,
			Gw:  net.ParseIP("192.168.2.2"),
		}

	})

	It("Test GetNodeInternalIP", func() {
		ret := GetNodeInternalIP(*node1)
		Expect(ret).Should(Equal("192.168.1.1"))
	})

	It("Test RouteEqual", func() {
		Expect(RouteEqual(route1, route2)).Should(BeTrue())
		Expect(RouteEqual(route1, route3)).Should(BeFalse())
		Expect(RouteEqual(route1, route4)).Should(BeFalse())
		Expect(RouteEqual(route1, route5)).Should(BeFalse())
	})

})
