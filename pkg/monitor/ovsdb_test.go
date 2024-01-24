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

package monitor

import (
	"testing"

	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/util/rand"
)

// nolint: funlen
func TestOvsDbEventHandler(t *testing.T) {
	RegisterTestingT(t)

	bridgeName := rand.String(10)
	Expect(createBridge(ovsClient, bridgeName)).Should(Succeed())

	testEventHandlerWithLocalEndpoint(bridgeName, t)
	testEventHandlerWithVethPair(bridgeName, t)
	testEventHandlerWithInternalPort(bridgeName, t)
}

func testEventHandlerWithLocalEndpoint(bridgeName string, t *testing.T) {
	portName := rand.String(10)
	iface := Iface{
		IfaceName: portName,
		IfaceType: "internal",
		OfPort:    uint32(11),
		VlanID:    uint16(1),
	}

	// Add local endpoint, set attached interface externalIDs
	Expect(createPort(ovsClient, bridgeName, portName, &iface)).Should(Succeed())

	t.Run("should handle local endpoint add event", func(t *testing.T) {
		Eventually(func() bool {
			_, ok := localEndpointCache.Get(iface.IfaceName)
			return ok
		}, timeout, interval).Should(BeTrue())
	})

	Expect(updatePortToTrunk(ovsClient, portName, []int{0, 1}, iface.VlanID)).Should(Succeed())
	t.Run("should handle local endpoint update event", func(t *testing.T) {
		Eventually(func() string {
			ep, ok := localEndpointCache.Get(iface.IfaceName)
			if !ok {
				return ""
			}
			return ep.(*LocalEndpoint).Trunk
		}, timeout, interval).Should(Equal("0,1"))
	})

	Expect(updatePortTrunk(ovsClient, portName, []int{1, 2})).Should(Succeed())
	t.Run("should handle local endpoint update event", func(t *testing.T) {
		Eventually(func() string {
			ep, ok := localEndpointCache.Get(iface.IfaceName)
			if !ok {
				return ""
			}
			return ep.(*LocalEndpoint).Trunk
		}, timeout, interval).Should(Equal("0,1,2"))
	})

	Expect(updatePortToAccess(ovsClient, portName, []int{0, 1, 2}, iface.VlanID)).Should(Succeed())
	t.Run("should handle local endpoint update event", func(t *testing.T) {
		Eventually(func() uint16 {
			ep, ok := localEndpointCache.Get(iface.IfaceName)
			if !ok {
				return 0
			}
			return ep.(*LocalEndpoint).Tag
		}, timeout, interval).Should(Equal(uint16(1)))
	})

	Expect(updatePortVlanTag(ovsClient, portName, iface.VlanID, uint16(2))).Should(Succeed())
	t.Run("should handle local endpoint update event", func(t *testing.T) {
		Eventually(func() uint16 {
			ep, ok := localEndpointCache.Get(iface.IfaceName)
			if !ok {
				return 0
			}
			return ep.(*LocalEndpoint).Tag
		}, timeout, interval).Should(Equal(uint16(2)))
	})

	// Delete local endpoint
	Expect(deletePort(ovsClient, bridgeName, portName, iface.IfaceName)).Should(Succeed())

	t.Run("should handle local endpoint delete event", func(t *testing.T) {
		Eventually(func() bool {
			_, ok := localEndpointCache.Get(iface.IfaceName)
			return ok
		}, timeout, interval).Should(BeFalse())
	})
}

func testEventHandlerWithVethPair(bridgeName string, t *testing.T) {
	// Add vethpair type interface, convert to endpoint, update interface MacAddr
	vethPortName, vethPortPeerName := rand.String(10), rand.String(10)
	vethIfaceName := vethPortName
	vethMacAddrStr := "00:11:11:11:11:22"
	vethIPStr := "10.12.12.1"
	vethInterfaceExternalIds := map[string]string{"attached-mac": vethMacAddrStr, "attached-ipv4": vethIPStr}
	vethIface := Iface{
		IfaceName:  vethPortName,
		OfPort:     uint32(15),
		externalID: vethInterfaceExternalIds,
	}

	t.Logf("create vethpair port %s", vethPortName)
	Expect(createVethPair(vethPortName, vethPortPeerName)).Should(Succeed())
	Expect(createPort(ovsClient, bridgeName, vethPortName, &vethIface)).Should(Succeed())

	t.Run("monitor should create new veth port", func(t *testing.T) {
		Eventually(func() error {
			_, err := getPort(k8sClient, bridgeName, vethPortName)
			return err
		}, timeout, interval).Should(Succeed())

		Eventually(func() string {
			ep, ok := localEndpointCache.Get(vethIfaceName)
			if !ok {
				return ""
			}
			return ep.(*LocalEndpoint).Mac
		}, timeout, interval).Should(Equal(vethMacAddrStr))

		Eventually(func() string {
			ep, ok := localEndpointCache.Get(vethIfaceName)
			if !ok {
				return ""
			}
			return ep.(*LocalEndpoint).IP.String()
		}, timeout, interval).Should(Equal(vethIPStr))
	})

	t.Run("monitor update veth interface test", func(t *testing.T) {
		Eventually(func() bool {
			iface, err := getIface(k8sClient, bridgeName, vethPortName, vethIfaceName)
			if isNotFoundError(err) {
				return false
			}
			ep, ok := localEndpointCache.Get(vethIfaceName)
			if !ok {
				return false
			}
			return ep.(*LocalEndpoint).Mac == iface.Mac
		}, timeout, interval).Should(Equal(true))
	})

	t.Logf("delete port %s on bridge %s", vethPortName, bridgeName)
	Expect(deletePort(ovsClient, bridgeName, vethPortName)).Should(Succeed())

	t.Run("monitor delete veth port", func(t *testing.T) {
		Eventually(func() bool {
			_, err := getPort(k8sClient, bridgeName, vethPortName)
			return isNotFoundError(err)
		}, timeout, interval).Should(BeTrue())
	})
}

func testEventHandlerWithInternalPort(bridgeName string, t *testing.T) {
	internalPortName := rand.String(10)
	internalIfaceName := internalPortName

	t.Logf("create internal port %s", internalPortName)
	internalIface := Iface{
		IfaceName: internalIfaceName,
		IfaceType: "internal",
		OfPort:    uint32(22),
	}
	Expect(createPort(ovsClient, bridgeName, internalPortName, &internalIface)).Should(Succeed())

	t.Run("Add internal endpoint", func(t *testing.T) {
		Eventually(func() bool {
			iface, err := getIface(k8sClient, bridgeName, internalPortName, internalIfaceName)
			if isNotFoundError(err) {
				return false
			}
			ep, ok := localEndpointCache.Get(internalIfaceName)
			if !ok {
				return false
			}
			return ep.(*LocalEndpoint).Mac == iface.Mac
		}, timeout, interval).Should(Equal(true))
	})

	t.Logf("delete port %s on bridge %s", internalPortName, bridgeName)
	Expect(deletePort(ovsClient, bridgeName, internalPortName)).Should(Succeed())

	t.Run("Delete internal endpoint", func(t *testing.T) {
		Eventually(func() bool {
			_, err := getPort(k8sClient, bridgeName, internalPortName)
			return isNotFoundError(err)
		}, timeout, interval).Should(BeTrue())
	})
}
