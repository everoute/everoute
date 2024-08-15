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
	"k8s.io/klog"
)

//nolint: funlen
func TestOvsDbEventHandler(t *testing.T) {
	RegisterTestingT(t)

	bridgeName := rand.String(10)
	ep1PortName := rand.String(10)
	ep1Iface := Iface{
		IfaceName: ep1PortName,
		IfaceType: "internal",
		OfPort:    uint32(11),
		VlanID:    uint16(1),
	}
	ep1 := Ep{
		VlanID: uint16(1),
	}
	newep1 := Ep{
		Trunk: "0,1",
	}

	t.Logf("create new bridge %s", bridgeName)
	Expect(createBridge(ovsClient, bridgeName)).Should(Succeed())

	// Add local endpoint, set attached interface externalIDs
	Expect(createPort(ovsClient, bridgeName, ep1PortName, &ep1Iface)).Should(Succeed())
	ep1OfPort, _ := getOfpPortNo(ovsClient, ep1PortName)

	t.Run("Add local endpoint ep1", func(t *testing.T) {
		Eventually(func() bool {
			localEndpointLock.Lock()
			_, ok := localEndpointMap[ep1OfPort]
			localEndpointLock.Unlock()
			return ok
		}, timeout, interval).Should(BeTrue())
	})

	Expect(updatePortToTrunk(ovsClient, ep1PortName, []int{0, 1}, ep1Iface.VlanID)).Should(Succeed())
	t.Run("Update local endpoint ep1, access port to trunk port", func(t *testing.T) {
		Eventually(func() string {
			localEndpointLock.Lock()
			trunks := localEndpointMap[ep1OfPort].Trunk
			localEndpointLock.Unlock()
			return trunks
		}, timeout, interval).Should(Equal(newep1.Trunk))
	})

	Expect(updatePortTrunk(ovsClient, ep1PortName, []int{1, 2})).Should(Succeed())
	t.Run("Update local endpoint ep1 trunk list", func(t *testing.T) {
		Eventually(func() string {
			localEndpointLock.Lock()
			trunks := localEndpointMap[ep1OfPort].Trunk
			localEndpointLock.Unlock()
			return trunks
		}, timeout, interval).Should(Equal("0,1,2"))
	})

	Expect(updatePortToAccess(ovsClient, ep1PortName, []int{0, 1, 2}, ep1Iface.VlanID)).Should(Succeed())
	t.Run("Update local endpoint ep1, trunk port to access port", func(t *testing.T) {
		Eventually(func() uint16 {
			localEndpointLock.Lock()
			vlan := localEndpointMap[ep1OfPort].VlanID
			localEndpointLock.Unlock()
			return vlan
		}, timeout, interval).Should(Equal(ep1.VlanID))
	})

	Expect(updatePortVlanTag(ovsClient, ep1PortName, ep1Iface.VlanID, uint16(2))).Should(Succeed())
	t.Run("Update local endpoint ep1 trunk list", func(t *testing.T) {
		Eventually(func() uint16 {
			localEndpointLock.Lock()
			vlanID := localEndpointMap[ep1OfPort].VlanID
			localEndpointLock.Unlock()
			return vlanID
		}, timeout, interval).Should(Equal(uint16(2)))
	})

	// Delete local endpoint
	Expect(deletePort(ovsClient, bridgeName, ep1PortName, ep1Iface.IfaceName)).Should(Succeed())

	t.Run("Delete local endpoint ep1", func(t *testing.T) {
		Eventually(func() bool {
			localEndpointLock.Lock()
			_, ok := localEndpointMap[ep1Iface.OfPort]
			localEndpointLock.Unlock()
			return ok
		}, timeout, interval).Should(BeFalse())
	})

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
			vethport, err := getOfpPortNo(ovsClient, vethPortName)
			if err != nil {
				return ""
			}
			localEndpointLock.Lock()
			macStr := localEndpointMap[vethport].MacAddrStr
			localEndpointLock.Unlock()
			return macStr
		}, timeout, interval).Should(Equal(vethMacAddrStr))

		Eventually(func() string {
			vethport, err := getOfpPortNo(ovsClient, vethPortName)
			if err != nil {
				return ""
			}
			localEndpointLock.Lock()
			ip := localEndpointMap[vethport].IPAddr
			localEndpointLock.Unlock()
			if ip == nil {
				return ""
			}
			return ip.String()
		}, timeout, interval).Should(Equal(vethIPStr))
	})

	t.Run("monitor update veth interface test", func(t *testing.T) {
		Eventually(func() bool {
			iface, err := getIface(k8sClient, bridgeName, vethPortName, vethIfaceName)
			if isNotFoundError(err) {
				return false
			}
			localEndpointLock.Lock()
			defer localEndpointLock.Unlock()
			klog.Infof("endpoint map  %v", localEndpointMap)
			return localEndpointMap[uint32(iface.Ofport)].MacAddrStr == iface.Mac
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
			iface, err := getIface(k8sClient, bridgeName, internalPortName, internalPortName)
			if isNotFoundError(err) {
				return false
			}
			localEndpointLock.Lock()
			defer localEndpointLock.Unlock()
			return localEndpointMap[internalIface.OfPort].MacAddrStr == iface.Mac
		}, timeout, interval).Should(BeTrue())
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
