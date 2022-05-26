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
	ep1PortName := rand.String(10)
	ep1MacAddrStr := "00:11:11:11:11:11"
	ep1InterfaceExternalIds := map[string]string{"attached-mac": ep1MacAddrStr}
	ep1Iface := Iface{
		IfaceName:  ep1PortName,
		IfaceType:  "internal",
		OfPort:     uint32(11),
		externalID: ep1InterfaceExternalIds,
	}

	t.Logf("create new bridge %s", bridgeName)
	Expect(createBridge(ovsClient, bridgeName)).Should(Succeed())

	// Add local endpoint, set attached interface externalIDs
	Expect(createPort(ovsClient, bridgeName, ep1PortName, &ep1Iface)).Should(Succeed())

	t.Run("Add local endpoint ep1", func(t *testing.T) {
		Eventually(func() string {
			localEndpointLock.Lock()
			endpointMac := localEndpointMap[ep1Iface.OfPort].String()
			localEndpointLock.Unlock()
			return endpointMac
		}, timeout, interval).Should(Equal(ep1MacAddrStr))
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

	t.Logf("create vethpair port %s", vethPortName)
	Expect(createVethPair(vethPortName, vethPortPeerName)).Should(Succeed())
	Expect(createPort(ovsClient, bridgeName, vethPortName, nil)).Should(Succeed())

	t.Run("monitor should create new veth port", func(t *testing.T) {
		Eventually(func() error {
			_, err := getPort(k8sClient, bridgeName, vethPortName)
			return err
		}, timeout, interval).Should(Succeed())
	})

	t.Run("monitor update veth interface test", func(t *testing.T) {
		Eventually(func() bool {
			iface, err := getIface(k8sClient, bridgeName, vethPortName, vethIfaceName)
			if isNotFoundError(err) {
				return false
			}
			localEndpointLock.Lock()
			defer localEndpointLock.Unlock()
			return localEndpointMap[uint32(iface.Ofport)].String() == iface.Mac
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
			return localEndpointMap[internalIface.OfPort].String() == iface.Mac
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
