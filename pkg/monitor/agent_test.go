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

package monitor

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/agiledragon/gomonkey/v2"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/util/rand"

	"github.com/everoute/everoute/pkg/constants"
	"github.com/everoute/everoute/pkg/types"
)

func TestAgentMonitor(t *testing.T) {
	RegisterTestingT(t)

	brName := rand.String(10)
	fakeportName := rand.String(10)
	portName := rand.String(10)
	portPeerName := rand.String(10)
	ifaceName := portName
	externalIDs := map[string]string{"everoute.agent.monitor.externalID.name": "everoute.agent.monitor.externalID.value"}

	t.Logf("create new bridge %s", brName)
	Expect(createBridge(ovsClient, brName)).Should(Succeed())

	t.Run("monitor should create new bridge", func(t *testing.T) {
		Eventually(func() error {
			_, err := getBridge(k8sClient, brName)
			return err
		}, timeout, interval).Should(Succeed())
	})

	t.Logf("create new port %s", portName)
	vethIface := Iface{}
	Expect(createVethPair(portName, portPeerName)).Should(Succeed())
	Expect(createPort(ovsClient, brName, portName, &vethIface)).Should(Succeed())

	t.Run("monitor should create new port", func(t *testing.T) {
		Eventually(func() error {
			_, err := getPort(k8sClient, brName, portName)
			return err
		}, timeout, interval).Should(Succeed())
	})

	t.Logf("create new fake port %s", fakeportName)
	Expect(createPort(ovsClient, brName, fakeportName, &vethIface)).Should(Succeed())

	t.Run("monitor should create new port", func(t *testing.T) {
		Eventually(func() error {
			_, err := getPort(k8sClient, brName, fakeportName)
			return err
		}, timeout, interval).Should(Succeed())
	})

	t.Run("interface with error should not appear in agentInfo", func(t *testing.T) {
		Eventually(func() error {
			monitor.ipCacheLock.RLock()
			defer monitor.ipCacheLock.RUnlock()
			agentInfo, _ := monitor.getAgentInfo()
			for _, br := range agentInfo.OVSInfo.Bridges {
				for _, port := range br.Ports {
					for _, iface := range port.Interfaces {
						if iface.Name == fakeportName {
							return fmt.Errorf("error")
						}
					}
				}
			}
			return nil
		}, timeout, interval).Should(Succeed())
	})

	t.Logf("update port %s externalIDs to %+v", portName, externalIDs)
	Expect(updatePort(ovsClient, portName, externalIDs)).Should(Succeed())

	t.Run("monitor should update port externalID", func(t *testing.T) {
		Eventually(func() map[string]string {
			port, _ := getPort(k8sClient, brName, portName)
			return port.ExternalIDs
		}, timeout, interval).Should(Equal(externalIDs))
	})

	t.Logf("update interface %s externalIDs to %+v", ifaceName, externalIDs)
	Expect(updateInterface(ovsClient, ifaceName, externalIDs)).Should(Succeed())

	t.Run("monitor should update interface externalID", func(t *testing.T) {
		Eventually(func() map[string]string {
			iface, _ := getIface(k8sClient, brName, portName, ifaceName)
			return iface.ExternalIDs
		}, timeout, interval).Should(Equal(externalIDs))
	})

	t.Logf("delete port %s on bridge %s", portName, brName)
	Expect(deletePort(ovsClient, brName, portName)).Should(Succeed())

	t.Run("monitor should delete port", func(t *testing.T) {
		Eventually(func() bool {
			_, err := getPort(k8sClient, brName, portName)
			return isNotFoundError(err)
		}, timeout, interval).Should(BeTrue())
	})

	t.Logf("delete bridge %s", brName)
	Expect(deleteBridge(ovsClient, brName)).Should(Succeed())

	t.Run("monitor should delete bridge", func(t *testing.T) {
		Eventually(func() bool {
			_, err := getBridge(k8sClient, brName)
			return isNotFoundError(err)
		}, timeout, interval).Should(BeTrue())
	})
}

func TestAgentMonitorIpAddressLearning(t *testing.T) {
	RegisterTestingT(t)
	brName := rand.String(10)

	t.Logf("create new bridge %s", brName)
	Expect(createBridge(ovsClient, brName)).Should(Succeed())

	externalIDs := make(map[string]string)
	externalIDs[constants.EndpointExternalIDKey] = rand.String(7)
	var portName = rand.String(10)
	var ofPort1 = uint32(rand.IntnRange(10, 100))
	var iface = Iface{IfaceName: rand.String(10), IfaceType: "internal", OfPort: ofPort1, externalID: externalIDs}
	var ipAddr1 = net.ParseIP("10.10.10.1")
	var ipAddr2 = net.ParseIP("10.10.10.2")

	t.Logf("create new port %s", portName)
	Expect(createPort(ovsClient, brName, portName, &iface)).Should(Succeed())
	Eventually(func() error {
		_, err := getIface(k8sClient, brName, portName, iface.IfaceName)
		return err
	}, timeout, interval).ShouldNot(HaveOccurred())

	t.Logf("Add OfPort %d, IpAddress %v.", ofPort1, ipAddr1)
	endpointIPChan <- &types.EndpointIP{BridgeName: brName, OfPort: ofPort1, IP: ipAddr1}

	t.Run("Monitor should learning ofPort to IpAddress mapping.", func(t *testing.T) {
		Eventually(func() bool {
			iface, err := getIface(k8sClient, brName, portName, iface.IfaceName)
			Expect(err).ShouldNot(HaveOccurred())
			hasIPAddr := iface.IPMap != nil && iface.IPMap[types.IPAddress(ipAddr1.String())] != nil
			return hasIPAddr && iface.Ofport == int32(ofPort1)
		}, timeout, interval).Should(BeTrue())
	})

	t.Logf("Add another ovsPort related IpAddress %v.", ipAddr2)
	endpointIPChan <- &types.EndpointIP{BridgeName: brName, OfPort: ofPort1, IP: ipAddr2}

	t.Run("Monitor should update learned OfPort to IpAddress mapping.", func(t *testing.T) {
		Eventually(func() bool {
			iface, err := getIface(k8sClient, brName, portName, iface.IfaceName)
			Expect(err).ShouldNot(HaveOccurred())
			hasIPAddr := iface.IPMap != nil && iface.IPMap[types.IPAddress(ipAddr2.String())] != nil
			return hasIPAddr && iface.Ofport == int32(ofPort1)
		}, timeout, interval).Should(BeTrue())
	})
}

func TestAgentMonitorProbeTimeoutIP(t *testing.T) {
	RegisterTestingT(t)

	patch := gomonkey.ApplyFuncReturn(getBridgeInternalMac, net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	defer patch.Reset()

	bridgeName := rand.String(10)
	Expect(createBridge(ovsClient, bridgeName)).Should(Succeed())

	t.Run("should probe timeout access iface ip", func(t *testing.T) {
		portName, peerName := rand.String(10), rand.String(10)
		ip := net.ParseIP("10.10.10.1")
		ofPort := uint32(rand.IntnRange(10, 100))

		Expect(createVethPair(portName, peerName)).Should(Succeed())
		Expect(createPort(ovsClient, bridgeName, portName, &Iface{VlanID: 201, OfPort: ofPort})).Should(Succeed())
		Eventually(func() error {
			_, err := getIface(k8sClient, bridgeName, portName, portName)
			return err
		}, timeout, interval).ShouldNot(HaveOccurred())

		endpointIPChan <- &types.EndpointIP{BridgeName: bridgeName, OfPort: ofPort, IP: ip, VlanID: 201, UpdateTime: time.Now().Add(-1 * time.Hour)}
		Eventually(func() bool {
			iface, err := getIface(k8sClient, bridgeName, portName, portName)
			Expect(err).ShouldNot(HaveOccurred())
			hasIPAddr := iface.IPMap != nil && iface.IPMap[types.IPAddress(ip.String())] != nil
			return hasIPAddr && iface.Ofport == int32(ofPort)
		}, timeout, interval).Should(BeTrue())

		fakeClock.Step(probeIPInterval * 2)
		Eventually(func() int32 {
			for {
				select {
				case endpointIP := <-probeEndpointIPChan:
					if endpointIP.BridgeName == bridgeName && endpointIP.OfPort == ofPort {
						return int32(endpointIP.VlanID)
					}
				default:
					return -1
				}
			}
		}, timeout, interval).Should(BeZero())
	})

	t.Run("should probe timeout trunk iface ip", func(t *testing.T) {
		portName, peerName := rand.String(10), rand.String(10)
		ip := net.ParseIP("10.10.10.1")
		ofPort := uint32(rand.IntnRange(10, 100))
		externalIDs := make(map[string]string)
		externalIDs[constants.EndpointExternalIDKey] = rand.String(7)

		Expect(createVethPair(portName, peerName)).Should(Succeed())
		Expect(createPort(ovsClient, bridgeName, portName, &Iface{Trunk: []int{100, 120}, OfPort: ofPort, externalID: externalIDs})).Should(Succeed())
		Eventually(func() error {
			_, err := getIface(k8sClient, bridgeName, portName, portName)
			return err
		}, timeout, interval).ShouldNot(HaveOccurred())

		endpointIPChan <- &types.EndpointIP{BridgeName: bridgeName, OfPort: ofPort, IP: ip, VlanID: 120, UpdateTime: time.Now().Add(-1 * time.Hour)}
		Eventually(func() bool {
			iface, err := getIface(k8sClient, bridgeName, portName, portName)
			Expect(err).ShouldNot(HaveOccurred())
			hasIPAddr := iface.IPMap != nil && iface.IPMap[types.IPAddress(ip.String())] != nil
			return hasIPAddr && iface.Ofport == int32(ofPort)
		}, timeout, interval).Should(BeTrue())

		fakeClock.Step(probeIPTimeout * 2)
		Eventually(func() int32 {
			for {
				select {
				case endpointIP := <-probeEndpointIPChan:
					if endpointIP.BridgeName == bridgeName && endpointIP.OfPort == ofPort {
						return int32(endpointIP.VlanID)
					}
				default:
					return -1
				}
			}
		}, timeout, interval).Should(Equal(int32(120)))
	})
}
