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

package monitor

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/agiledragon/gomonkey"
	ovsdb "github.com/contiv/libovsdb"
	"github.com/contiv/ofnet"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/api/errors"
	k8stypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/uuid"
	"k8s.io/klog"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	agentv1alpha1 "github.com/smartxworks/lynx/pkg/apis/agent/v1alpha1"
	"github.com/smartxworks/lynx/pkg/client/clientset_generated/clientset/scheme"
	"github.com/smartxworks/lynx/pkg/types"
)

const (
	timeout  = time.Second * 10
	interval = time.Millisecond * 250
)

type Iface struct {
	IfaceName string
	IfaceType string
	MacAddr   string
	OfPort    uint32
}

var (
	k8sClient                     client.Client
	ovsClient                     *ovsdb.OvsdbClient
	agentName                     string
	monitor                       *agentMonitor
	stopChan                      chan struct{}
	ofPortIPAddressMonitorChan    chan map[uint32][]net.IP
	localEndpointLock             sync.RWMutex
	localEndpointMap              map[uint32]net.HardwareAddr
	curActiveSlaveLock            sync.RWMutex
	curActiveSlaveInterfaceOfPort *uint32
	uplinkLock                    sync.RWMutex
	curUplinkPortInfoMap          map[string]ofnet.PortInfo
)

func TestMain(m *testing.M) {
	k8sClient = fake.NewFakeClientWithScheme(scheme.Scheme)

	// return new fake agentname instead of read/write from file
	gomonkey.ApplyFunc(readOrGenerateAgentName, func() (string, error) {
		return `unit.test.agent.name`, nil
	})

	var err error

	ovsClient, err = ovsdb.ConnectUnix(ovsdb.DEFAULT_SOCK)
	if err != nil {
		klog.Fatalf("fail to connect ovs client: %s", err)
	}

	localEndpointMap = make(map[uint32]net.HardwareAddr)
	curUplinkPortInfoMap = make(map[string]ofnet.PortInfo)

	monitor, stopChan, ofPortIPAddressMonitorChan = startAgentMonitor(k8sClient)
	agentName = monitor.Name()

	m.Run()
}

func TestAgentMonitor(t *testing.T) {
	RegisterTestingT(t)

	testAgentInfoSync(t)
	testIPAddressLearning(t)
	testOvsDBEventHandler(t)
	testAgentMonitorRestart(t)
}

func testAgentInfoSync(t *testing.T) {
	brName := string(uuid.NewUUID())
	portName := string(uuid.NewUUID())
	ifaceName := portName
	externalIDs := map[string]string{"lynx.agent.monitor.externalID.name": "lynx.agent.monitor.externalID.value"}

	t.Logf("create new bridge %s", brName)
	Expect(createBridge(ovsClient, brName)).Should(Succeed())
	t.Run("monitor should create new bridge", func(t *testing.T) {
		Eventually(func() error {
			_, err := getBridge(k8sClient, brName)
			return err
		}, timeout, interval).Should(Succeed())
	})

	t.Logf("create new port %s", portName)
	Expect(createPort(ovsClient, brName, portName)).Should(Succeed())
	t.Run("monitor should create new port", func(t *testing.T) {
		Eventually(func() error {
			_, err := getPort(k8sClient, brName, portName)
			return err
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

func testAgentMonitorRestart(t *testing.T) {
	var ofport int32 = 10
	var ipAddr = []types.IPAddress{"10.10.56.32"}

	t.Logf("stop agent %s monitor", agentName)
	close(stopChan)

	t.Logf("set ofport %d IPAddr %v to agentInfo", ofport, ipAddr)
	Expect(setOfportIPAddr(k8sClient, ofport, ipAddr)).Should(Succeed())

	t.Logf("rerun agent %s monitor", agentName)
	monitor, stopChan, ofPortIPAddressMonitorChan = startAgentMonitor(k8sClient)

	t.Run("monitor should rebuild mapping of ofport to ipAddr", func(t *testing.T) {
		Eventually(func() []types.IPAddress {
			monitor.cacheLock.RLock()
			defer monitor.cacheLock.RUnlock()
			return monitor.ofportsCache[ofport]
		}, timeout, interval).Should(Equal(ipAddr))
	})
}

func testIPAddressLearning(t *testing.T) {
	var ofPort1 uint32 = 1
	var ofPort2 uint32 = 2
	var ipAddr1 = []net.IP{net.ParseIP("10.10.10.1")}
	var ipAddr2 = []net.IP{net.ParseIP("10.10.10.2")}

	t.Logf("Add OfPort %d, IpAddress %v.", ofPort1, ipAddr1)
	Expect(addOfPortIPAddress(ofPort1, ipAddr1, ofPortIPAddressMonitorChan)).Should(Succeed())

	t.Run("Monitor should learning ofPort to IpAddress mapping.", func(t *testing.T) {
		Eventually(func() string {
			monitor.cacheLock.RLock()
			defer monitor.cacheLock.RUnlock()
			ipAddrs := monitor.ofportsCache[int32(ofPort1)]
			return ofPortInfoToString(ipAddrs)
		}, timeout, interval).Should(Equal(ipInfoToString(ipAddr1)))
	})

	t.Logf("Update ovsPort related OfPort from %d to %d.", ofPort1, ofPort2)
	Expect(updateOfPort(ofPort1, ofPort2, ofPortIPAddressMonitorChan)).Should(Succeed())

	t.Run("Monitor should update Learned OfPort to IpAddress mapping.", func(t *testing.T) {
		Eventually(func() string {
			monitor.cacheLock.RLock()
			defer monitor.cacheLock.RUnlock()
			ipAddrs := monitor.ofportsCache[int32(ofPort2)]
			return ofPortInfoToString(ipAddrs)
		}, timeout, interval).Should(Equal(ipInfoToString(ipAddr1)))
	})

	t.Logf("Update ovsPort related IpAddress from %v to %v.", ipAddr1, ipAddr2)
	Expect(updateIPAddress(ofPort2, ipAddr2, ofPortIPAddressMonitorChan)).Should(Succeed())

	t.Run("Monitor should update learned OfPort to IpAddress mapping.", func(t *testing.T) {
		Eventually(func() string {
			monitor.cacheLock.RLock()
			defer monitor.cacheLock.RUnlock()
			ipAddrs := monitor.ofportsCache[int32(ofPort2)]
			return ofPortInfoToString(ipAddrs)
		}, timeout, interval).Should(Equal(ipInfoToString(ipAddr2)))
	})
}

func testOvsDBEventHandler(t *testing.T) {
	bridgeName := string(uuid.NewUUID())

	t.Logf("create new bridge %s", bridgeName)
	Expect(createBridge(ovsClient, bridgeName)).Should(Succeed())

	testEndpointOperation(t, bridgeName)
	testStandAloneUplinkOperation(t, bridgeName)
	testBondUplinkOperation(t, bridgeName)

	Expect(deleteBridge(ovsClient, bridgeName)).Should(Succeed())
}

func testBondUplinkOperation(t *testing.T, bridgeName string) {
	var bondUplinkPortInfo ofnet.PortInfo
	eth2LinkInfo := ofnet.LinkInfo{
		Name:       eth2Iface.IfaceName,
		OfPort:     eth2Iface.OfPort,
		LinkStatus: 0,
		Port:       &bondUplinkPortInfo,
	}
	eth3LinkInfo := ofnet.LinkInfo{
		Name:       eth3Iface.IfaceName,
		OfPort:     eth3Iface.OfPort,
		LinkStatus: 0,
		Port:       &bondUplinkPortInfo,
	}
	bondUplinkPortInfo = ofnet.PortInfo{
		Name:       bondUplinkPortName,
		Type:       "bond",
		LinkStatus: 0,
		MbrLinks:   []*ofnet.LinkInfo{&eth3LinkInfo, &eth2LinkInfo},
	}

	testBondUplinkAdd(t, bridgeName, bondUplinkPortInfo)
	testBondUplinkUpdate(t)
	testBondUplinkDelete(t, bridgeName)
}

func testEndpointOperation(t *testing.T, bridgeName string) {
	ep1Port := "ep1"
	ep1MacAddrStr := "00:11:11:11:11:11"
	ep1InterfaceExternalIds := map[string]string{"attached-mac": ep1MacAddrStr}
	ep1Iface := Iface{
		IfaceName: "ep1Iface",
		IfaceType: "internal",
		MacAddr:   ep1MacAddrStr,
		OfPort:    uint32(11),
	}

	// Add local endpoint, set attached interface externalIDs
	Expect(createOvsPort(bridgeName, ep1Port, []Iface{ep1Iface}, 0)).Should(Succeed())
	Expect(updateInterface(ovsClient, ep1Iface.IfaceName, ep1InterfaceExternalIds)).Should(Succeed())
	t.Run("Add local endpoint ep1", func(t *testing.T) {
		Eventually(func() string {
			localEndpointLock.Lock()
			defer localEndpointLock.Unlock()

			if ep1MacAddr, ok := localEndpointMap[ep1Iface.OfPort]; ok {
				return ep1MacAddr.String()
			}

			return ""
		}, timeout, interval).Should(Equal(ep1MacAddrStr))
	})

	//  Delete local endpoint
	Expect(deletePort(ovsClient, bridgeName, ep1Port, ep1Iface.IfaceName)).Should(Succeed())

	t.Run("Delete local endpoint ep1", func(t *testing.T) {
		Eventually(func() bool {
			localEndpointLock.Lock()
			defer localEndpointLock.Unlock()

			if ep1MacAddr, ok := localEndpointMap[ep1Iface.OfPort]; ok {
				if ep1MacAddr.String() == ep1MacAddrStr {
					return false
				}
			}

			return true
		}, timeout, interval).Should(Equal(true))
	})
}

func testStandAloneUplinkOperation(t *testing.T, bridgeName string) {
	standAloneUplinkPortName := "eth1"
	uplinkPortExternalIds := map[string]string{"uplink-port": "true"}
	eth1Iface := Iface{
		IfaceName: "eth1Iface",
		IfaceType: "internal",
		OfPort:    uint32(1),
	}

	var standAloneUplinkPortInfo ofnet.PortInfo
	eth1LinkInfo := ofnet.LinkInfo{
		Name:       eth1Iface.IfaceName,
		OfPort:     eth1Iface.OfPort,
		LinkStatus: 0,
		Port:       &standAloneUplinkPortInfo,
	}
	standAloneUplinkPortInfo = ofnet.PortInfo{
		Name:       standAloneUplinkPortName,
		Type:       "individual",
		LinkStatus: 0,
		MbrLinks:   []*ofnet.LinkInfo{&eth1LinkInfo},
	}

	// Add standAlone uplink port
	Expect(createOvsPort(bridgeName, standAloneUplinkPortName, []Iface{eth1Iface}, 0)).Should(Succeed())
	Expect(updatePort(ovsClient, standAloneUplinkPortName, uplinkPortExternalIds)).Should(Succeed())
	t.Run("Add standAlone uplink port", func(t *testing.T) {
		Eventually(func() bool {
			uplinkLock.Lock()
			defer uplinkLock.Unlock()

			portInfo, ok := curUplinkPortInfoMap[standAloneUplinkPortName]
			if !ok {
				return false
			}

			if reflect.DeepEqual(portInfo, standAloneUplinkPortInfo) {
				return true
			}

			return false
		}, timeout, interval).Should(Equal(true))
	})

	// Delete standAlone uplink port
	Expect(deletePort(ovsClient, bridgeName, standAloneUplinkPortName, eth1Iface.IfaceName)).Should(Succeed())

	t.Run("Delete standAlone uplink port", func(t *testing.T) {
		Eventually(func() bool {
			uplinkLock.Lock()
			defer uplinkLock.Unlock()

			if _, ok := curUplinkPortInfoMap[standAloneUplinkPortName]; ok {
				return true
			}

			return false
		}, timeout, interval).Should(Equal(false))
	})
}

var (
	bondUplinkPortName    = "bond"
	uplinkPortExternalIds = map[string]string{"uplink-port": "true"}

	eth2Iface = Iface{
		IfaceName: "eth2Iface",
		IfaceType: "internal",
		OfPort:    uint32(2),
	}
	eth3Iface = Iface{
		IfaceName: "eth3Iface",
		IfaceType: "internal",
		OfPort:    uint32(3),
	}
)

func testBondUplinkAdd(t *testing.T, bridgeName string, bondUplinkPortInfo ofnet.PortInfo) {
	// Add bonded uplink port
	Expect(createOvsPort(bridgeName, bondUplinkPortName, []Iface{eth2Iface, eth3Iface}, 0)).Should(Succeed())
	Expect(updatePort(ovsClient, bondUplinkPortName, uplinkPortExternalIds)).Should(Succeed())
	t.Run("Add bond uplink port", func(t *testing.T) {
		Eventually(func() bool {
			uplinkLock.Lock()
			defer uplinkLock.Unlock()

			portInfo, ok := curUplinkPortInfoMap[bondUplinkPortName]
			if !ok {
				return false
			}

			if portInfoDeepEqual(portInfo, bondUplinkPortInfo) {
				return true
			}

			return false
		}, timeout, interval).Should(Equal(true))
	})
}

func testBondUplinkUpdate(t *testing.T) {
	var curNonActiveMacMap map[uint32]string

	// Change bonded uplink port bond mode.
	Expect(updateBondMode(ovsClient, bondUplinkPortName, "balance-slb")).Should(Succeed())

	// Wait for mocked bond uplink interfaces in initialized status
	t.Run("Get updated bonded port mbrLink interface mac", func(t *testing.T) {
		Eventually(func() bool {
			curNonActiveMacMap = getBondInfo(bondUplinkPortName)

			return len(curNonActiveMacMap) > 0
		}, timeout, interval).Should(Equal(true))
	})

	// Update bonded uplink port active-slave
	Expect(updateBondActiveSlave(ovsClient, bondUplinkPortName, curNonActiveMacMap[eth3Iface.OfPort])).Should(Succeed())
	t.Run("Update bond active slave", func(t *testing.T) {
		Eventually(func() bool {
			curActiveSlaveLock.Lock()
			defer curActiveSlaveLock.Unlock()

			if curActiveSlaveInterfaceOfPort == nil {
				return false
			}

			return *curActiveSlaveInterfaceOfPort == eth3Iface.OfPort
		}, timeout, interval).Should(Equal(true))
	})
}

func testBondUplinkDelete(t *testing.T, bridgeName string) {
	// Delete bonded uplink port
	Expect(deletePort(ovsClient, bridgeName, bondUplinkPortName, eth2Iface.IfaceName,
		eth3Iface.IfaceName)).Should(Succeed())
	t.Run("Delete bond uplink port", func(t *testing.T) {
		Eventually(func() bool {
			uplinkLock.Lock()
			defer uplinkLock.Unlock()

			if _, ok := curUplinkPortInfoMap[bondUplinkPortName]; ok {
				return true
			}

			return false
		}, timeout, interval).Should(Equal(false))
	})
}

func portInfoDeepEqual(portInfo1 ofnet.PortInfo, portInfo2 ofnet.PortInfo) bool {
	if portInfo1.Name != portInfo2.Name {
		return false
	}
	if portInfo1.Type != portInfo2.Type {
		return false
	}
	if portInfo1.LinkStatus != portInfo2.LinkStatus {
		return false
	}

	if len(portInfo1.MbrLinks) != len(portInfo2.MbrLinks) {
		return false
	}

	var isLinkEqual bool = false
	for _, mbrLink1 := range portInfo1.MbrLinks {
		for _, mbrLink2 := range portInfo2.MbrLinks {
			if linkInfoDeepEqual(*mbrLink1, *mbrLink2) {
				isLinkEqual = true
				break
			}
		}

		if !isLinkEqual {
			break
		}
	}

	return isLinkEqual
}

func linkInfoDeepEqual(link1 ofnet.LinkInfo, link2 ofnet.LinkInfo) bool {
	if link1.Name != link2.Name {
		return false
	}

	// We just compare port name that attach this link to determine whether two link equal, and avoid cycle-dependency
	// loop
	if link1.Port.Name != link2.Port.Name {
		return false
	}

	if link1.OfPort != link2.OfPort {
		return false
	}

	if link1.LinkStatus != link2.LinkStatus {
		return false
	}

	return true
}

func getBondInfo(portName string) map[uint32]string {
	var bondInterfaceUUIDs []ovsdb.UUID
	var curActiveSlaveMacAddrStr string
	nonActiveSlaveMacAddrMap := make(map[uint32]string)

	monitor.cacheLock.Lock()
	defer monitor.cacheLock.Unlock()

	for _, row := range monitor.ovsdbCache["Port"] {
		name := row.Fields["name"].(string)
		if name == portName {
			bondInterfaceUUIDs = listUUID(row.Fields["interfaces"])
			curActiveSlaveMacAddrStr, _ = row.Fields["bond_active_slave"].(string)
			break
		}
	}

	for _, interfaceUUID := range bondInterfaceUUIDs {
		ovsInterface, ok := monitor.ovsdbCache["Interface"][interfaceUUID.GoUuid]
		if !ok {
			klog.Infof("Failed to get bonded uplink port interface: %+v", interfaceUUID)
			continue
		}

		interfaceMac, _ := ovsInterface.Fields["mac_in_use"].(string)
		interfaceOfPort, _ := ovsInterface.Fields["ofport"].(float64)

		if interfaceMac == curActiveSlaveMacAddrStr {
			continue
		}

		nonActiveSlaveMacAddrMap[uint32(interfaceOfPort)] = interfaceMac
	}

	return nonActiveSlaveMacAddrMap
}

func getOvsDBInterfaceInfo(opStr string, interfaces []Iface) ([]ovsdb.UUID, []ovsdb.Operation) {
	var intfOperations []ovsdb.Operation
	intfUUID := []ovsdb.UUID{}

	for _, iface := range interfaces {
		intfUUIDStr := iface.IfaceName
		intfUUID = append(intfUUID, ovsdb.UUID{GoUuid: intfUUIDStr})

		intf := make(map[string]interface{})
		intf["name"] = iface.IfaceName
		intf["type"] = iface.IfaceType
		intf["ofport"] = float64(iface.OfPort)
		if iface.MacAddr != "" {
			intf["mac_in_use"] = iface.MacAddr
		}

		intfOp := ovsdb.Operation{
			Op:       opStr,
			Table:    "Interface",
			Row:      intf,
			UUIDName: iface.IfaceName,
		}

		intfOperations = append(intfOperations, intfOp)
	}

	return intfUUID, intfOperations
}

func createOvsPort(bridgeName, portName string, interfaces []Iface, vlanTag uint) error {
	var err error
	portUUIDStr := portName
	portUUID := []ovsdb.UUID{{GoUuid: portUUIDStr}}
	opStr := "insert"

	// Add interface to interfaces table
	intfUUID, intfOperations := getOvsDBInterfaceInfo(opStr, interfaces)

	// Insert a row in Port table
	port := make(map[string]interface{})
	port["name"] = portName
	if vlanTag != 0 {
		port["vlan_mode"] = "access"
		port["tag"] = vlanTag
	} else {
		port["vlan_mode"] = "trunk"
	}

	port["interfaces"], err = ovsdb.NewOvsSet(intfUUID)
	if err != nil {
		return err
	}

	// Add an entry in Port table
	portOp := ovsdb.Operation{
		Op:       opStr,
		Table:    "Port",
		Row:      port,
		UUIDName: portUUIDStr,
	}

	// mutate the Ports column of the row in the Bridge table
	mutateSet, _ := ovsdb.NewOvsSet(portUUID)
	mutation := ovsdb.NewMutation("ports", opStr, mutateSet)
	condition := ovsdb.NewCondition("name", "==", bridgeName)
	mutateOp := ovsdb.Operation{
		Op:        "mutate",
		Table:     "Bridge",
		Mutations: []interface{}{mutation},
		Where:     []interface{}{condition},
	}

	var operations []ovsdb.Operation
	operations = append(operations, intfOperations...)
	operations = append(operations, portOp, mutateOp)

	// Perform OVS transaction
	_, err = ovsdbTransact(ovsClient, operations...)

	return err
}

func updateInterface(client *ovsdb.OvsdbClient, ifaceName string, externalIDs map[string]string) error {
	if externalIDs == nil {
		externalIDs = make(map[string]string)
	}
	ovsExternalIDs, _ := ovsdb.NewOvsMap(externalIDs)

	portOperation := ovsdb.Operation{
		Op:    "update",
		Table: "Interface",
		Row: map[string]interface{}{
			"external_ids": ovsExternalIDs,
		},
		Where: []interface{}{[]interface{}{"name", "==", ifaceName}},
	}

	_, err := ovsdbTransact(client, portOperation)
	return err
}

func updateBondActiveSlave(client *ovsdb.OvsdbClient, portName, activeSlaveMacStr string) error {
	portOperation := ovsdb.Operation{
		Op:    "update",
		Table: "Port",
		Row: map[string]interface{}{
			"bond_active_slave": activeSlaveMacStr,
		},
		Where: []interface{}{[]interface{}{"name", "==", portName}},
	}

	_, err := ovsdbTransact(client, portOperation)
	return err
}

func updateBondMode(client *ovsdb.OvsdbClient, portName, bondMode string) error {
	portOperation := ovsdb.Operation{
		Op:    "update",
		Table: "Port",
		Row: map[string]interface{}{
			"bond_mode": bondMode,
		},
		Where: []interface{}{[]interface{}{"name", "==", portName}},
	}

	_, err := ovsdbTransact(client, portOperation)
	return err
}

func ofPortInfoToString(ips []types.IPAddress) string {
	var buffer bytes.Buffer
	for _, ip := range ips {
		buffer.WriteString(ip.String())
	}
	return buffer.String()
}

func ipInfoToString(ips []net.IP) string {
	var buffer bytes.Buffer
	for _, ip := range ips {
		buffer.WriteString(ip.String())
	}
	return buffer.String()
}

func addOfPortIPAddress(ofPort uint32, ipAddr []net.IP, ofPortIPAddressMonitorChan chan map[uint32][]net.IP) error {
	ofPortInfo := map[uint32][]net.IP{ofPort: ipAddr}
	ofPortIPAddressMonitorChan <- ofPortInfo
	return nil
}

func updateOfPort(oldOfPort uint32, newOfPort uint32, ofPortIPAddressMonitorChan chan map[uint32][]net.IP) error {
	monitor.cacheLock.RLock()
	defer monitor.cacheLock.RUnlock()

	if _, ok := monitor.ofportsCache[int32(oldOfPort)]; !ok {
		return fmt.Errorf("error when get ofportsCache, port: %d.", oldOfPort)
	}
	oldOfPortInfo := map[uint32][]net.IP{
		oldOfPort: {},
	}
	ofPortIPAddressMonitorChan <- oldOfPortInfo

	ipAddr := monitor.ofportsCache[int32(oldOfPort)]
	newOfPortInfo := map[uint32][]net.IP{
		newOfPort: {net.ParseIP(ipAddr[0].String())},
	}
	ofPortIPAddressMonitorChan <- newOfPortInfo

	return nil
}

func updateIPAddress(ofPort uint32, newIPAddr []net.IP, ofPortIPAddressMonitorChan chan map[uint32][]net.IP) error {
	monitor.cacheLock.RLock()
	defer monitor.cacheLock.RUnlock()

	if _, ok := monitor.ofportsCache[int32(ofPort)]; !ok {
		return fmt.Errorf("error when get ofportcache, port: %d.", ofPort)
	}
	ofPortInfo := map[uint32][]net.IP{
		ofPort: newIPAddr,
	}
	ofPortIPAddressMonitorChan <- ofPortInfo
	return nil
}

const emptyUUID = "00000000-0000-0000-0000-000000000000"

func createBridge(client *ovsdb.OvsdbClient, brName string) error {
	bridgeOperation := ovsdb.Operation{
		Op:       "insert",
		Table:    "Bridge",
		UUIDName: "dummy",
		Row: map[string]interface{}{
			"name": brName,
		},
	}

	mutateOperation := ovsdb.Operation{
		Op:        "mutate",
		Table:     "Open_vSwitch",
		Mutations: []interface{}{[]interface{}{"bridges", "insert", ovsdb.UUID{GoUuid: "dummy"}}},
		Where:     []interface{}{[]interface{}{"_uuid", "excludes", ovsdb.UUID{GoUuid: emptyUUID}}},
	}

	_, err := ovsdbTransact(client, bridgeOperation, mutateOperation)
	return err
}

func deleteBridge(client *ovsdb.OvsdbClient, brName string) error {
	brUUID, err := getMemberUUID(client, "Bridge", brName)
	if err != nil {
		return fmt.Errorf("can't found uuid of bridge %s: %s", brName, err)
	}

	bridgeOperation := ovsdb.Operation{
		Op:    "delete",
		Table: "Bridge",
		Where: []interface{}{[]interface{}{"name", "==", brName}},
	}

	mutateOperation := ovsdb.Operation{
		Op:        "mutate",
		Table:     "Open_vSwitch",
		Mutations: []interface{}{[]interface{}{"bridges", "delete", brUUID}},
		Where:     []interface{}{[]interface{}{"_uuid", "excludes", ovsdb.UUID{GoUuid: emptyUUID}}},
	}

	_, err = ovsdbTransact(client, bridgeOperation, mutateOperation)
	return err
}

// createPort also create an interface with the same name
func createPort(client *ovsdb.OvsdbClient, brName, portName string) error {
	ifaceOperation := ovsdb.Operation{
		Op:    "insert",
		Table: "Interface",
		Row: map[string]interface{}{
			"name": portName,
		},
		UUIDName: "ifacedummy",
	}

	portOperation := ovsdb.Operation{
		Op:       "insert",
		Table:    "Port",
		UUIDName: "dummy",
		Row: map[string]interface{}{
			"name":       portName,
			"interfaces": ovsdb.UUID{GoUuid: "ifacedummy"},
		},
	}

	mutateOperation := ovsdb.Operation{
		Op:        "mutate",
		Table:     "Bridge",
		Mutations: []interface{}{[]interface{}{"ports", "insert", ovsdb.UUID{GoUuid: "dummy"}}},
		Where:     []interface{}{[]interface{}{"name", "==", brName}},
	}

	_, err := ovsdbTransact(client, ifaceOperation, portOperation, mutateOperation)
	return err
}

func updatePort(client *ovsdb.OvsdbClient, portName string, externalIDs map[string]string) error {
	if externalIDs == nil {
		externalIDs = make(map[string]string)
	}
	ovsExternalIDs, _ := ovsdb.NewOvsMap(externalIDs)

	portOperation := ovsdb.Operation{
		Op:    "update",
		Table: "Port",
		Row: map[string]interface{}{
			"external_ids": ovsExternalIDs,
		},
		Where: []interface{}{[]interface{}{"name", "==", portName}},
	}

	_, err := ovsdbTransact(client, portOperation)
	return err
}

func deletePort(client *ovsdb.OvsdbClient, brName, portName string, ifaceNames ...string) error {
	portUUID, err := getMemberUUID(client, "Port", portName)
	if err != nil {
		return fmt.Errorf("can't found uuid of port %s: %s", portName, err)
	}

	if len(ifaceNames) == 0 {
		// delete port default iface if ifaceNames not specific
		ifaceNames = []string{portName}
	}
	operations := make([]ovsdb.Operation, 0, len(ifaceNames)+2)

	for _, ifaceName := range ifaceNames {
		ifaceOperation := ovsdb.Operation{
			Op:    "delete",
			Table: "Interface",
			Where: []interface{}{[]interface{}{"name", "==", ifaceName}},
		}
		operations = append(operations, ifaceOperation)
	}

	portOperation := ovsdb.Operation{
		Op:    "delete",
		Table: "Port",
		Where: []interface{}{[]interface{}{"name", "==", portName}},
	}
	operations = append(operations, portOperation)

	mutateOperation := ovsdb.Operation{
		Op:        "mutate",
		Table:     "Bridge",
		Mutations: []interface{}{[]interface{}{"ports", "delete", portUUID}},
		Where:     []interface{}{[]interface{}{"name", "==", brName}},
	}
	operations = append(operations, mutateOperation)

	_, err = ovsdbTransact(client, operations...)
	return err
}

func getMemberUUID(client *ovsdb.OvsdbClient, tableName, memberName string) (ovsdb.UUID, error) {
	selectOperation := ovsdb.Operation{
		Op:    "select",
		Table: tableName,
		Where: []interface{}{[]interface{}{"name", "==", memberName}},
	}

	result, err := ovsdbTransact(client, selectOperation)
	if err != nil {
		return ovsdb.UUID{}, err
	}

	if len(result[0].Rows) == 0 {
		return ovsdb.UUID{}, fmt.Errorf("no member name with %s found in table %s", memberName, tableName)
	}

	return ovsdb.UUID{
		GoUuid: result[0].Rows[0]["_uuid"].([]interface{})[1].(string),
	}, nil
}

func ovsdbTransact(client *ovsdb.OvsdbClient, operation ...ovsdb.Operation) ([]ovsdb.OperationResult, error) {
	results, err := client.Transact("Open_vSwitch", operation...)
	for item, result := range results {
		if result.Error != "" {
			return results, fmt.Errorf("operator %v: %s, details: %s", operation[item], result.Error, result.Details)
		}
	}

	return results, err
}

func getBridge(client client.Client, brName string) (*agentv1alpha1.OVSBridge, error) {
	agentInfo := &agentv1alpha1.AgentInfo{}
	err := client.Get(context.Background(), k8stypes.NamespacedName{Name: agentName}, agentInfo)
	if err != nil {
		return nil, err
	}

	for _, bridge := range agentInfo.OVSInfo.Bridges {
		if bridge.Name == brName {
			return &bridge, nil
		}
	}

	return nil, notFoundError(fmt.Errorf("bridge %s not found in agentInfo", brName))
}

func getPort(client client.Client, brName, portName string) (*agentv1alpha1.OVSPort, error) {
	bridge, err := getBridge(client, brName)
	if err != nil {
		return nil, err
	}

	for _, port := range bridge.Ports {
		if port.Name == portName {
			return &port, nil
		}
	}

	return nil, notFoundError(fmt.Errorf("port %s not found in agentInfo", portName))
}

func getIface(client client.Client, brName, portName, ifaceName string) (*agentv1alpha1.OVSInterface, error) {
	port, err := getPort(client, brName, portName)
	if err != nil {
		return nil, err
	}

	for _, iface := range port.Interfaces {
		if iface.Name == ifaceName {
			return &iface, nil
		}
	}

	return nil, notFoundError(fmt.Errorf("port %s not found in agentInfo", ifaceName))
}

type notFoundError error

func isNotFoundError(err error) bool {
	switch err.(type) {
	case notFoundError:
		return true
	default:
		return false
	}
}

func startAgentMonitor(k8sClient client.Client) (*agentMonitor, chan struct{}, chan map[uint32][]net.IP) {
	ofPortIPAddressMonitorChan = make(chan map[uint32][]net.IP, 1024)

	monitor, err := NewAgentMonitor(k8sClient, ofPortIPAddressMonitorChan)
	if err != nil {
		klog.Fatalf("fail to create agentMonitor: %s", err)
	}

	monitor.RegisterOvsdbEventHandler(OvsdbEventHandlerFuncs{
		LocalEndpointAddFunc: func(endpointInfo ofnet.EndpointInfo) {
			localEndpointLock.Lock()
			defer localEndpointLock.Unlock()

			localEndpointMap[endpointInfo.PortNo] = endpointInfo.MacAddr
		},
		LocalEndpointDeleteFunc: func(portNo uint32) {
			localEndpointLock.Lock()
			defer localEndpointLock.Unlock()

			delete(localEndpointMap, portNo)
		},
		UplinkAddFunc: func(portInfo *ofnet.PortInfo) {
			uplinkLock.Lock()
			defer uplinkLock.Unlock()

			curUplinkPortInfoMap[portInfo.Name] = *portInfo
		},
		UplinkDelFunc: func(portName string) {
			uplinkLock.Lock()
			defer uplinkLock.Unlock()

			delete(curUplinkPortInfoMap, portName)
		},
		UplinkActiveSlaveUpdateFunc: func(portName string, portUpdates ofnet.PortUpdates) {
			curActiveSlaveLock.Lock()
			defer curActiveSlaveLock.Unlock()

			ofPort := portUpdates.Updates[0].UpdateInfo.(uint32)
			curActiveSlaveInterfaceOfPort = &ofPort
		},
	})

	stopChan := make(chan struct{})
	go monitor.Run(stopChan)

	return monitor, stopChan, ofPortIPAddressMonitorChan
}

// create or update agntinfo with giving ofport and IPAddr
func setOfportIPAddr(k8sClient client.Client, ofport int32, ipAddr []types.IPAddress) error {
	var ctx = context.Background()
	var agentInfoOld = &agentv1alpha1.AgentInfo{}

	var agentInfo = &agentv1alpha1.AgentInfo{
		OVSInfo: agentv1alpha1.OVSInfo{
			Bridges: []agentv1alpha1.OVSBridge{
				{
					Ports: []agentv1alpha1.OVSPort{
						{
							Interfaces: []agentv1alpha1.OVSInterface{
								{
									Ofport: ofport,
									IPs:    ipAddr,
								},
							},
						},
					},
				},
			},
		},
	}
	agentInfo.Name = agentName

	err := k8sClient.Get(ctx, k8stypes.NamespacedName{Name: agentName}, agentInfoOld)
	if errors.IsNotFound(err) {
		if err = k8sClient.Create(ctx, agentInfo); err != nil {
			return fmt.Errorf("couldn't create agent %s agentinfo: %s", agentName, err)
		}
		return nil
	}

	if err != nil {
		return fmt.Errorf("couldn't fetch agent %s agentinfo: %s", agentName, err)
	}

	agentInfo.ObjectMeta = agentInfoOld.ObjectMeta
	err = k8sClient.Update(ctx, agentInfo)
	if err != nil {
		return fmt.Errorf("couldn't update agent %s agentinfo: %s", agentName, err)
	}

	return nil
}
