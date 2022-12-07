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
	"context"
	"fmt"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	ovsdb "github.com/contiv/libovsdb"
	"github.com/vishvananda/netlink"
	k8stypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/klog"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake" // nolint: staticcheck

	"github.com/everoute/everoute/pkg/agent/datapath"
	agentv1alpha1 "github.com/everoute/everoute/pkg/apis/agent/v1alpha1"
	"github.com/everoute/everoute/pkg/client/clientset_generated/clientset/scheme"
)

const (
	timeout   = time.Second * 8
	interval  = time.Millisecond * 250
	emptyUUID = "00000000-0000-0000-0000-000000000000"
)

type Iface struct {
	IfaceName  string
	IfaceType  string
	OfPort     uint32
	VlanID     uint16
	Trunk      string
	externalID map[string]string
}

type Ep struct {
	MacAddrStr string
	OfPort     uint32
	VlanID     uint16
	Trunk      string
}

var (
	k8sClient                  client.Client
	ovsClient                  *ovsdb.OvsdbClient
	agentName                  string
	ovsdbMonitor               *OVSDBMonitor
	monitor                    *AgentMonitor
	localEndpointLock          sync.RWMutex
	localEndpointMap           = make(map[uint32]Ep)
	stopChan                   = make(chan struct{})
	ofPortIPAddressMonitorChan = make(chan map[string]net.IP, 1024)
)

func TestMain(m *testing.M) {
	// todo: we need to use the real k8s client
	k8sClient = fake.NewFakeClientWithScheme(scheme.Scheme)

	var err error

	ovsClient, err = ovsdb.ConnectUnix(ovsdb.DEFAULT_SOCK)
	if err != nil {
		klog.Fatalf("fail to connect ovs client: %s", err)
	}

	ovsdbMonitor, err = NewOVSDBMonitor()
	if err != nil {
		klog.Fatalf("fail to create ovsdb monitor: %s", err)
	}
	monitor = NewAgentMonitor(k8sClient, ovsdbMonitor, ofPortIPAddressMonitorChan)

	ovsdbMonitor.RegisterOvsdbEventHandler(OvsdbEventHandlerFuncs{
		LocalEndpointAddFunc: func(endpoint *datapath.Endpoint) {
			localEndpointLock.Lock()
			defer localEndpointLock.Unlock()

			localEndpointMap[endpoint.PortNo] = Ep{
				MacAddrStr: endpoint.MacAddrStr,
				VlanID:     endpoint.VlanID,
				Trunk:      endpoint.Trunk,
			}
		},
		LocalEndpointDeleteFunc: func(endpoint *datapath.Endpoint) {
			localEndpointLock.Lock()
			defer localEndpointLock.Unlock()

			delete(localEndpointMap, endpoint.PortNo)
		},
		LocalEndpointUpdateFunc: func(newEndpoint, oldEndpoint *datapath.Endpoint) {
			localEndpointLock.Lock()
			defer localEndpointLock.Unlock()

			delete(localEndpointMap, oldEndpoint.PortNo)
			localEndpointMap[newEndpoint.PortNo] = Ep{
				MacAddrStr: newEndpoint.MacAddrStr,
				VlanID:     newEndpoint.VlanID,
				Trunk:      newEndpoint.Trunk,
			}
		},
	})

	agentName = monitor.Name()
	go ovsdbMonitor.Run(stopChan)
	go monitor.Run(stopChan)

	exitCode := m.Run()
	os.Exit(exitCode)
}

func createVethPair(vethName, peerName string) error {
	veth := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{Name: vethName, TxQLen: 0},
		PeerName:  peerName}
	if err := netlink.LinkAdd(veth); err != nil {
		return err
	}
	return nil
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

	_, err := ovsdbTransact(client, "Open_vSwitch", portOperation)
	return err
}

func addOfPortIPAddress(brName string, ofPort uint32, ipAddr net.IP, ofPortIPAddressMonitorChan chan map[string]net.IP) error {
	ofPortInfo := map[string]net.IP{fmt.Sprintf("%s-%d", brName, ofPort): ipAddr}
	ofPortIPAddressMonitorChan <- ofPortInfo
	return nil
}

func updateIPAddress(brName string, ofPort uint32, newIPAddr net.IP, ofPortIPAddressMonitorChan chan map[string]net.IP) error {
	monitor.ipCacheLock.RLock()
	defer monitor.ipCacheLock.RUnlock()

	ofPortInfo := map[string]net.IP{
		fmt.Sprintf("%s-%d", brName, ofPort): newIPAddr,
	}
	ofPortIPAddressMonitorChan <- ofPortInfo
	return nil
}

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

	_, err := ovsdbTransact(client, "Open_vSwitch", bridgeOperation, mutateOperation)
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

	_, err = ovsdbTransact(client, "Open_vSwitch", bridgeOperation, mutateOperation)
	return err
}

// createPort also create an interface with the same name
func createPort(client *ovsdb.OvsdbClient, brName, portName string, iface *Iface) error {
	ifaceRow := make(map[string]interface{})
	if iface == nil {
		ifaceRow["name"] = portName
	} else {
		ifaceRow["name"] = iface.IfaceName
		ifaceRow["type"] = iface.IfaceType
		ifaceRow["ofport"] = iface.OfPort
		if iface.externalID != nil {
			ifaceRow["external_ids"], _ = ovsdb.NewOvsMap(iface.externalID)
		}
	}

	ifaceOperation := ovsdb.Operation{
		Op:       "insert",
		Table:    "Interface",
		Row:      ifaceRow,
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
	if iface != nil {
		portOperation.Row["tag"] = iface.VlanID
	}

	mutateOperation := ovsdb.Operation{
		Op:        "mutate",
		Table:     "Bridge",
		Mutations: []interface{}{[]interface{}{"ports", "insert", ovsdb.UUID{GoUuid: "dummy"}}},
		Where:     []interface{}{[]interface{}{"name", "==", brName}},
	}

	_, err := ovsdbTransact(client, "Open_vSwitch", ifaceOperation, portOperation, mutateOperation)
	return err
}

func updatePortToTrunk(client *ovsdb.OvsdbClient, portName string, trunk []int, tag uint16) error {
	var portOperations []ovsdb.Operation
	portOperations = append(portOperations, ovsdb.Operation{
		Op:        "mutate",
		Table:     "Port",
		Mutations: []interface{}{[]interface{}{"tag", "delete", tag}},
		Where:     []interface{}{[]interface{}{"name", "==", portName}},
	})

	mutateSet, _ := ovsdb.NewOvsSet(trunk)
	portOperations = append(portOperations, ovsdb.Operation{
		Op:        "mutate",
		Table:     "Port",
		Mutations: []interface{}{[]interface{}{"trunks", "insert", mutateSet}},
		Where:     []interface{}{[]interface{}{"name", "==", portName}},
	})

	_, err := ovsdbTransact(client, "Open_vSwitch", portOperations...)
	return err
}

func updatePortToAccess(client *ovsdb.OvsdbClient, portName string, trunk []int, tag uint16) error {
	var portOperations []ovsdb.Operation
	mutateSet, _ := ovsdb.NewOvsSet(trunk)
	portOperations = append(portOperations, ovsdb.Operation{
		Op:        "mutate",
		Table:     "Port",
		Mutations: []interface{}{[]interface{}{"trunks", "delete", mutateSet}},
		Where:     []interface{}{[]interface{}{"name", "==", portName}},
	})

	portOperations = append(portOperations, ovsdb.Operation{
		Op:        "mutate",
		Table:     "Port",
		Mutations: []interface{}{[]interface{}{"tag", "insert", tag}},
		Where:     []interface{}{[]interface{}{"name", "==", portName}},
	})

	_, err := ovsdbTransact(client, "Open_vSwitch", portOperations...)
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

	_, err := ovsdbTransact(client, "Open_vSwitch", portOperation)
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

	_, err = ovsdbTransact(client, "Open_vSwitch", operations...)
	return err
}

func getMemberUUID(client *ovsdb.OvsdbClient, tableName, memberName string) (ovsdb.UUID, error) {
	selectOperation := ovsdb.Operation{
		Op:    "select",
		Table: tableName,
		Where: []interface{}{[]interface{}{"name", "==", memberName}},
	}

	result, err := ovsdbTransact(client, "Open_vSwitch", selectOperation)
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

func ovsdbTransact(client *ovsdb.OvsdbClient, database string, operation ...ovsdb.Operation) ([]ovsdb.OperationResult, error) {
	results, err := client.Transact(database, operation...)
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
