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
	"testing"
	"time"

	"github.com/agiledragon/gomonkey/v2"
	ovsdb "github.com/contiv/libovsdb"
	"github.com/vishvananda/netlink"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"
	testclocks "k8s.io/utils/clock/testing"

	"github.com/everoute/everoute/pkg/agent/datapath"
	agentv1alpha1 "github.com/everoute/everoute/pkg/apis/agent/v1alpha1"
	"github.com/everoute/everoute/pkg/client/clientset_generated/clientset/fake"
	clientset "github.com/everoute/everoute/pkg/client/clientset_generated/clientset/typed/agent/v1alpha1"
	"github.com/everoute/everoute/pkg/types"
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
	Trunk      []int
	externalID map[string]string
}

type LocalEndpoint struct {
	Name  string
	IP    net.IP
	Mac   string
	Tag   uint16
	Trunk string
}

var (
	k8sClient           clientset.AgentInfoInterface
	ovsClient           *ovsdb.OvsdbClient
	agentName           string
	ovsdbMonitor        *OVSDBMonitor
	monitor             *AgentMonitor
	localEndpointCache  = cache.NewThreadSafeStore(cache.Indexers{}, cache.Indices{})
	stopChan            = make(chan struct{})
	endpointIPChan      = make(chan *types.EndpointIP, 1024)
	probeEndpointIPChan = make(chan *types.EndpointIP, 1024)
	fakeClock           = testclocks.NewFakeClock(time.Now())
)

func TestMain(m *testing.M) {
	clientset := fake.NewSimpleClientset()
	k8sClient = clientset.AgentV1alpha1().AgentInfos()

	var err error

	patch := gomonkey.ApplyFunc(wait.NonSlidingUntil, nonSlidingUntilWithFakeClock)
	defer patch.Reset()

	ovsClient, err = ovsdb.ConnectUnix(ovsdb.DEFAULT_SOCK)
	if err != nil {
		klog.Fatalf("fail to connect ovs client: %s", err)
	}

	ovsdbMonitor, err = NewOVSDBMonitor(false)
	if err != nil {
		klog.Fatalf("fail to create ovsdb monitor: %s", err)
	}

	monitor = NewAgentMonitor(&NewAgentMonitorOptions{
		ProbeTimeoutIPCallback: probeTimeoutIPCallback,
		Clientset:              clientset,
		OVSDBMonitor:           ovsdbMonitor,
		OFPortIPMonitorChan:    endpointIPChan,
	})

	ovsdbMonitor.RegisterOvsdbEventHandler(OvsdbEventHandlerFuncs{
		LocalEndpointAddFunc:    func(ep *datapath.Endpoint) { localEndpointCache.Add(ep.InterfaceName, toLocalEndpoint(ep)) },
		LocalEndpointDeleteFunc: func(ep *datapath.Endpoint) { localEndpointCache.Delete(ep.InterfaceName) },
		LocalEndpointUpdateFunc: func(ep, _ *datapath.Endpoint) { localEndpointCache.Update(ep.InterfaceName, toLocalEndpoint(ep)) },
	})

	agentName = monitor.Name()

	// fix: create event lost when reflector list and watch with fake client
	// the agent monitor loops infinitely to create agentinfo when agentinfo not in informer cache
	go monitor.agentInformer.Run(stopChan)
	cache.WaitForCacheSync(stopChan, monitor.agentInformer.HasSynced)

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
	ifaceRow["name"] = portName
	if iface.IfaceName != "" {
		ifaceRow["name"] = iface.IfaceName
	}
	if iface.IfaceType != "" {
		ifaceRow["type"] = iface.IfaceType
	}
	if iface.OfPort != 0 {
		ifaceRow["ofport"] = iface.OfPort
	}
	if iface.externalID != nil {
		ifaceRow["external_ids"], _ = ovsdb.NewOvsMap(iface.externalID)
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
	if len(iface.Trunk) == 0 {
		portOperation.Row["tag"] = iface.VlanID
	} else {
		trunkSet, _ := ovsdb.NewOvsSet(iface.Trunk)
		portOperation.Row["trunks"] = trunkSet
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

func updatePortTrunk(client *ovsdb.OvsdbClient, portName string, trunk []int) error {
	var portOperations []ovsdb.Operation

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

func updatePortVlanTag(client *ovsdb.OvsdbClient, portName string, oldTag, newTag uint16) error {
	var portOperations []ovsdb.Operation
	portOperations = append(portOperations, ovsdb.Operation{
		Op:        "mutate",
		Table:     "Port",
		Mutations: []interface{}{[]interface{}{"tag", "delete", oldTag}},
		Where:     []interface{}{[]interface{}{"name", "==", portName}},
	})

	portOperations = append(portOperations, ovsdb.Operation{
		Op:        "mutate",
		Table:     "Port",
		Mutations: []interface{}{[]interface{}{"tag", "insert", newTag}},
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

func getBridge(client clientset.AgentInfoInterface, brName string) (*agentv1alpha1.OVSBridge, error) {
	agentInfo, err := client.Get(context.Background(), agentName, metav1.GetOptions{})
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

func getPort(client clientset.AgentInfoInterface, brName, portName string) (*agentv1alpha1.OVSPort, error) {
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

func getIface(client clientset.AgentInfoInterface, brName, portName, ifaceName string) (*agentv1alpha1.OVSInterface, error) {
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

func nonSlidingUntilWithFakeClock(f func(), period time.Duration, stopCh <-chan struct{}) {
	wait.BackoffUntil(f, wait.NewJitteredBackoffManager(period, 0.0, fakeClock), false, stopCh)
}

func probeTimeoutIPCallback(ctx context.Context, endpointIP *types.EndpointIP) error {
	probeEndpointIPChan <- endpointIP
	return ctx.Err()
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

func toLocalEndpoint(ep *datapath.Endpoint) *LocalEndpoint {
	return &LocalEndpoint{
		Name:  ep.InterfaceName,
		IP:    ep.IPAddr,
		Mac:   ep.MacAddrStr,
		Tag:   ep.VlanID,
		Trunk: ep.Trunk,
	}
}
