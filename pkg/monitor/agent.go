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
	"context"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"time"

	ovsdb "github.com/contiv/libovsdb"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8stypes "k8s.io/apimachinery/pkg/types"
	typeuuid "k8s.io/apimachinery/pkg/util/uuid"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/everoute/everoute/pkg/agent/datapath"
	agentv1alpha1 "github.com/everoute/everoute/pkg/apis/agent/v1alpha1"
	"github.com/everoute/everoute/pkg/types"
)

const (
	AgentNameConfigPath   = "/var/lib/everoute/agent/name"
	LocalEndpointIdentity = "attached-mac"
)

type ovsdbEventHandler interface {
	AddLocalEndpoint(endpoint datapath.Endpoint)
	DeleteLocalEndpoint(endpoint datapath.Endpoint)
	UpdateLocalEndpoint(newEndpoint datapath.Endpoint, oldEndpoint datapath.Endpoint)
}

type OvsdbEventHandlerFuncs struct {
	LocalEndpointAddFunc    func(endpoint datapath.Endpoint)
	LocalEndpointDeleteFunc func(endpoint datapath.Endpoint)
	LocalEndpointUpdateFunc func(newEndpoint datapath.Endpoint, oldEndpoint datapath.Endpoint)
}

func (handler OvsdbEventHandlerFuncs) AddLocalEndpoint(endpoint datapath.Endpoint) {
	if handler.LocalEndpointAddFunc != nil {
		handler.LocalEndpointAddFunc(endpoint)
	}
}

func (handler OvsdbEventHandlerFuncs) DeleteLocalEndpoint(endpoint datapath.Endpoint) {
	if handler.LocalEndpointDeleteFunc != nil {
		handler.LocalEndpointDeleteFunc(endpoint)
	}
}

func (handler OvsdbEventHandlerFuncs) UpdateLocalEndpoint(newEndpoint datapath.Endpoint, oldEndpoint datapath.Endpoint) {
	if handler.LocalEndpointUpdateFunc != nil {
		handler.LocalEndpointUpdateFunc(newEndpoint, oldEndpoint)
	}
}

func (monitor *AgentMonitor) RegisterOvsdbEventHandler(ovsdbEventHandler ovsdbEventHandler) {
	if ovsdbEventHandler == nil {
		klog.Fatalf("Failed to register ovsdbEventHandler: register nil ovsdbEventHandler not allow")
	}
	if monitor.ovsdbEventHandler != nil {
		klog.Fatalf("Failed to register ovsdbEventHandler: monitor ovsdbEventHandler already register")
	}

	monitor.ovsdbEventHandler = ovsdbEventHandler
}

// agentMonitor monitor agent state, update agentinfo to apiserver.
type AgentMonitor struct {
	// k8sClient used to create/read/update agentinfo
	k8sClient client.Client
	// ovsClient used to monitor ovsdb table port/bridge/interface
	ovsClient *ovsdb.OvsdbClient

	// agentName is the name and uuid of this agent
	agentName string

	// cacheLock is a read/write lock for accessing the cache
	cacheLock                  sync.RWMutex
	ovsdbCache                 map[string]map[string]ovsdb.Row
	ipCacheLock                sync.RWMutex
	ipCache                    map[string]map[types.IPAddress]metav1.Time
	ofPortIPAddressMonitorChan chan map[string]net.IP

	ovsdbEventHandler                  ovsdbEventHandler
	localEndpointHardwareAddrCacheLock sync.RWMutex
	localEndpointHardwareAddrCache     map[string]uint32

	// syncQueue used to notify agentMonitor synchronize AgentInfo
	syncQueue workqueue.RateLimitingInterface
}

// NewAgentMonitor return a new agentMonitor with kubernetes client and ipMonitor.
func NewAgentMonitor(client client.Client, ofPortIPAddressMonitorChan chan map[string]net.IP) (*AgentMonitor, error) {
	monitor := &AgentMonitor{
		k8sClient:                          client,
		cacheLock:                          sync.RWMutex{},
		ipCacheLock:                        sync.RWMutex{},
		ovsdbCache:                         make(map[string]map[string]ovsdb.Row),
		ipCache:                            make(map[string]map[types.IPAddress]metav1.Time),
		ofPortIPAddressMonitorChan:         ofPortIPAddressMonitorChan,
		localEndpointHardwareAddrCache:     make(map[string]uint32),
		localEndpointHardwareAddrCacheLock: sync.RWMutex{},
		syncQueue:                          workqueue.NewRateLimitingQueue(workqueue.DefaultItemBasedRateLimiter()),
	}

	var err error

	monitor.agentName, err = readOrGenerateAgentName()
	if err != nil {
		klog.Errorf("unable get agent name: %s", err)
		return nil, err
	}

	monitor.ovsClient, err = ovsdb.ConnectUnix(ovsdb.DEFAULT_SOCK)
	if err != nil {
		klog.Errorf("failed to connection to ovsdb: %s", err.Error())
		return nil, err
	}

	return monitor, nil
}

func (monitor *AgentMonitor) Run(stopChan <-chan struct{}) {
	defer monitor.syncQueue.ShutDown()
	defer monitor.ovsClient.Disconnect()

	klog.Infof("start agent %s monitor", monitor.Name())
	defer klog.Infof("shutting down agent %s monitor", monitor.Name())

	var err error
	err = monitor.startOvsdbMonitor()
	if err != nil {
		klog.Fatalf("unable start ovsdb monitor: %s", err)
	}
	go monitor.HandleOfPortIPAddressUpdate(monitor.ofPortIPAddressMonitorChan, stopChan)

	go wait.Until(monitor.syncAgentInfoWorker, 0, stopChan)
	<-stopChan
}

func (monitor *AgentMonitor) HandleOfPortIPAddressUpdate(ofPortIPAddressMonitorChan <-chan map[string]net.IP, stopChan <-chan struct{}) {
	for {
		select {
		case localEndpointInfo := <-ofPortIPAddressMonitorChan:
			monitor.updateOfPortIPAddress(localEndpointInfo)
		case <-stopChan:
			return
		}
	}
}

func (monitor *AgentMonitor) updateOfPortIPAddress(localEndpointInfo map[string]net.IP) {
	monitor.ipCacheLock.Lock()
	defer monitor.ipCacheLock.Unlock()

	for bridgePort, ip := range localEndpointInfo {
		if _, ok := monitor.ipCache[bridgePort]; !ok {
			monitor.ipCache[bridgePort] = make(map[types.IPAddress]metav1.Time)
		}
		monitor.ipCache[bridgePort] = map[types.IPAddress]metav1.Time{
			types.IPAddress(ip.String()): metav1.NewTime(time.Now()),
		}
	}

	monitor.syncQueue.Add(monitor.Name())
}

func (monitor *AgentMonitor) startOvsdbMonitor() error {
	klog.Infof("start monitor ovsdb %s", "Open_vSwitch")
	monitor.ovsClient.Register(ovsUpdateHandlerFunc(monitor.handleOvsUpdates))

	selectAll := ovsdb.MonitorSelect{
		Initial: true,
		Insert:  true,
		Delete:  true,
		Modify:  true,
	}
	requests := map[string]ovsdb.MonitorRequest{
		"Port":         {Select: selectAll, Columns: []string{"name", "interfaces", "external_ids", "bond_mode", "vlan_mode", "tag", "trunks"}},
		"Interface":    {Select: selectAll, Columns: []string{"name", "mac_in_use", "ofport", "type", "external_ids", "error"}},
		"Bridge":       {Select: selectAll, Columns: []string{"name", "ports"}},
		"Open_vSwitch": {Select: selectAll, Columns: []string{"ovs_version"}},
	}

	initial, err := monitor.ovsClient.Monitor("Open_vSwitch", nil, requests)
	if err != nil {
		return fmt.Errorf("monitor ovsdb %s: %s", "Open_vSwitch", err)
	}
	monitor.handleOvsUpdates(*initial)

	return nil
}

// Endpoint implement in everoute datapath module pr
func (monitor *AgentMonitor) interfaceToEndpoint(ofport uint32, interfaceName, macAddrStr string) *datapath.Endpoint {
	// NOTE should use interface uuid to caculate endpoint info
	var bridgeName string
	var portUUID string
	var vlanID uint16

	monitor.cacheLock.RLock()
	defer monitor.cacheLock.RUnlock()
	for uuid, port := range monitor.ovsdbCache["Port"] {
		if port.Fields["name"].(string) == interfaceName {
			portUUID = uuid
			tag, ok := port.Fields["tag"].(float64)
			if !ok {
				break
			}
			vlanID = uint16(tag)
			break
		}
	}

	for _, bridge := range monitor.ovsdbCache["Bridge"] {
		portUUIDs := listUUID(bridge.Fields["ports"])
		for _, uuid := range portUUIDs {
			if uuid.GoUuid == portUUID {
				bridgeName = bridge.Fields["name"].(string)
				break
			}
		}
	}

	return &datapath.Endpoint{
		MacAddrStr: macAddrStr,
		PortNo:     ofport,
		BridgeName: bridgeName,
		VlanID:     vlanID,
	}
}

func (monitor *AgentMonitor) syncAgentInfoWorker() {
	item, shutdown := monitor.syncQueue.Get()
	if shutdown {
		return
	}
	defer monitor.syncQueue.Done(item)

	if err := monitor.syncAgentInfo(); err != nil {
		monitor.syncQueue.AddAfter(monitor.Name(), time.Second)
		if errors.IsConflict(err) {
			klog.V(4).Infof("conflict update agentinfo %s: %s", monitor.Name(), err)
		} else {
			klog.Errorf("sync agentinfo %s: %s", monitor.Name(), err)
		}
	}
}

func (monitor *AgentMonitor) syncAgentInfo() error {
	ctx := context.Background()
	agentName := monitor.Name()

	agentInfo, err := monitor.getAgentInfo()
	if err != nil {
		return fmt.Errorf("couldn't get agentinfo: %s", err)
	}

	cpAgentInfo := &agentv1alpha1.AgentInfo{}

	err = monitor.k8sClient.Get(ctx, k8stypes.NamespacedName{Name: agentName}, cpAgentInfo)
	if errors.IsNotFound(err) {
		if err = monitor.k8sClient.Create(ctx, agentInfo); err != nil {
			return fmt.Errorf("couldn't create agent %s agentinfo: %s", agentName, err)
		}
		return nil
	}

	if err != nil {
		return fmt.Errorf("couldn't fetch agent %s agentinfo: %s", agentName, err)
	}

	monitor.ipCacheLock.Lock()
	defer monitor.ipCacheLock.Unlock()
	roundIPCache := monitor.ipCache
	monitor.ipCache = make(map[string]map[types.IPAddress]metav1.Time)

	monitor.mergeAgentInfo(agentInfo, cpAgentInfo)
	agentInfo.ObjectMeta = cpAgentInfo.ObjectMeta
	err = monitor.k8sClient.Update(ctx, agentInfo)
	if err != nil {
		monitor.ipCache = roundIPCache
		return err
	}

	return nil
}

func (monitor *AgentMonitor) mergeAgentInfo(localAgentInfo, cpAgentInfo *agentv1alpha1.AgentInfo) {
	for i, ovsBr := range localAgentInfo.OVSInfo.Bridges {
		for j, port := range ovsBr.Ports {
			for k, intf := range port.Interfaces {
				matchIntf := getCpIntf(ovsBr.Name, intf, cpAgentInfo)
				if matchIntf == nil {
					continue
				}
				for key, value := range matchIntf.IPMap {
					if intf.IPMap == nil {
						localAgentInfo.OVSInfo.Bridges[i].Ports[j].Interfaces[k].IPMap = make(map[types.IPAddress]metav1.Time)
					}
					if _, ok := intf.IPMap[key]; !ok {
						localAgentInfo.OVSInfo.Bridges[i].Ports[j].Interfaces[k].IPMap[key] = value
					}
				}
			}
		}
	}
}

func (monitor *AgentMonitor) getAgentInfo() (*agentv1alpha1.AgentInfo, error) {
	monitor.cacheLock.RLock()
	defer monitor.cacheLock.RUnlock()

	agentInfo := &agentv1alpha1.AgentInfo{
		ObjectMeta: metav1.ObjectMeta{
			Name:      monitor.Name(),
			Namespace: metav1.NamespaceNone,
		},
	}

	ovsVersion, err := monitor.fetchOvsVersionLocked()
	if err == nil {
		agentInfo.OVSInfo.Version = ovsVersion
	}

	hostname, err := os.Hostname()
	if err == nil {
		agentInfo.Hostname = hostname
	}

	for uuid := range monitor.ovsdbCache["Bridge"] {
		bridge, err := monitor.fetchBridgeLocked(ovsdb.UUID{GoUuid: uuid})
		if err != nil {
			return nil, fmt.Errorf("unable fetch bridge %s: %s", uuid, err)
		}
		agentInfo.OVSInfo.Bridges = append(agentInfo.OVSInfo.Bridges, *bridge)
	}

	agentHealthCondition := agentv1alpha1.AgentCondition{
		Type:              agentv1alpha1.AgentHealthy,
		Status:            corev1.ConditionTrue,
		LastHeartbeatTime: metav1.NewTime(time.Now()),
	}
	agentInfo.Conditions = []agentv1alpha1.AgentCondition{agentHealthCondition}

	return agentInfo, nil
}

func (monitor *AgentMonitor) filterEndpoint(rowupdate ovsdb.RowUpdate) (*datapath.Endpoint, *datapath.Endpoint) {
	if rowupdate.New.Fields["external_ids"] == nil {
		return nil, nil
	}
	newExternalIds := rowupdate.New.Fields["external_ids"].(ovsdb.OvsMap).GoMap

	// interface externalIDs without attached-mac, it's not local endpoint, ignore it
	if _, ok := newExternalIds[LocalEndpointIdentity]; !ok {
		return nil, nil
	}

	empty := ovsdb.Row{}
	if reflect.DeepEqual(rowupdate.Old, empty) {
		return monitor.filterEndpointAdded(rowupdate), nil
	}

	if rowupdate.Old.Fields["external_ids"] == nil {
		return monitor.filterEndpointAdded(rowupdate), nil
	}

	return monitor.filterEndpointUpdated(rowupdate)
}

func (monitor *AgentMonitor) filterEndpointUpdated(rowupdate ovsdb.RowUpdate) (*datapath.Endpoint, *datapath.Endpoint) {
	newExternalIds := rowupdate.New.Fields["external_ids"].(ovsdb.OvsMap).GoMap

	newOfPort, ok := rowupdate.New.Fields["ofport"].(float64)
	if !ok {
		return nil, nil
	}
	oldOfPort, ok := rowupdate.Old.Fields["ofport"].(float64)
	if !ok {
		return nil, nil
	}

	if newOfPort <= 0 || oldOfPort <= 0 {
		return nil, nil
	}

	macAddr, err := net.ParseMAC(newExternalIds["attached-mac"].(string))
	if err != nil {
		klog.Errorf("Parsing endpoint macAddr error: %v", macAddr)
		return nil, nil
	}
	// interface udpate is triggerd by some other fileds except that ofport field
	if newOfPort == oldOfPort {
		return nil, nil
	}
	monitor.localEndpointHardwareAddrCacheLock.Lock()
	defer monitor.localEndpointHardwareAddrCacheLock.Unlock()
	monitor.localEndpointHardwareAddrCache[newExternalIds[LocalEndpointIdentity].(string)] = uint32(newOfPort)

	newEndpoint := monitor.interfaceToEndpoint(uint32(newOfPort), rowupdate.New.Fields["name"].(string), macAddr.String())
	oldEndpoint := monitor.interfaceToEndpoint(uint32(oldOfPort), rowupdate.Old.Fields["name"].(string), macAddr.String())
	return newEndpoint, oldEndpoint
}

func (monitor *AgentMonitor) filterEndpointAdded(rowupdate ovsdb.RowUpdate) *datapath.Endpoint {
	newExternalIds := rowupdate.New.Fields["external_ids"].(ovsdb.OvsMap).GoMap
	monitor.localEndpointHardwareAddrCacheLock.Lock()
	defer monitor.localEndpointHardwareAddrCacheLock.Unlock()

	if _, ok := monitor.localEndpointHardwareAddrCache[newExternalIds[LocalEndpointIdentity].(string)]; ok {
		return nil
	}
	ofPort, ok := rowupdate.New.Fields["ofport"].(float64)
	if !ok {
		return nil
	}

	if ofPort <= 0 {
		// Parsing added ofport error: invalid local endpoint ofPort. In OfPort initializing status
		return nil
	}
	ofport := uint32(ofPort)

	macAddr, err := net.ParseMAC(newExternalIds["attached-mac"].(string))
	if err != nil {
		klog.Errorf("Parsing endpoint macAddr error: %v", macAddr)
		return nil
	}
	monitor.localEndpointHardwareAddrCache[newExternalIds[LocalEndpointIdentity].(string)] = uint32(ofPort)

	return monitor.interfaceToEndpoint(ofport, rowupdate.New.Fields["name"].(string), newExternalIds[LocalEndpointIdentity].(string))
}

func (monitor *AgentMonitor) filterEndpointDeleted(rowupdate ovsdb.RowUpdate) *datapath.Endpoint {
	var ofport uint32
	if rowupdate.Old.Fields["external_ids"] == nil {
		return nil
	}
	oldExternalIds := rowupdate.Old.Fields["external_ids"].(ovsdb.OvsMap).GoMap

	monitor.localEndpointHardwareAddrCacheLock.Lock()
	defer monitor.localEndpointHardwareAddrCacheLock.Unlock()
	if _, ok := oldExternalIds[LocalEndpointIdentity]; ok {
		if _, ok := monitor.localEndpointHardwareAddrCache[oldExternalIds[LocalEndpointIdentity].(string)]; !ok {
			return nil
		}

		ofPort, ok := rowupdate.Old.Fields["ofport"].(float64)
		if !ok {
			return nil
		}
		if ofPort <= 0 {
			ofport = monitor.localEndpointHardwareAddrCache[oldExternalIds[LocalEndpointIdentity].(string)]
		} else {
			ofport = uint32(ofPort)
		}

		delete(monitor.localEndpointHardwareAddrCache, oldExternalIds[LocalEndpointIdentity].(string))

		endpoint := monitor.interfaceToEndpoint(ofport, rowupdate.Old.Fields["name"].(string), oldExternalIds[LocalEndpointIdentity].(string))
		return endpoint
	}

	return nil
}

func (monitor *AgentMonitor) processEndpointUpdate(rowupdate ovsdb.RowUpdate) {
	newEndpoint, oldEndpoint := monitor.filterEndpoint(rowupdate)
	if newEndpoint != nil && oldEndpoint != nil {
		go monitor.ovsdbEventHandler.UpdateLocalEndpoint(*newEndpoint, *oldEndpoint)
	} else if newEndpoint != nil {
		go monitor.ovsdbEventHandler.AddLocalEndpoint(*newEndpoint)
	}
}

func (monitor *AgentMonitor) processEndpointDel(rowupdate ovsdb.RowUpdate) {
	deletedEndpoints := monitor.filterEndpointDeleted(rowupdate)
	if deletedEndpoints != nil {
		go monitor.ovsdbEventHandler.DeleteLocalEndpoint(*deletedEndpoints)
	}
}

func (monitor *AgentMonitor) handleOvsUpdates(updates ovsdb.TableUpdates) {
	monitor.cacheLock.Lock()
	defer monitor.cacheLock.Unlock()

	for table, tableUpdate := range updates.Updates {
		if _, ok := monitor.ovsdbCache[table]; !ok {
			monitor.ovsdbCache[table] = make(map[string]ovsdb.Row)
		}
		for uuid, row := range tableUpdate.Rows {
			empty := ovsdb.Row{}
			if !reflect.DeepEqual(row.New, empty) {
				if table == "Interface" {
					go monitor.processEndpointUpdate(row)
				}

				monitor.ovsdbCache[table][uuid] = row.New
			} else {
				if table == "Interface" {
					go monitor.processEndpointDel(row)
				}

				delete(monitor.ovsdbCache[table], uuid)
			}
		}
	}

	monitor.syncQueue.Add(monitor.Name())
}

func (monitor *AgentMonitor) Name() string {
	return monitor.agentName
}

func (monitor *AgentMonitor) fetchOvsVersionLocked() (string, error) {
	tableOvs := monitor.ovsdbCache["Open_vSwitch"]
	if len(tableOvs) == 0 {
		return "", fmt.Errorf("couldn't find table %s, agentMonitor may haven't start", "Open_vSwitch")
	}

	for _, raw := range tableOvs {
		return raw.Fields["ovs_version"].(string), nil
	}

	return "", nil
}

func (monitor *AgentMonitor) fetchPortLocked(uuid ovsdb.UUID, bridgeName string) (*agentv1alpha1.OVSPort, error) {
	ovsPort, ok := monitor.ovsdbCache["Port"][uuid.GoUuid]
	if !ok {
		return nil, fmt.Errorf("ovs port %s not found in cache", uuid)
	}

	port := &agentv1alpha1.OVSPort{
		Name:        ovsPort.Fields["name"].(string),
		ExternalIDs: make(map[string]string),
	}

	externalIDs := ovsPort.Fields["external_ids"].(ovsdb.OvsMap).GoMap
	for name, value := range externalIDs {
		port.ExternalIDs[name.(string)] = value.(string)
	}

	// we use _ receive the second return, because field type is ovsdb.OvsSet when field empty
	ovsVlanMode, _ := ovsPort.Fields["vlan_mode"].(string)
	ovsBondMode, _ := ovsPort.Fields["bond_mode"].(string)

	// json number type is always float64
	ovsTag, _ := ovsPort.Fields["tag"].(float64)
	ovsTrunks, _ := ovsPort.Fields["trunks"].(float64)

	port.VlanConfig = &agentv1alpha1.VlanConfig{
		VlanMode: vlanModeMap[ovsVlanMode],
		Tag:      int32(ovsTag),
		Trunks:   int32(ovsTrunks),
	}

	port.BondConfig = &agentv1alpha1.BondConfig{
		BondMode: bondModeMap[ovsBondMode],
	}

	for _, uuid := range listUUID(ovsPort.Fields["interfaces"]) {
		iface := monitor.fetchInterfaceLocked(uuid, bridgeName)
		if iface != nil {
			port.Interfaces = append(port.Interfaces, *iface)
		}
	}

	return port, nil
}

func (monitor *AgentMonitor) fetchInterfaceLocked(uuid ovsdb.UUID, bridgeName string) *agentv1alpha1.OVSInterface {
	ovsIface, ok := monitor.ovsdbCache["Interface"][uuid.GoUuid]
	if !ok {
		klog.V(4).Infof("could not find interface %+v in cache", ovsIface)
		return nil
	}
	// ignore interface will errors
	if ifHasError(ovsIface.Fields["error"]) {
		klog.V(4).Infof("errors occur in interface %+v", ovsIface)
		return nil
	}

	iface := agentv1alpha1.OVSInterface{
		Name:        ovsIface.Fields["name"].(string),
		Type:        ovsIface.Fields["type"].(string),
		ExternalIDs: make(map[string]string),
	}

	externalIDs := ovsIface.Fields["external_ids"].(ovsdb.OvsMap).GoMap
	for name, value := range externalIDs {
		iface.ExternalIDs[name.(string)] = value.(string)
	}

	if mac, ok := iface.ExternalIDs["attached-mac"]; ok {
		// if attached-mac found, use attached-mac as endpoint mac
		iface.Mac = mac
	} else {
		// field type is ovsdb.OvsSet instead of string when field empty
		iface.Mac, _ = ovsIface.Fields["mac_in_use"].(string)
	}

	ofport, ok := ovsIface.Fields["ofport"].(float64)
	if ok && ofport >= 0 {
		iface.Ofport = int32(ofport)
		monitor.ipCacheLock.Lock()
		defer monitor.ipCacheLock.Unlock()
		iface.IPMap = monitor.ipCache[fmt.Sprintf("%s-%d", bridgeName, iface.Ofport)]
	}

	// clear ip address set once we write it to local agentinfo.
	monitor.ipCache[fmt.Sprintf("%s-%d", bridgeName, iface.Ofport)] = make(map[types.IPAddress]metav1.Time)
	return &iface
}

func (monitor *AgentMonitor) fetchBridgeLocked(uuid ovsdb.UUID) (*agentv1alpha1.OVSBridge, error) {
	ovsBri, ok := monitor.ovsdbCache["Bridge"][uuid.GoUuid]
	if !ok {
		return nil, fmt.Errorf("ovs bridge %s not found in cache", uuid)
	}

	bridge := &agentv1alpha1.OVSBridge{
		Name: ovsBri.Fields["name"].(string),
	}

	for _, uuid := range listUUID(ovsBri.Fields["ports"]) {
		port, err := monitor.fetchPortLocked(uuid, bridge.Name)
		if err != nil {
			return nil, err
		}
		bridge.Ports = append(bridge.Ports, *port)
	}

	return bridge, nil
}

func ifHasError(ovsIf interface{}) bool {
	value, ok := ovsIf.(string)
	if !ok {
		return false
	}
	if ok && value == "" {
		return false
	}
	return true
}

func listUUID(uuidList interface{}) []ovsdb.UUID {
	var idList []ovsdb.UUID

	switch uuidList.(type) {
	case ovsdb.UUID:
		return []ovsdb.UUID{uuidList.(ovsdb.UUID)}
	case ovsdb.OvsSet:
		uuidSet := uuidList.(ovsdb.OvsSet).GoSet
		for item := range uuidSet {
			idList = append(idList, listUUID(uuidSet[item])...)
		}
	}

	return idList
}

func readOrGenerateAgentName() (string, error) {
	content, err := ioutil.ReadFile(AgentNameConfigPath)
	if err == nil {
		return string(content), nil
	}

	name := string(typeuuid.NewUUID())

	err = os.MkdirAll(filepath.Dir(AgentNameConfigPath), 0644)
	if err != nil {
		return "", fmt.Errorf("while write name %s: %s", name, err)
	}

	err = ioutil.WriteFile(AgentNameConfigPath, []byte(name), 0644)
	if err != nil {
		return "", fmt.Errorf("while write name %s: %s", name, err)
	}

	return name, nil
}

func getCpIntf(bridgeName string, newInterface agentv1alpha1.OVSInterface, cpAgentInfo *agentv1alpha1.AgentInfo) *agentv1alpha1.OVSInterface {
	var matchInterface agentv1alpha1.OVSInterface
	for _, ovsBr := range cpAgentInfo.OVSInfo.Bridges {
		if ovsBr.Name != bridgeName {
			continue
		}
		for _, port := range ovsBr.Ports {
			for _, intf := range port.Interfaces {
				if intf.Ofport == newInterface.Ofport {
					intf.DeepCopyInto(&matchInterface)
					return &matchInterface
				}
			}
		}
	}

	return nil
}
