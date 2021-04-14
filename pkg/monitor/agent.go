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
	"github.com/contiv/ofnet"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8stypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	typeuuid "k8s.io/apimachinery/pkg/util/uuid"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog"
	"sigs.k8s.io/controller-runtime/pkg/client"

	agentv1alpha1 "github.com/smartxworks/lynx/pkg/apis/agent/v1alpha1"
	"github.com/smartxworks/lynx/pkg/types"
)

const (
	AgentNameConfigPath   = "/var/lib/lynx/agent/name"
	LocalEndpointIdentity = "attached-mac"
	UplinkPortIdentity    = "uplink-port"
	UplinkUpdateInterval  = 300
)

type ovsdbEventHandler interface {
	AddLocalEndpoint(endpointInfo ofnet.EndpointInfo)
	DeleteLocalEndpoint(portNo uint32)
	UpdateUplinkActiveSlave(ofPort uint32)
	AddUplink(port *ofnet.PortInfo)
	DeleteUplink(portName string)
}

type OvsdbEventHandlerFuncs struct {
	LocalEndpointAddFunc        func(endpointInfo ofnet.EndpointInfo)
	LocalEndpointDeleteFunc     func(portNo uint32)
	UplinkActiveSlaveUpdateFunc func(portName string, updates ofnet.PortUpdates)
	UplinkAddFunc               func(port *ofnet.PortInfo)
	UplinkDelFunc               func(portName string)
}

func (handler OvsdbEventHandlerFuncs) AddLocalEndpoint(endpointInfo ofnet.EndpointInfo) {
	if handler.LocalEndpointAddFunc != nil {
		handler.LocalEndpointAddFunc(endpointInfo)
	}
}

func (handler OvsdbEventHandlerFuncs) DeleteLocalEndpoint(portNo uint32) {
	if handler.LocalEndpointDeleteFunc != nil {
		handler.LocalEndpointDeleteFunc(portNo)
	}
}

func (handler OvsdbEventHandlerFuncs) UpdateUplinkActiveSlave(ofPort uint32) {
	if handler.UplinkActiveSlaveUpdateFunc != nil {
		portUpdate := ofnet.PortUpdates{
			Updates: []ofnet.PortUpdate{{
				UpdateInfo: ofPort,
			}},
		}
		handler.UplinkActiveSlaveUpdateFunc("", portUpdate)
	}
}

func (handler OvsdbEventHandlerFuncs) AddUplink(port *ofnet.PortInfo) {
	if handler.UplinkAddFunc != nil {
		handler.UplinkAddFunc(port)
	}
}

func (handler OvsdbEventHandlerFuncs) DeleteUplink(portName string) {
	if handler.UplinkDelFunc != nil {
		handler.UplinkDelFunc(portName)
	}
}

func (monitor *agentMonitor) RegisterOvsdbEventHandler(ovsdbEventHandler ovsdbEventHandler) {
	if ovsdbEventHandler == nil {
		klog.Fatalf("Failed to register ovsdbEventHandler: register nil ovsdbEventHandler not allow")
	}
	if monitor.ovsdbEventHandler != nil {
		klog.Fatalf("Failed to register ovsdbEventHandler: monitor ovsdbEventHandler already register")
	}

	monitor.ovsdbEventHandler = ovsdbEventHandler
}

// agentMonitor monitor agent state, update agentinfo to apiserver.
type agentMonitor struct {
	// k8sClient used to create/read/update agentinfo
	k8sClient client.Client
	// ovsClient used to monitor ovsdb table port/bridge/interface
	ovsClient *ovsdb.OvsdbClient

	// agentName is the name and uuid of this agent
	agentName string

	// cacheLock is a read/write lock for accessing the cache
	cacheLock                  sync.RWMutex
	ovsdbCache                 map[string]map[string]ovsdb.Row
	ofportsCache               map[int32][]types.IPAddress
	ofPortIPAddressMonitorChan chan map[uint32][]net.IP

	ovsdbEventHandler              ovsdbEventHandler
	localEndpointHardwareAddrCache sets.String
	inUpdatingUplinkMutex          sync.RWMutex
	inUpdatingUplinkPortMap        map[string]ovsdb.RowUpdate
	isUpdatingUplinkActive         bool

	// syncQueue used to notify agentMonitor synchronize AgentInfo
	syncQueue workqueue.RateLimitingInterface
}

// NewAgentMonitor return a new agentMonitor with kubernetes client and ipMonitor.
func NewAgentMonitor(client client.Client, ofPortIPAddressMonitorChan chan map[uint32][]net.IP) (*agentMonitor, error) {
	monitor := &agentMonitor{
		k8sClient:                      client,
		cacheLock:                      sync.RWMutex{},
		ovsdbCache:                     make(map[string]map[string]ovsdb.Row),
		ofportsCache:                   make(map[int32][]types.IPAddress),
		ofPortIPAddressMonitorChan:     ofPortIPAddressMonitorChan,
		localEndpointHardwareAddrCache: sets.NewString(),
		inUpdatingUplinkPortMap:        make(map[string]ovsdb.RowUpdate),
		isUpdatingUplinkActive:         false,
		syncQueue:                      workqueue.NewRateLimitingQueue(workqueue.DefaultItemBasedRateLimiter()),
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

func (monitor *agentMonitor) Run(stopChan <-chan struct{}) error {
	defer monitor.syncQueue.ShutDown()
	defer monitor.ovsClient.Disconnect()

	klog.Infof("start agent %s monitor", monitor.Name())
	defer klog.Infof("shutting down agent %s monitor", monitor.Name())

	var err error

	err = monitor.rebuildOfportCache()
	if err != nil {
		klog.Errorf("unable rebuild ofport cache from apiserver: %s", err)
		return err
	}

	err = monitor.startOvsdbMonitor()
	if err != nil {
		klog.Errorf("unable start ovsdb monitor: %s", err)
		return err
	}
	go monitor.HandleOfPortIPAddressUpdate(monitor.ofPortIPAddressMonitorChan, stopChan)

	go wait.Until(monitor.syncAgentInfoWorker, 0, stopChan)
	<-stopChan

	return nil
}

func (monitor *agentMonitor) HandleOfPortIPAddressUpdate(ofPortIPAddressMonitorChan <-chan map[uint32][]net.IP,
	stopChan <-chan struct{}) {
	for {
		select {
		case localEndpointInfo := <-ofPortIPAddressMonitorChan:
			monitor.updateOfPortIPAddress(localEndpointInfo)
		case <-stopChan:
			return
		}
	}
}

func (monitor *agentMonitor) updateOfPortIPAddress(localEndpointInfo map[uint32][]net.IP) {
	monitor.cacheLock.Lock()
	defer monitor.cacheLock.Unlock()

	for port, ips := range localEndpointInfo {
		// OfPort already updated, flush deprecated ofportsCache entry related with port
		if len(ips) == 0 {
			delete(monitor.ofportsCache, int32(port))
			break
		}

		var ipAddrs []types.IPAddress
		for _, ip := range ips {
			ipAddrs = append(ipAddrs, types.IPAddress(ip.String()))
		}
		monitor.ofportsCache[int32(port)] = ipAddrs
	}

	monitor.syncQueue.Add(monitor.Name())
}

func (monitor *agentMonitor) startOvsdbMonitor() error {
	klog.Infof("start monitor ovsdb %s", "Open_vSwitch")
	monitor.ovsClient.Register(ovsUpdateHandlerFunc(monitor.handleOvsUpdates))

	selectAll := ovsdb.MonitorSelect{
		Initial: true,
		Insert:  true,
		Delete:  true,
		Modify:  true,
	}
	requests := map[string]ovsdb.MonitorRequest{
		"Port": {Select: selectAll, Columns: []string{"name", "interfaces", "external_ids", "bond_mode",
			"bond_active_slave", "vlan_mode", "tag", "trunks"}},
		"Interface":    {Select: selectAll, Columns: []string{"name", "mac_in_use", "ofport", "type", "external_ids"}},
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

func (monitor *agentMonitor) syncAgentInfoWorker() {
	item, shutdown := monitor.syncQueue.Get()
	if shutdown {
		return
	}
	defer monitor.syncQueue.Done(item)

	if err := monitor.syncAgentInfo(); err != nil {
		monitor.syncQueue.AddAfter(monitor.Name(), time.Second)
		klog.Errorf("couldn't to sync agentinfo %s: %s", monitor.Name(), err)
	}
}

func (monitor *agentMonitor) syncAgentInfo() error {
	ctx := context.Background()
	agentName := monitor.Name()

	agentInfo, err := monitor.getAgentInfo()
	if err != nil {
		return fmt.Errorf("couldn't get agentinfo: %s", err)
	}

	agentInfoOld := &agentv1alpha1.AgentInfo{}

	err = monitor.k8sClient.Get(ctx, k8stypes.NamespacedName{Name: agentName}, agentInfoOld)
	if errors.IsNotFound(err) {
		if err = monitor.k8sClient.Create(ctx, agentInfo); err != nil {
			return fmt.Errorf("couldn't create agent %s agentinfo: %s", agentName, err)
		}
		return nil
	}

	if err != nil {
		return fmt.Errorf("couldn't fetch agent %s agentinfo: %s", agentName, err)
	}

	agentInfo.ObjectMeta = agentInfoOld.ObjectMeta
	err = monitor.k8sClient.Update(ctx, agentInfo)
	if err != nil {
		return fmt.Errorf("couldn't update agent %s agentinfo: %s", agentName, err)
	}

	return nil
}

func (monitor *agentMonitor) getAgentInfo() (*agentv1alpha1.AgentInfo, error) {
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

// when agent restart, mapping of ofport to IPaddr lost, rebuild from agentInfo
func (monitor *agentMonitor) rebuildOfportCache() error {
	klog.Infof("rebuild ofport cache from agentInfo")

	var ctx = context.Background()
	var agentInfo agentv1alpha1.AgentInfo

	err := monitor.k8sClient.Get(ctx, k8stypes.NamespacedName{Name: monitor.Name()}, &agentInfo)
	if err != nil {
		// ignore NotFoundError, agentInfo hasn't been created yet
		return client.IgnoreNotFound(err)
	}

	monitor.cacheLock.Lock()
	defer monitor.cacheLock.Unlock()

	for _, bridge := range agentInfo.OVSInfo.Bridges {
		for _, port := range bridge.Ports {
			for _, iface := range port.Interfaces {
				if iface.Ofport < 0 || len(iface.IPs) == 0 {
					// skip if interface has empty IPaddr
					continue
				}
				if _, ok := monitor.ofportsCache[iface.Ofport]; ok {
					// skip if monitor has learned ofport IPaddr
					continue
				}
				monitor.ofportsCache[iface.Ofport] = iface.IPs
			}
		}
	}

	return nil
}

func (monitor *agentMonitor) filterEndpointAdded(rowupdate ovsdb.RowUpdate) *ofnet.EndpointInfo {
	if rowupdate.New.Fields["external_ids"] == nil {
		return nil
	}

	newExternalIds := rowupdate.New.Fields["external_ids"].(ovsdb.OvsMap).GoMap
	if _, ok := newExternalIds[LocalEndpointIdentity]; ok {
		// LocalEndpoint already exists
		if monitor.localEndpointHardwareAddrCache.Has(newExternalIds[LocalEndpointIdentity].(string)) {
			return nil
		}

		ofPort, ok := rowupdate.New.Fields["ofport"].(float64)
		if !ok {
			klog.Errorf("Parsing added ofPort error: ofPort not found")
			return nil
		}

		if ofPort < 0 {
			klog.Errorf("Parsing added ofport error: Invalid invalid local endpoint ofPort %f", ofPort)
			return nil
		}

		if ofPort == 0 {
			// OfPort in initializing status
			return nil
		}

		ofport := uint32(ofPort)

		macAddr, err := net.ParseMAC(newExternalIds["attached-mac"].(string))
		if err != nil {
			klog.Errorf("Parsing endpoint macAddr error: %v", macAddr)
			return nil
		}

		monitor.localEndpointHardwareAddrCache.Insert(newExternalIds[LocalEndpointIdentity].(string))

		return &ofnet.EndpointInfo{
			MacAddr: macAddr,
			PortNo:  ofport,
		}
	}

	return nil
}

func (monitor *agentMonitor) filterEndpointDeleted(rowupdate ovsdb.RowUpdate) *uint32 {
	if rowupdate.Old.Fields["external_ids"] == nil {
		return nil
	}

	oldExternalIds := rowupdate.Old.Fields["external_ids"].(ovsdb.OvsMap).GoMap
	if _, ok := oldExternalIds[LocalEndpointIdentity]; ok {
		if !monitor.localEndpointHardwareAddrCache.Has(oldExternalIds[LocalEndpointIdentity].(string)) {
			return nil
		}

		ofPort, ok := rowupdate.Old.Fields["ofport"].(float64)
		if !ok {
			klog.Errorf("Parsing deleted ofPort error: ofPort not found")
			return nil
		}
		if ofPort <= 0 {
			klog.Errorf("Parsing deleted ofPort error: invalid local endpoint ofport %f ", ofPort)
			return nil
		}
		ofport := uint32(ofPort)

		monitor.localEndpointHardwareAddrCache.Delete(oldExternalIds[LocalEndpointIdentity].(string))

		return &ofport
	}

	return nil
}

func (monitor *agentMonitor) filterUplinkPort(rowupdate ovsdb.RowUpdate) bool {
	if rowupdate.New.Fields["external_ids"] == nil {
		return false
	}

	newExternalIds := rowupdate.New.Fields["external_ids"].(ovsdb.OvsMap).GoMap
	if _, ok := newExternalIds[UplinkPortIdentity]; ok {
		return true
	}

	return false
}

func (monitor *agentMonitor) filterBondModeUpdate(rowupdate ovsdb.RowUpdate) bool {
	if rowupdate.New.Fields["bond_mode"] != nil && rowupdate.Old.Fields["bond_mode"] != nil &&
		!reflect.DeepEqual(rowupdate.New.Fields["bond_mode"], rowupdate.Old.Fields["bond_mode"]) {
		return true
	}

	return false
}

func (monitor *agentMonitor) filterBondActiveSlaveUpdate(rowupdate ovsdb.RowUpdate) bool {
	if rowupdate.New.Fields["bond_active_slave"] != nil && rowupdate.Old.Fields["bond_active_slave"] != nil &&
		!reflect.DeepEqual(rowupdate.New.Fields["bond_active_slave"], rowupdate.Old.Fields["bond_active_slave"]) {
		return true
	}

	return false
}

func (monitor *agentMonitor) filterCurrentBondActiveSlave(rowupdate ovsdb.RowUpdate) *uint32 {
	var activeInterfaceOfPort uint32

	curActiveSlaveMacAddr, _ := rowupdate.New.Fields["bond_active_slave"].(string)
	if curActiveSlaveMacAddr == "" {
		return nil
	}

	bondInterfaceUUIDs := listUUID(rowupdate.New.Fields["interfaces"])
	for _, interfaceUUID := range bondInterfaceUUIDs {
		ovsInterface, ok := monitor.ovsdbCache["Interface"][interfaceUUID.GoUuid]
		if !ok {
			klog.Infof("Failed to get ovs interface: %+v", interfaceUUID)
			continue
		}

		interfaceMac, _ := ovsInterface.Fields["mac_in_use"].(string)
		if interfaceMac == curActiveSlaveMacAddr {
			ofPort, ok := ovsInterface.Fields["ofport"].(float64)
			if ok && ofPort > 0 {
				activeInterfaceOfPort = uint32(ofPort)
			}

			return &activeInterfaceOfPort
		}
	}

	return nil
}

func (monitor *agentMonitor) filterUplinkAlreadyAdded(rowupdate ovsdb.RowUpdate) bool {
	if rowupdate.Old.Fields["external_ids"] != nil {
		oldExternalIds := rowupdate.Old.Fields["external_ids"].(ovsdb.OvsMap).GoMap
		if _, ok := oldExternalIds[UplinkPortIdentity]; ok {
			// UplinkPortIdentity already exists --- uplinkPortExternalIds fields already exists in rowOld.
			return true
		}
	}

	return false
}

func (monitor *agentMonitor) filterUplinkDeleted(rowupdate ovsdb.RowUpdate) *string {
	if rowupdate.Old.Fields["external_ids"] == nil {
		return nil
	}

	oldExternalIds := rowupdate.Old.Fields["external_ids"].(ovsdb.OvsMap).GoMap
	if _, ok := oldExternalIds[UplinkPortIdentity]; ok {
		uplinkPortName := rowupdate.Old.Fields["name"].(string)

		return &uplinkPortName
	}

	return nil
}

func (monitor *agentMonitor) buildUplinkPortInfo(rowupdate ovsdb.RowUpdate) *ofnet.PortInfo {
	var portInfo ofnet.PortInfo
	var mbrLinkInfo []*ofnet.LinkInfo
	var portType string = "individual"
	uplinkPortName := rowupdate.New.Fields["name"].(string)

	uplinkInterfaceUUIDs := listUUID(rowupdate.New.Fields["interfaces"])
	if len(uplinkInterfaceUUIDs) > 1 {
		portType = "bond"
	}

	for _, interfaceUUID := range uplinkInterfaceUUIDs {
		var interfaceOfPort uint32
		uplinkInterface, ok := monitor.ovsdbCache["Interface"][interfaceUUID.GoUuid]
		if !ok {
			return nil
		}

		interfaceName, _ := uplinkInterface.Fields["name"].(string)
		ofport, ok := uplinkInterface.Fields["ofport"].(float64)
		if !ok {
			return nil
		}

		if ofport < 0 {
			return nil
		}

		// OfPort of UplinkPort member link interface is not initialized
		if ofport == 0 {
			return nil
		}

		interfaceOfPort = uint32(ofport)

		mbrLinkInfo = append(mbrLinkInfo, &ofnet.LinkInfo{
			Name:       interfaceName,
			OfPort:     interfaceOfPort,
			LinkStatus: 0,
			Port:       &portInfo,
		})
	}

	portInfo = ofnet.PortInfo{
		Name:       uplinkPortName,
		Type:       portType,
		LinkStatus: 0,
		MbrLinks:   mbrLinkInfo,
	}

	return &portInfo
}

func (monitor *agentMonitor) processInterfaceUpdate(rowupdate ovsdb.RowUpdate) {
	addedEndpoints := monitor.filterEndpointAdded(rowupdate)
	if addedEndpoints != nil {
		go monitor.ovsdbEventHandler.AddLocalEndpoint(*addedEndpoints)
	}
}

func (monitor *agentMonitor) processInterfaceDelete(rowupdate ovsdb.RowUpdate) {
	deletedEndpoints := monitor.filterEndpointDeleted(rowupdate)
	if deletedEndpoints != nil {
		go monitor.ovsdbEventHandler.DeleteLocalEndpoint(*deletedEndpoints)
	}
}

func (monitor *agentMonitor) processPortUpdate(rowupdate ovsdb.RowUpdate) {
	if !monitor.filterUplinkPort(rowupdate) {
		// Whether it's uplink port
		return
	}

	if monitor.filterBondModeUpdate(rowupdate) {
		return
	}

	if monitor.filterBondActiveSlaveUpdate(rowupdate) {
		curActiveSlaveInterfaceOfPort := monitor.filterCurrentBondActiveSlave(rowupdate)
		if curActiveSlaveInterfaceOfPort != nil {
			monitor.processBondActiveSlaveSwitch(*curActiveSlaveInterfaceOfPort)
		}
		return
	}

	addedUplinkPortName, _ := rowupdate.New.Fields["name"].(string)
	if monitor.filterUplinkAlreadyAdded(rowupdate) {
		// Add port event of received uplink port already processed in previous round, this event is update some other
		// column in port table
		return
	}

	monitor.inUpdatingUplinkMutex.Lock()
	defer monitor.inUpdatingUplinkMutex.Unlock()

	monitor.inUpdatingUplinkPortMap[addedUplinkPortName] = rowupdate

	if !monitor.isUpdatingUplinkActive {
		go monitor.processInUpdatingUplinkAdd()
		monitor.isUpdatingUplinkActive = true
	}
}

func (monitor *agentMonitor) processInUpdatingUplinkAdd() {
	for {
		monitor.inUpdatingUplinkMutex.Lock()

		for portname, row := range monitor.inUpdatingUplinkPortMap {
			monitor.cacheLock.Lock()
			addedUplinkPort := monitor.buildUplinkPortInfo(row)
			monitor.cacheLock.Unlock()

			if addedUplinkPort != nil {
				go monitor.ovsdbEventHandler.AddUplink(addedUplinkPort)
				delete(monitor.inUpdatingUplinkPortMap, portname)

				continue
			}
		}

		if len(monitor.inUpdatingUplinkPortMap) == 0 {
			monitor.isUpdatingUplinkActive = false
			monitor.inUpdatingUplinkMutex.Unlock()

			return
		}

		monitor.inUpdatingUplinkMutex.Unlock()
		time.Sleep(time.Millisecond * UplinkUpdateInterval)
	}
}

func (monitor *agentMonitor) processPortDelete(rowupdate ovsdb.RowUpdate) {
	deletedUplinkPortName := monitor.filterUplinkDeleted(rowupdate)
	if deletedUplinkPortName != nil {
		go monitor.ovsdbEventHandler.DeleteUplink(*deletedUplinkPortName)
	}
}

func (monitor *agentMonitor) processBondActiveSlaveSwitch(curBondActiveSlaveInterfaceOfPort uint32) {
	go monitor.ovsdbEventHandler.UpdateUplinkActiveSlave(curBondActiveSlaveInterfaceOfPort)
}

func (monitor *agentMonitor) handleOvsUpdates(updates ovsdb.TableUpdates) {
	monitor.cacheLock.Lock()
	defer monitor.cacheLock.Unlock()

	for table, tableUpdate := range updates.Updates {
		if _, ok := monitor.ovsdbCache[table]; !ok {
			monitor.ovsdbCache[table] = make(map[string]ovsdb.Row)
		}
		for uuid, row := range tableUpdate.Rows {
			empty := ovsdb.Row{}
			if !reflect.DeepEqual(row.New, empty) {
				switch table {
				case "Interface":
					monitor.processInterfaceUpdate(row)
				case "Port":
					monitor.processPortUpdate(row)
				}

				monitor.ovsdbCache[table][uuid] = row.New
			} else {
				switch table {
				case "Interface":
					monitor.processInterfaceDelete(row)
				case "Port":
					monitor.processPortDelete(row)
				}

				delete(monitor.ovsdbCache[table], uuid)
			}
		}
	}

	monitor.syncQueue.Add(monitor.Name())
}

func (monitor *agentMonitor) Name() string {
	return monitor.agentName
}

func (monitor *agentMonitor) fetchOvsVersionLocked() (string, error) {
	tableOvs := monitor.ovsdbCache["Open_vSwitch"]
	if len(tableOvs) == 0 {
		return "", fmt.Errorf("couldn't find table %s, agentMonitor may haven't start", "Open_vSwitch")
	}

	for _, raw := range tableOvs {
		return raw.Fields["ovs_version"].(string), nil
	}

	return "", nil
}

func (monitor *agentMonitor) fetchPortLocked(uuid ovsdb.UUID) (*agentv1alpha1.OVSPort, error) {
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
		iface, err := monitor.fetchInterfaceLocked(uuid)
		if err != nil {
			return nil, err
		}
		port.Interfaces = append(port.Interfaces, *iface)
	}

	return port, nil
}

func (monitor *agentMonitor) fetchInterfaceLocked(uuid ovsdb.UUID) (*agentv1alpha1.OVSInterface, error) {
	ovsIface, ok := monitor.ovsdbCache["Interface"][uuid.GoUuid]
	if !ok {
		return nil, fmt.Errorf("ovs interface %s not found in cache", uuid)
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
		iface.IPs = monitor.ofportsCache[iface.Ofport]
	}

	return &iface, nil
}

func (monitor *agentMonitor) fetchBridgeLocked(uuid ovsdb.UUID) (*agentv1alpha1.OVSBridge, error) {
	ovsBri, ok := monitor.ovsdbCache["Bridge"][uuid.GoUuid]
	if !ok {
		return nil, fmt.Errorf("ovs bridge %s not found in cache", uuid)
	}

	bridge := &agentv1alpha1.OVSBridge{
		Name: ovsBri.Fields["name"].(string),
	}

	for _, uuid := range listUUID(ovsBri.Fields["ports"]) {
		port, err := monitor.fetchPortLocked(uuid)
		if err != nil {
			return nil, err
		}
		bridge.Ports = append(bridge.Ports, *port)
	}

	return bridge, nil
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
