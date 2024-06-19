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
	"reflect"
	"strings"
	"sync"

	ovsdb "github.com/contiv/libovsdb"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"

	"github.com/everoute/everoute/pkg/agent/datapath"
	"github.com/everoute/everoute/pkg/utils"
)

const (
	OvsDBBridgeTable    = "Bridge"
	OvsDBPortTable      = "Port"
	OvsDBInterfaceTable = "Interface"

	OvsdbUpdatesChanSize = 100
)

type ovsdbEventHandler interface {
	AddLocalEndpoint(endpoint *datapath.Endpoint)
	DeleteLocalEndpoint(endpoint *datapath.Endpoint)
	UpdateLocalEndpoint(newEndpoint *datapath.Endpoint, oldEndpoint *datapath.Endpoint)
}

type OvsdbEventHandlerFuncs struct {
	LocalEndpointAddFunc    func(endpoint *datapath.Endpoint)
	LocalEndpointDeleteFunc func(endpoint *datapath.Endpoint)
	LocalEndpointUpdateFunc func(newEndpoint *datapath.Endpoint, oldEndpoint *datapath.Endpoint)
}

func (handler OvsdbEventHandlerFuncs) AddLocalEndpoint(endpoint *datapath.Endpoint) {
	if handler.LocalEndpointAddFunc != nil {
		handler.LocalEndpointAddFunc(endpoint)
	}
}

func (handler OvsdbEventHandlerFuncs) DeleteLocalEndpoint(endpoint *datapath.Endpoint) {
	if handler.LocalEndpointDeleteFunc != nil {
		handler.LocalEndpointDeleteFunc(endpoint)
	}
}

func (handler OvsdbEventHandlerFuncs) UpdateLocalEndpoint(newEndpoint *datapath.Endpoint, oldEndpoint *datapath.Endpoint) {
	if handler.LocalEndpointUpdateFunc != nil {
		handler.LocalEndpointUpdateFunc(newEndpoint, oldEndpoint)
	}
}

type OVSDBCache map[string]map[string]ovsdb.Row

// OVSDBMonitor monitor and cache ovsdb, the syncQueue are queued on cache updates
type OVSDBMonitor struct {
	// ovsClient used to monitor ovsdb table port/bridge/interface
	ovsClient *ovsdb.OvsdbClient

	// cacheLock is a read/write lock for accessing the cache
	cacheLock  sync.RWMutex
	ovsdbCache OVSDBCache

	ovsdbEventHandler ovsdbEventHandler
	// map interface uuid
	endpointMap      map[string]*datapath.Endpoint
	bridgeMap        map[string]sets.String
	ovsdbUpdatesChan chan ovsdb.TableUpdates

	// syncQueue used to notify ovsdb update
	syncQueue workqueue.RateLimitingInterface
}

// NewOVSDBMonitor create a new instance of OVSDBMonitor
func NewOVSDBMonitor() (*OVSDBMonitor, error) {
	ovsClient, err := ovsdb.ConnectUnix(ovsdb.DEFAULT_SOCK)
	if err != nil {
		return nil, err
	}

	monitor := &OVSDBMonitor{
		ovsClient:        ovsClient,
		cacheLock:        sync.RWMutex{},
		endpointMap:      make(map[string]*datapath.Endpoint),
		ovsdbCache:       make(map[string]map[string]ovsdb.Row),
		syncQueue:        workqueue.NewRateLimitingQueue(workqueue.DefaultItemBasedRateLimiter()),
		bridgeMap:        make(map[string]sets.String),
		ovsdbUpdatesChan: make(chan ovsdb.TableUpdates, OvsdbUpdatesChanSize),
	}

	return monitor, nil
}

func (monitor *OVSDBMonitor) RegisterOvsdbEventHandler(ovsdbEventHandler ovsdbEventHandler) {
	if ovsdbEventHandler == nil {
		klog.Fatalf("Failed to register ovsdbEventHandler: register nil ovsdbEventHandler not allow")
	}
	if monitor.ovsdbEventHandler != nil {
		klog.Fatalf("Failed to register ovsdbEventHandler: monitor ovsdbEventHandler already register")
	}

	monitor.ovsdbEventHandler = ovsdbEventHandler
}

func (monitor *OVSDBMonitor) LockedAccessCache(readFunc func(OVSDBCache) error) error {
	monitor.cacheLock.RLock()
	defer monitor.cacheLock.RUnlock()
	return readFunc(monitor.ovsdbCache)
}

func (monitor *OVSDBMonitor) GetSyncQueue() workqueue.RateLimitingInterface {
	return monitor.syncQueue
}

func (monitor *OVSDBMonitor) Run(stopChan <-chan struct{}) {
	defer monitor.ovsClient.Disconnect()

	klog.Infof("start ovsdb monitor")
	defer klog.Infof("shutting down ovsdb monitor")

	err := monitor.startOvsdbMonitor()
	if err != nil {
		klog.Fatalf("unable start ovsdb monitor: %s", err)
	}
	go monitor.handleOvsEvents(stopChan)

	<-stopChan
}

func (monitor *OVSDBMonitor) startOvsdbMonitor() error {
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
		"Interface":    {Select: selectAll, Columns: []string{"name", "mac_in_use", "ofport", "type", "external_ids", "error", "status"}},
		"Bridge":       {Select: selectAll, Columns: []string{"name", "ports"}},
		"Open_vSwitch": {Select: selectAll, Columns: []string{"ovs_version"}},
	}

	err := monitor.ovsClient.Monitor("Open_vSwitch", nil, requests)
	if err != nil {
		return fmt.Errorf("monitor ovsdb %s: %s", "Open_vSwitch", err)
	}

	return nil
}

func (monitor *OVSDBMonitor) filterPortVlanModeUpdate(rowupdate ovsdb.RowUpdate, ifaceUUID string) (*datapath.Endpoint, *datapath.Endpoint) {
	var newEndpoint, oldEndpoint *datapath.Endpoint
	var oldTag, newTag *float64
	var oldTrunk, newTrunk []float64
	var ok bool

	oldEndpoint, ok = monitor.endpointMap[ifaceUUID]
	if !ok {
		return nil, nil
	}
	if rowupdate.New.Fields["tag"] != nil {
		newID, ok := rowupdate.New.Fields["tag"].(float64)
		if ok {
			newTag = &newID
		}
	}
	if rowupdate.Old.Fields["tag"] != nil {
		oldID, ok := rowupdate.Old.Fields["tag"].(float64)
		if ok {
			oldTag = &oldID
		}
	}
	if rowupdate.New.Fields["trunks"] != nil {
		newTrunk = listVlanTrunks(rowupdate.New.Fields["trunks"])
	}
	if rowupdate.Old.Fields["trunks"] != nil {
		oldTrunk = listVlanTrunks(rowupdate.Old.Fields["trunks"])
	}

	// access to trunk
	if newTag == nil && oldTag != nil && len(newTrunk) != 0 && len(oldTrunk) == 0 {
		trunkString := strings.Trim(strings.Join(strings.Split(fmt.Sprintf("%v", newTrunk), " "), ","), "[]")
		newEndpoint = &datapath.Endpoint{
			InterfaceName: oldEndpoint.InterfaceName,
			InterfaceUUID: oldEndpoint.InterfaceUUID,
			MacAddrStr:    oldEndpoint.MacAddrStr,
			PortNo:        oldEndpoint.PortNo,
			BridgeName:    oldEndpoint.BridgeName,
			Trunk:         trunkString,
			VlanID:        0,
		}
	}
	// trunk to access
	if newTag != nil && oldTag == nil && len(newTrunk) == 0 && len(oldTrunk) != 0 {
		newEndpoint = &datapath.Endpoint{
			InterfaceName: oldEndpoint.InterfaceName,
			InterfaceUUID: oldEndpoint.InterfaceUUID,
			MacAddrStr:    oldEndpoint.MacAddrStr,
			PortNo:        oldEndpoint.PortNo,
			BridgeName:    oldEndpoint.BridgeName,
			VlanID:        uint16(*newTag),
			Trunk:         "",
		}
	}

	return newEndpoint, oldEndpoint
}

func (monitor *OVSDBMonitor) filterPortVlanTagUpdate(rowupdate ovsdb.RowUpdate, ifaceUUID string) (*datapath.Endpoint, *datapath.Endpoint) {
	var newEndpoint, oldEndpoint *datapath.Endpoint
	var oldTag, newTag float64
	if rowupdate.New.Fields["tag"] == nil || rowupdate.Old.Fields["tag"] == nil {
		return nil, nil
	}
	newTag, _ = rowupdate.New.Fields["tag"].(float64)
	oldTag, _ = rowupdate.Old.Fields["tag"].(float64)
	if newTag == oldTag {
		return nil, nil
	}

	if _, ok := monitor.endpointMap[ifaceUUID]; !ok {
		return nil, nil
	}

	oldEndpoint = monitor.endpointMap[ifaceUUID]
	newEndpoint = &datapath.Endpoint{
		InterfaceName: oldEndpoint.InterfaceName,
		InterfaceUUID: oldEndpoint.InterfaceUUID,
		MacAddrStr:    oldEndpoint.MacAddrStr,
		PortNo:        oldEndpoint.PortNo,
		BridgeName:    oldEndpoint.BridgeName,
		VlanID:        uint16(newTag),
		Trunk:         "",
	}

	return newEndpoint, oldEndpoint
}

func (monitor *OVSDBMonitor) filterPortVlanTrunkUpdate(rowupdate ovsdb.RowUpdate, ifaceUUID string) (*datapath.Endpoint, *datapath.Endpoint) {
	var newEndpoint, oldEndpoint *datapath.Endpoint
	var oldTrunk, newTrunk []float64

	if _, ok := monitor.endpointMap[ifaceUUID]; !ok {
		return nil, nil
	}
	if rowupdate.New.Fields["trunks"] == nil || rowupdate.Old.Fields["trunks"] == nil {
		return nil, nil
	}

	newTrunk = listVlanTrunks(rowupdate.New.Fields["trunks"])
	oldTrunk = listVlanTrunks(rowupdate.Old.Fields["trunks"])

	if reflect.DeepEqual(newTrunk, oldTrunk) {
		return nil, nil
	}

	oldEndpoint = monitor.endpointMap[ifaceUUID]
	newEndpoint = &datapath.Endpoint{
		InterfaceName: oldEndpoint.InterfaceName,
		InterfaceUUID: oldEndpoint.InterfaceUUID,
		MacAddrStr:    oldEndpoint.MacAddrStr,
		PortNo:        oldEndpoint.PortNo,
		BridgeName:    oldEndpoint.BridgeName,
		Trunk:         strings.Trim(strings.Join(strings.Split(fmt.Sprintf("%v", newTrunk), " "), ","), "[]"),
	}

	return newEndpoint, oldEndpoint
}

func (monitor *OVSDBMonitor) processOvsBridgeAdd(row ovsdb.RowUpdate) {
	bridgeName := row.New.Fields["name"].(string)
	ports := listUUID(row.New.Fields["ports"])
	portUUIDs := sets.NewString()
	for _, port := range ports {
		portUUIDs.Insert(port.GoUuid)
	}
	monitor.bridgeMap[bridgeName] = portUUIDs
}

func (monitor *OVSDBMonitor) processOvsBridgeDelete(row ovsdb.RowUpdate) {
	bridgeName := row.Old.Fields["name"].(string)
	delete(monitor.bridgeMap, bridgeName)
}

func (monitor *OVSDBMonitor) processOvsBridgeUpdate(row ovsdb.RowUpdate) {
	bridgeName := row.New.Fields["name"].(string)
	oldPorts := listUUID(row.Old.Fields["ports"])
	newPorts := listUUID(row.New.Fields["ports"])
	oldPortUUIDs := sets.NewString()
	newPortUUIDs := sets.NewString()
	for _, port := range oldPorts {
		oldPortUUIDs.Insert(port.GoUuid)
	}
	for _, port := range newPorts {
		newPortUUIDs.Insert(port.GoUuid)
	}
	if oldPortUUIDs.Equal(newPortUUIDs) {
		return
	}

	// added ports
	addedPorts := newPortUUIDs.Difference(oldPortUUIDs)
	for _, portUUID := range addedPorts.List() {
		monitor.bridgeMap[bridgeName].Insert(portUUID)
	}
	// deleted ports
	deletedPorts := oldPortUUIDs.Difference(newPortUUIDs)
	for _, portUUID := range deletedPorts.List() {
		monitor.bridgeMap[bridgeName].Delete(portUUID)
	}
}

func (monitor *OVSDBMonitor) processOvsPortAdd(uuid string, rowupdate ovsdb.RowUpdate) {
	newIfaces := listUUID(rowupdate.New.Fields["interfaces"])
	if len(newIfaces) != 1 {
		// bond port
		return
	}

	newIfaceUUID := newIfaces[0].GoUuid
	if _, ok := monitor.endpointMap[newIfaceUUID]; !ok {
		monitor.endpointMap[newIfaceUUID] = &datapath.Endpoint{}
	}

	var newTrunk []float64
	var newTag float64
	if rowupdate.New.Fields["trunks"] != nil {
		newTrunk = listVlanTrunks(rowupdate.New.Fields["trunks"])
	}
	if rowupdate.New.Fields["tag"] != nil {
		newID, ok := rowupdate.New.Fields["tag"].(float64)
		if ok {
			newTag = newID
		}
	}
	if len(newTrunk) != 0 {
		monitor.endpointMap[newIfaceUUID].Trunk = strings.Trim(strings.Join(strings.Split(fmt.Sprintf("%v", newTrunk), " "), ","), "[]")
	} else {
		monitor.endpointMap[newIfaceUUID].VlanID = uint16(newTag)
	}
	monitor.endpointMap[newIfaceUUID].InterfaceUUID = newIfaceUUID
	monitor.endpointMap[newIfaceUUID].BridgeName = monitor.getPortBridgeName(uuid)

	if monitor.isEndpointReady(monitor.endpointMap[newIfaceUUID]) {
		monitor.ovsdbEventHandler.AddLocalEndpoint(monitor.endpointMap[newIfaceUUID])
	}
}

func (monitor *OVSDBMonitor) processOvsInterfaceAdd(uuid string, rowupdate ovsdb.RowUpdate) {
	var macStr, interfaceName string
	interfaceName = rowupdate.New.Fields["name"].(string)

	if _, ok := monitor.endpointMap[uuid]; !ok {
		monitor.endpointMap[uuid] = &datapath.Endpoint{}
	}
	monitor.endpointMap[uuid].InterfaceName = interfaceName
	monitor.endpointMap[uuid].InterfaceUUID = uuid

	ofPort, ok := rowupdate.New.Fields["ofport"].(float64)
	if ok && ofPort > 0 {
		monitor.endpointMap[uuid].PortNo = uint32(ofPort)
	}

	macStr, err := getMacStrFromInterface(rowupdate.New)
	if err != nil {
		klog.Errorf("Failed to get interface %+v mac, err: %s", rowupdate, err)
	}
	monitor.endpointMap[uuid].MacAddrStr = macStr

	if newExternalIds, ok := rowupdate.New.Fields["external_ids"].(ovsdb.OvsMap); ok {
		ip := getIPv4Addr(newExternalIds.GoMap)
		monitor.endpointMap[uuid].IPAddr = ip
	}

	// if endpoint info is ready, trigger endpoint add callback
	if monitor.isEndpointReady(monitor.endpointMap[uuid]) {
		monitor.ovsdbEventHandler.AddLocalEndpoint(monitor.endpointMap[uuid])
	}
}

func (monitor *OVSDBMonitor) processOvsPortUpdate(uuid string, rowupdate ovsdb.RowUpdate) {
	var newEndpoint, oldEndpoint *datapath.Endpoint
	var newIfaceUUID, oldIfaceUUID string

	oldIfaces := listUUID(rowupdate.Old.Fields["interfaces"])
	newIfaces := listUUID(rowupdate.New.Fields["interfaces"])
	if len(newIfaces) > 1 || len(oldIfaces) > 1 {
		// bond port
		return
	}

	newIfaceUUID = newIfaces[0].GoUuid
	if len(oldIfaces) == 0 {
		oldIfaceUUID = newIfaceUUID
	} else {
		oldIfaceUUID = oldIfaces[0].GoUuid
	}

	if oldIfaceUUID != newIfaceUUID {
		// ovsport interfaces field update
		if _, ok := monitor.endpointMap[oldIfaceUUID]; !ok {
			monitor.endpointMap[oldIfaceUUID] = &datapath.Endpoint{}
			oldEndpoint = &datapath.Endpoint{}
		} else {
			oldEndpoint = monitor.endpointMap[oldIfaceUUID]
		}

		if _, ok := monitor.endpointMap[newIfaceUUID]; !ok {
			monitor.endpointMap[newIfaceUUID] = &datapath.Endpoint{}
			newEndpoint = &datapath.Endpoint{}
		} else {
			newEndpoint = monitor.endpointMap[newIfaceUUID]
		}

		// Is this case exsit
		if monitor.isEndpointReady(oldEndpoint) && monitor.isEndpointReady(newEndpoint) {
			monitor.ovsdbEventHandler.UpdateLocalEndpoint(newEndpoint, oldEndpoint)
		}
		if monitor.isEndpointReady(newEndpoint) && !monitor.isEndpointReady(oldEndpoint) {
			monitor.ovsdbEventHandler.AddLocalEndpoint(newEndpoint)
		}
		delete(monitor.endpointMap, oldIfaceUUID)
		monitor.endpointMap[newIfaceUUID] = newEndpoint
	}

	// ovsport vlan status update
	monitor.processVlanUpdate(rowupdate, newIfaceUUID)
}

func (monitor *OVSDBMonitor) processVlanUpdate(rowupdate ovsdb.RowUpdate, ifaceUUID string) {
	newEndpoint, oldEndpoint := monitor.filterPortVlanModeUpdate(rowupdate, ifaceUUID)
	if newEndpoint != nil && oldEndpoint != nil {
		klog.Infof("port vlan mode update %v : %v", oldEndpoint, newEndpoint)
		monitor.updateEndpoint(newEndpoint, oldEndpoint, ifaceUUID)
		return
	}

	newEndpoint, oldEndpoint = monitor.filterPortVlanTagUpdate(rowupdate, ifaceUUID)
	if newEndpoint != nil && oldEndpoint != nil {
		klog.Infof("port vlan tag update %v : %v", oldEndpoint, newEndpoint)
		monitor.updateEndpoint(newEndpoint, oldEndpoint, ifaceUUID)
		return
	}

	newEndpoint, oldEndpoint = monitor.filterPortVlanTrunkUpdate(rowupdate, ifaceUUID)
	if newEndpoint != nil && oldEndpoint != nil {
		klog.Infof("port Trunk update %v : %v", oldEndpoint, newEndpoint)
		monitor.updateEndpoint(newEndpoint, oldEndpoint, ifaceUUID)
	}
}

func (monitor *OVSDBMonitor) processOvsInterfaceUpdate(uuid string, rowupdate ovsdb.RowUpdate) {
	var ifaceName string
	var ok bool
	var newOfPort uint32

	ifaceName = rowupdate.New.Fields["name"].(string)

	ofPort, ok := rowupdate.New.Fields["ofport"].(float64)
	if ok && ofPort > 0 {
		newOfPort = uint32(ofPort)
	}

	newMacStr, err := getMacStrFromInterface(rowupdate.New)
	if err != nil {
		klog.Errorf("Failed to get interface %+v mac, err: %s", rowupdate, err)
	}

	var newIP net.IP
	if newExternalIds, ok := rowupdate.New.Fields["external_ids"].(ovsdb.OvsMap); ok {
		newIP = getIPv4Addr(newExternalIds.GoMap)
	}

	var newEndpoint, oldEndpoint *datapath.Endpoint
	oldEndpoint, ok = monitor.endpointMap[uuid]
	if !ok {
		monitor.endpointMap[uuid] = &datapath.Endpoint{
			InterfaceName: ifaceName,
			InterfaceUUID: uuid,
			MacAddrStr:    newMacStr,
			IPAddr:        utils.IPCopy(newIP),
			PortNo:        newOfPort,
		}
		return
	}

	newEndpoint = &datapath.Endpoint{
		InterfaceName: oldEndpoint.InterfaceName,
		InterfaceUUID: oldEndpoint.InterfaceUUID,
		BridgeName:    oldEndpoint.BridgeName,
		MacAddrStr:    oldEndpoint.MacAddrStr,
		IPAddr:        utils.IPCopy(oldEndpoint.IPAddr),
		PortNo:        oldEndpoint.PortNo,
		VlanID:        oldEndpoint.VlanID,
		Trunk:         oldEndpoint.Trunk,
	}

	if oldEndpoint.MacAddrStr != newMacStr {
		newEndpoint.MacAddrStr = newMacStr
	}

	newEndpoint.IPAddr = utils.IPCopy(newIP)

	if oldEndpoint.PortNo != newOfPort {
		newEndpoint.PortNo = newOfPort
	}

	monitor.updateEndpoint(newEndpoint, oldEndpoint, uuid)
}

func (monitor *OVSDBMonitor) processOvsPortDelete(uuid string, rowupdate ovsdb.RowUpdate) {
	oldIfaces := listUUID(rowupdate.Old.Fields["interfaces"])
	if len(oldIfaces) != 1 {
		// bond port
		return
	}

	oldIfaceUUID := oldIfaces[0].GoUuid
	oldEndpoint, ok := monitor.endpointMap[oldIfaceUUID]
	if !ok {
		return
	}

	if monitor.isEndpointReady(oldEndpoint) {
		monitor.ovsdbEventHandler.DeleteLocalEndpoint(monitor.endpointMap[oldIfaceUUID])
	}
	delete(monitor.endpointMap, uuid)
}

func (monitor *OVSDBMonitor) processOvsInterfaceDelete(uuid string, rowupdate ovsdb.RowUpdate) {
	// var macStr string

	oldEndpoint, ok := monitor.endpointMap[uuid]
	if !ok {
		return
	}

	if monitor.isEndpointReady(oldEndpoint) {
		monitor.ovsdbEventHandler.DeleteLocalEndpoint(monitor.endpointMap[uuid])
	}
	delete(monitor.endpointMap, uuid)
}

func (monitor *OVSDBMonitor) getPortBridgeName(portUUID string) string {
	var bridgeName string
	for brName, portUUIDs := range monitor.bridgeMap {
		if portUUIDs.Has(portUUID) {
			bridgeName = brName
			break
		}
	}

	return bridgeName
}

func (monitor *OVSDBMonitor) updateEndpoint(newEndpoint, oldEndpoint *datapath.Endpoint, ifaceUUID string) {
	if monitor.isEndpointReady(oldEndpoint) && monitor.isEndpointReady(newEndpoint) {
		monitor.ovsdbEventHandler.UpdateLocalEndpoint(newEndpoint, oldEndpoint)
		delete(monitor.endpointMap, ifaceUUID)
		monitor.endpointMap[ifaceUUID] = newEndpoint
	}
	if monitor.isEndpointReady(newEndpoint) && !monitor.isEndpointReady(oldEndpoint) {
		monitor.ovsdbEventHandler.AddLocalEndpoint(newEndpoint)
		delete(monitor.endpointMap, ifaceUUID)
		monitor.endpointMap[ifaceUUID] = newEndpoint
	}
	if !monitor.isEndpointReady(newEndpoint) && monitor.isEndpointReady(oldEndpoint) {
		monitor.ovsdbEventHandler.DeleteLocalEndpoint(oldEndpoint)
		delete(monitor.endpointMap, ifaceUUID)
	}
}

func (monitor *OVSDBMonitor) isEndpointReady(endpoint *datapath.Endpoint) bool {
	return endpoint.BridgeName != "" && endpoint.InterfaceUUID != "" &&
		endpoint.InterfaceName != "" && endpoint.MacAddrStr != "" && endpoint.PortNo != 0
}

func (monitor *OVSDBMonitor) handleOvsUpdates(updates ovsdb.TableUpdates) {
	monitor.cacheLock.Lock()
	for table, tableUpdate := range updates.Updates {
		if _, ok := monitor.ovsdbCache[table]; !ok {
			monitor.ovsdbCache[table] = make(map[string]ovsdb.Row)
		}
		for uuid, row := range tableUpdate.Rows {
			empty := ovsdb.Row{}
			if !reflect.DeepEqual(row.New, empty) {
				monitor.ovsdbCache[table][uuid] = row.New
			} else {
				delete(monitor.ovsdbCache[table], uuid)
			}
		}
	}
	monitor.cacheLock.Unlock()

	monitor.syncQueue.Add("ovsdb-event")
	monitor.ovsdbUpdatesChan <- updates
}

func (monitor *OVSDBMonitor) handleOvsEvents(stopChan <-chan struct{}) {
	for {
		select {
		case updates := <-monitor.ovsdbUpdatesChan:
			monitor.ovsdbEventFilter(updates)
		case <-stopChan:
			return
		}
	}
}

func (monitor *OVSDBMonitor) ovsdbEventFilter(updates ovsdb.TableUpdates) {
	bridgeUpdate, ok := updates.Updates[OvsDBBridgeTable]
	empty := ovsdb.Row{}
	if ok {
		for _, row := range bridgeUpdate.Rows {
			switch {
			case !reflect.DeepEqual(row.New, empty) && reflect.DeepEqual(row.Old, empty):
				monitor.processOvsBridgeAdd(row)
			case !reflect.DeepEqual(row.New, empty) && !reflect.DeepEqual(row.Old, empty):
				monitor.processOvsBridgeUpdate(row)
			case reflect.DeepEqual(row.New, empty) && !reflect.DeepEqual(row.Old, empty):
				monitor.processOvsBridgeDelete(row)
			}
		}
	}
	for table, tableUpdate := range updates.Updates {
		for uuid, row := range tableUpdate.Rows {
			switch {
			case !reflect.DeepEqual(row.New, empty) && reflect.DeepEqual(row.Old, empty):
				if table == OvsDBInterfaceTable {
					monitor.processOvsInterfaceAdd(uuid, row)
				}
				if table == OvsDBPortTable {
					monitor.processOvsPortAdd(uuid, row)
				}
			case !reflect.DeepEqual(row.New, empty) && !reflect.DeepEqual(row.Old, empty):
				if table == OvsDBInterfaceTable {
					monitor.processOvsInterfaceUpdate(uuid, row)
				}
				if table == OvsDBPortTable {
					monitor.processOvsPortUpdate(uuid, row)
				}
			case reflect.DeepEqual(row.New, empty) && !reflect.DeepEqual(row.Old, empty):
				if table == OvsDBInterfaceTable {
					monitor.processOvsInterfaceDelete(uuid, row)
				}
				if table == OvsDBPortTable {
					monitor.processOvsPortDelete(uuid, row)
				}
			}
		}
	}
}
