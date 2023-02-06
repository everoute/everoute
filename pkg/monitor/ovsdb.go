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
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog"

	"github.com/everoute/everoute/pkg/agent/datapath"
)

const (
	OvsDBPortTable      = "Port"
	OvsDBInterfaceTable = "Interface"
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
	endpointMap map[string]*datapath.Endpoint

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
		ovsClient:   ovsClient,
		cacheLock:   sync.RWMutex{},
		endpointMap: make(map[string]*datapath.Endpoint),
		ovsdbCache:  make(map[string]map[string]ovsdb.Row),
		syncQueue:   workqueue.NewRateLimitingQueue(workqueue.DefaultItemBasedRateLimiter()),
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
		"Interface":    {Select: selectAll, Columns: []string{"name", "mac_in_use", "ofport", "type", "external_ids", "error"}},
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
		newTrunks, ok := rowupdate.New.Fields["trunks"].(ovsdb.OvsSet)
		if ok {
			trunkSet := newTrunks.GoSet
			for _, item := range trunkSet {
				newTrunk = append(newTrunk, item.(float64))
			}
		}
	}
	if rowupdate.Old.Fields["trunks"] != nil {
		oldTrunks, ok := rowupdate.Old.Fields["trunks"].(ovsdb.OvsSet)
		if ok {
			trunkSet := oldTrunks.GoSet
			for _, item := range trunkSet {
				oldTrunk = append(oldTrunk, item.(float64))
			}
		}
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

	newTrunks, ok := rowupdate.New.Fields["trunks"].(ovsdb.OvsSet)
	if ok {
		trunkSet := newTrunks.GoSet
		for _, item := range trunkSet {
			newTrunk = append(newTrunk, item.(float64))
		}
	}

	oldTrunks, ok := rowupdate.Old.Fields["trunks"].(ovsdb.OvsSet)
	if ok {
		trunkSet := oldTrunks.GoSet
		for _, item := range trunkSet {
			oldTrunk = append(oldTrunk, item.(float64))
		}
	}

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
		newTrunks, ok := rowupdate.New.Fields["trunks"].(ovsdb.OvsSet)
		if ok {
			trunkSet := newTrunks.GoSet
			for _, item := range trunkSet {
				newTrunk = append(newTrunk, item.(float64))
			}
		}
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

	newExternalIds := rowupdate.New.Fields["external_ids"].(ovsdb.OvsMap).GoMap
	_, ok := newExternalIds[LocalEndpointIdentity]
	if !ok {
		macStr, _ = rowupdate.New.Fields["mac_in_use"].(string)
	} else {
		macStr, _ = newExternalIds[LocalEndpointIdentity].(string)
	}

	ofPort, ok := rowupdate.New.Fields["ofport"].(float64)
	if ok && ofPort > 0 {
		monitor.endpointMap[uuid].PortNo = uint32(ofPort)
	}

	_, err := net.ParseMAC(macStr)
	if err != nil {
		macStr = ""
	}
	monitor.endpointMap[uuid].MacAddrStr = macStr

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
		monitor.ovsdbEventHandler.UpdateLocalEndpoint(newEndpoint, oldEndpoint)
		delete(monitor.endpointMap, ifaceUUID)
		monitor.endpointMap[ifaceUUID] = newEndpoint
		return
	}

	newEndpoint, oldEndpoint = monitor.filterPortVlanTagUpdate(rowupdate, ifaceUUID)
	if newEndpoint != nil && oldEndpoint != nil {
		klog.Infof("port vlan tag update %v : %v", oldEndpoint, newEndpoint)
		monitor.ovsdbEventHandler.UpdateLocalEndpoint(newEndpoint, oldEndpoint)
		delete(monitor.endpointMap, ifaceUUID)
		monitor.endpointMap[ifaceUUID] = newEndpoint
		return
	}

	newEndpoint, oldEndpoint = monitor.filterPortVlanTrunkUpdate(rowupdate, ifaceUUID)
	if newEndpoint != nil && oldEndpoint != nil {
		klog.Infof("port Trunk update %v : %v", oldEndpoint, newEndpoint)
		monitor.ovsdbEventHandler.UpdateLocalEndpoint(newEndpoint, oldEndpoint)
		delete(monitor.endpointMap, ifaceUUID)
		monitor.endpointMap[ifaceUUID] = newEndpoint
	}
}

func (monitor *OVSDBMonitor) processOvsInterfaceUpdate(uuid string, rowupdate ovsdb.RowUpdate) {
	var newMacStr, ifaceName string
	var ok bool
	var newOfPort uint32

	ifaceName = rowupdate.New.Fields["name"].(string)
	newExternalIds := rowupdate.New.Fields["external_ids"].(ovsdb.OvsMap).GoMap
	_, ok = newExternalIds[LocalEndpointIdentity]
	if !ok {
		newMacStr, _ = rowupdate.New.Fields["mac_in_use"].(string)
	} else {
		newMacStr, _ = newExternalIds[LocalEndpointIdentity].(string)
	}

	ofPort, ok := rowupdate.New.Fields["ofport"].(float64)
	if ok && ofPort > 0 {
		newOfPort = uint32(ofPort)
	}

	_, err := net.ParseMAC(newMacStr)
	if err != nil {
		// invalid mac addr, set it to null string, ensure not update endpoint mac
		newMacStr = ""
	}

	var newEndpoint, oldEndpoint *datapath.Endpoint
	oldEndpoint, ok = monitor.endpointMap[uuid]
	if !ok {
		monitor.endpointMap[uuid] = &datapath.Endpoint{
			InterfaceName: ifaceName,
			InterfaceUUID: uuid,
			MacAddrStr:    newMacStr,
			PortNo:        newOfPort,
		}
		return
	}
	newEndpoint = &datapath.Endpoint{
		InterfaceName: oldEndpoint.InterfaceName,
		InterfaceUUID: oldEndpoint.InterfaceUUID,
		BridgeName:    oldEndpoint.BridgeName,
		MacAddrStr:    oldEndpoint.MacAddrStr,
		PortNo:        oldEndpoint.PortNo,
		VlanID:        oldEndpoint.VlanID,
		Trunk:         oldEndpoint.Trunk,
	}

	if oldEndpoint.MacAddrStr != newMacStr {
		newEndpoint.MacAddrStr = newMacStr
	}
	if oldEndpoint.PortNo != newOfPort {
		newEndpoint.PortNo = newOfPort
	}

	if monitor.isEndpointReady(oldEndpoint) && monitor.isEndpointReady(newEndpoint) {
		monitor.ovsdbEventHandler.UpdateLocalEndpoint(newEndpoint, oldEndpoint)
		delete(monitor.endpointMap, uuid)
		monitor.endpointMap[uuid] = newEndpoint
	}
	if monitor.isEndpointReady(newEndpoint) && !monitor.isEndpointReady(oldEndpoint) {
		monitor.ovsdbEventHandler.AddLocalEndpoint(newEndpoint)
		monitor.endpointMap[uuid] = newEndpoint
	}
	if !monitor.isEndpointReady(newEndpoint) && monitor.isEndpointReady(oldEndpoint) {
		monitor.ovsdbEventHandler.DeleteLocalEndpoint(oldEndpoint)
		delete(monitor.endpointMap, uuid)
	}
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
	for _, bridge := range monitor.ovsdbCache["Bridge"] {
		portUUIDs := listUUID(bridge.Fields["ports"])
		for _, uuid := range portUUIDs {
			if uuid.GoUuid == portUUID {
				bridgeName = bridge.Fields["name"].(string)
				return bridgeName
			}
		}
	}

	return bridgeName
}

func (monitor *OVSDBMonitor) isEndpointReady(endpoint *datapath.Endpoint) bool {
	return endpoint.BridgeName != "" && endpoint.InterfaceUUID != "" &&
		endpoint.InterfaceName != "" && endpoint.MacAddrStr != "" && endpoint.PortNo != 0
}

func (monitor *OVSDBMonitor) handleOvsUpdates(updates ovsdb.TableUpdates) {
	monitor.cacheLock.Lock()
	defer monitor.cacheLock.Unlock()

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

	for table, tableUpdate := range updates.Updates {
		for uuid, row := range tableUpdate.Rows {
			empty := ovsdb.Row{}
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

	monitor.syncQueue.Add("ovsdb-event")
}
