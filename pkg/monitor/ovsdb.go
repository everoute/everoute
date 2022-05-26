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
	"sync"
	"time"

	ovsdb "github.com/contiv/libovsdb"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog"

	"github.com/everoute/everoute/pkg/agent/datapath"
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

	ovsdbEventHandler                  ovsdbEventHandler
	localEndpointHardwareAddrCacheLock sync.RWMutex
	localEndpointHardwareAddrCache     map[string]uint32

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
		ovsClient:                          ovsClient,
		cacheLock:                          sync.RWMutex{},
		ovsdbCache:                         make(map[string]map[string]ovsdb.Row),
		localEndpointHardwareAddrCacheLock: sync.RWMutex{},
		localEndpointHardwareAddrCache:     make(map[string]uint32),
		syncQueue:                          workqueue.NewRateLimitingQueue(workqueue.DefaultItemBasedRateLimiter()),
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

	initial, err := monitor.ovsClient.Monitor("Open_vSwitch", nil, requests)
	if err != nil {
		return fmt.Errorf("monitor ovsdb %s: %s", "Open_vSwitch", err)
	}
	monitor.handleOvsUpdates(*initial)

	return nil
}

// Endpoint implement in everoute datapath module pr
func (monitor *OVSDBMonitor) interfaceToEndpoint(ofport uint32, interfaceName, macAddrStr string) *datapath.Endpoint {
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
		InterfaceName: interfaceName,
		MacAddrStr:    macAddrStr,
		PortNo:        ofport,
		BridgeName:    bridgeName,
		VlanID:        vlanID,
	}
}

func (monitor *OVSDBMonitor) filterEndpoint(rowupdate ovsdb.RowUpdate) (*datapath.Endpoint, *datapath.Endpoint) {
	newExternalIds := rowupdate.New.Fields["external_ids"].(ovsdb.OvsMap).GoMap
	_, ok := newExternalIds[LocalEndpointIdentity]
	if !ok {
		if rowupdate.New.Fields["mac_in_use"] == "" {
			return nil, nil
		}
	}
	return monitor.filterLocalEndpoint(rowupdate)
}

func (monitor *OVSDBMonitor) filterLocalEndpoint(rowupdate ovsdb.RowUpdate) (*datapath.Endpoint, *datapath.Endpoint) {
	empty := ovsdb.Row{}
	if reflect.DeepEqual(rowupdate.Old, empty) {
		return monitor.filterEndpointAdded(rowupdate), nil
	}

	if rowupdate.Old.Fields["external_ids"] == nil {
		return monitor.filterEndpointAdded(rowupdate), nil
	}

	return monitor.filterEndpointUpdated(rowupdate)
}

func (monitor *OVSDBMonitor) filterEndpointUpdated(rowupdate ovsdb.RowUpdate) (*datapath.Endpoint, *datapath.Endpoint) {
	var macStr string
	newExternalIds := rowupdate.New.Fields["external_ids"].(ovsdb.OvsMap).GoMap
	_, ok := newExternalIds[LocalEndpointIdentity]
	if !ok {
		macStr, _ = rowupdate.New.Fields["mac_in_use"].(string)
	} else {
		macStr, _ = newExternalIds[LocalEndpointIdentity].(string)
	}
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
	macAddr, err := net.ParseMAC(macStr)
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
	monitor.localEndpointHardwareAddrCache[macStr] = uint32(newOfPort)

	if err := monitor.waitForPortPresent(rowupdate.New.Fields["name"].(string), 1*time.Second); err != nil {
		klog.Errorf("Failed to update local endpoint, wait ovs port of newEndpoint present timeout, error: %v", err)
		return nil, nil
	}

	newEndpoint := monitor.interfaceToEndpoint(uint32(newOfPort), rowupdate.New.Fields["name"].(string), macAddr.String())
	oldEndpoint := monitor.interfaceToEndpoint(uint32(oldOfPort), rowupdate.Old.Fields["name"].(string), macAddr.String())
	return newEndpoint, oldEndpoint
}

func (monitor *OVSDBMonitor) filterEndpointAdded(rowupdate ovsdb.RowUpdate) *datapath.Endpoint {
	var macStr string
	newExternalIds := rowupdate.New.Fields["external_ids"].(ovsdb.OvsMap).GoMap
	_, ok := newExternalIds[LocalEndpointIdentity]
	if !ok {
		macStr, _ = rowupdate.New.Fields["mac_in_use"].(string)
	} else {
		macStr, _ = newExternalIds[LocalEndpointIdentity].(string)
	}
	monitor.localEndpointHardwareAddrCacheLock.Lock()
	defer monitor.localEndpointHardwareAddrCacheLock.Unlock()

	if _, ok := monitor.localEndpointHardwareAddrCache[macStr]; ok {
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

	macAddr, err := net.ParseMAC(macStr)
	if err != nil {
		klog.Errorf("Parsing endpoint macAddr error: %v", macAddr)
		return nil
	}
	monitor.localEndpointHardwareAddrCache[macStr] = uint32(ofPort)

	if err := monitor.waitForPortPresent(rowupdate.New.Fields["name"].(string), 1*time.Second); err != nil {
		klog.Errorf("Failed to add local endpoint, wait ovs port present timeout, error: %v", err)
		return nil
	}

	return monitor.interfaceToEndpoint(ofport, rowupdate.New.Fields["name"].(string), macStr)
}

func (monitor *OVSDBMonitor) waitForPortPresent(interfaceName string, timeout time.Duration) error {
	return wait.PollImmediate(10*time.Millisecond, timeout, func() (do bool, err error) {
		if !monitor.isPortExists(interfaceName) {
			return false, nil
		}

		return true, nil
	})
}

func (monitor *OVSDBMonitor) isPortExists(interfaceName string) bool {
	monitor.cacheLock.RLock()
	defer monitor.cacheLock.RUnlock()
	for _, port := range monitor.ovsdbCache["Port"] {
		if port.Fields["name"].(string) == interfaceName {
			return true
		}
	}

	return false
}

func (monitor *OVSDBMonitor) filterEndpointDeleted(rowupdate ovsdb.RowUpdate) *datapath.Endpoint {
	var ofport uint32
	var macStr string
	oldExternalIds := rowupdate.Old.Fields["external_ids"].(ovsdb.OvsMap).GoMap
	_, ok := oldExternalIds[LocalEndpointIdentity]
	if !ok {
		macStr, _ = rowupdate.Old.Fields["mac_in_use"].(string)
	} else {
		macStr, _ = oldExternalIds[LocalEndpointIdentity].(string)
	}

	monitor.localEndpointHardwareAddrCacheLock.Lock()
	defer monitor.localEndpointHardwareAddrCacheLock.Unlock()

	if _, ok := monitor.localEndpointHardwareAddrCache[macStr]; !ok {
		return nil
	}

	ofPort, ok := rowupdate.Old.Fields["ofport"].(float64)
	if !ok {
		return nil
	}
	if ofPort <= 0 {
		ofport = monitor.localEndpointHardwareAddrCache[macStr]
	} else {
		ofport = uint32(ofPort)
	}

	delete(monitor.localEndpointHardwareAddrCache, macStr)

	return monitor.interfaceToEndpoint(ofport, rowupdate.Old.Fields["name"].(string), macStr)
}

func (monitor *OVSDBMonitor) filterPortVlanTagUpdate(rowupdate ovsdb.RowUpdate) (*datapath.Endpoint, *datapath.Endpoint) {
	monitor.cacheLock.Lock()
	ok, localEndpointIface := monitor.isLocalEndpointPort(rowupdate.New.Fields["name"].(string))
	if !ok {
		monitor.cacheLock.Unlock()
		return nil, nil
	}
	monitor.cacheLock.Unlock()

	var oldTag, newTag float64
	var ofport uint32
	if rowupdate.New.Fields["tag"] == nil {
		return nil, nil
	}
	if rowupdate.Old.Fields["tag"] == nil {
		return nil, nil
	}
	newTag, _ = rowupdate.New.Fields["tag"].(float64)
	oldTag, _ = rowupdate.Old.Fields["tag"].(float64)
	if newTag == oldTag {
		return nil, nil
	}

	portName := localEndpointIface.Fields["name"].(string)
	externalIDs := localEndpointIface.Fields["external_ids"].(ovsdb.OvsMap).GoMap
	ofPort, ok := localEndpointIface.Fields["ofport"].(float64)
	if !ok {
		return nil, nil
	}
	if ofPort <= 0 {
		monitor.localEndpointHardwareAddrCacheLock.Lock()
		ofport = monitor.localEndpointHardwareAddrCache[externalIDs[LocalEndpointIdentity].(string)]
		monitor.localEndpointHardwareAddrCacheLock.Unlock()
	} else {
		ofport = uint32(ofPort)
	}

	newEndpoint := monitor.interfaceToEndpoint(ofport, portName, externalIDs[LocalEndpointIdentity].(string))
	oldEndpoint := &datapath.Endpoint{
		InterfaceName: newEndpoint.InterfaceName,
		MacAddrStr:    newEndpoint.MacAddrStr,
		PortNo:        newEndpoint.PortNo,
		BridgeName:    newEndpoint.BridgeName,
		VlanID:        uint16(oldTag),
	}

	return newEndpoint, oldEndpoint
}

func (monitor *OVSDBMonitor) isLocalEndpointPort(portName string) (bool, ovsdb.Row) {
	for i, iface := range monitor.ovsdbCache["Interface"] {
		if iface.Fields["name"].(string) == portName {
			if _, ok := iface.Fields["external_ids"].(ovsdb.OvsMap).GoMap[LocalEndpointIdentity]; ok {
				return true, monitor.ovsdbCache["Interface"][i]
			}
		}
	}
	return false, ovsdb.Row{}
}

func (monitor *OVSDBMonitor) processPortUpdate(rowupdate ovsdb.RowUpdate) {
	newEndpoint, oldEndpoint := monitor.filterPortVlanTagUpdate(rowupdate)
	if newEndpoint != nil && oldEndpoint != nil {
		go monitor.ovsdbEventHandler.UpdateLocalEndpoint(newEndpoint, oldEndpoint)
	}
}

func (monitor *OVSDBMonitor) processEndpointUpdate(rowupdate ovsdb.RowUpdate) {
	newEndpoint, oldEndpoint := monitor.filterEndpoint(rowupdate)
	if newEndpoint != nil && oldEndpoint != nil {
		go monitor.ovsdbEventHandler.UpdateLocalEndpoint(newEndpoint, oldEndpoint)
	} else if newEndpoint != nil {
		go monitor.ovsdbEventHandler.AddLocalEndpoint(newEndpoint)
	}
}

func (monitor *OVSDBMonitor) processEndpointDel(rowupdate ovsdb.RowUpdate) {
	deletedEndpoints := monitor.filterEndpointDeleted(rowupdate)
	if deletedEndpoints != nil {
		go monitor.ovsdbEventHandler.DeleteLocalEndpoint(deletedEndpoints)
	}
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
				if table == "Interface" {
					go monitor.processEndpointUpdate(row)
				}
				if table == "Port" {
					go monitor.processPortUpdate(row)
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

	monitor.syncQueue.Add("ovsdb-event")
}
