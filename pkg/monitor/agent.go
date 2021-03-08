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
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8stypes "k8s.io/apimachinery/pkg/types"
	typeuuid "k8s.io/apimachinery/pkg/util/uuid"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog"
	"sigs.k8s.io/controller-runtime/pkg/client"

	agentv1alpha1 "github.com/smartxworks/lynx/pkg/apis/agent/v1alpha1"
	"github.com/smartxworks/lynx/pkg/types"
)

const (
	AgentNameConfigPath = "/var/lib/lynx/agent/name"
)

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
	ofPortIpAddressMonitorChan chan map[uint32][]net.IP

	// syncQueue used to notify agentMonitor synchronize AgentInfo
	syncQueue workqueue.RateLimitingInterface
}

// NewAgentMonitor return a new agentMonitor with kubernetes client and ipMonitor.
func NewAgentMonitor(client client.Client, ofPortIpAddressMonitorChan chan map[uint32][]net.IP) (*agentMonitor, error) {
	monitor := &agentMonitor{
		k8sClient:    client,
		cacheLock:    sync.RWMutex{},
		ovsdbCache:   make(map[string]map[string]ovsdb.Row),
		ofportsCache: make(map[int32][]types.IPAddress),
		syncQueue:    workqueue.NewRateLimitingQueue(workqueue.DefaultItemBasedRateLimiter()),
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

	go wait.Until(monitor.syncAgentInfoWorker, 0, stopChan)
	<-stopChan

	return nil
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
		"Port":         {Select: selectAll, Columns: []string{"name", "interfaces", "external_ids", "bond_mode", "vlan_mode", "tag", "trunks"}},
		"Interface":    {Select: selectAll, Columns: []string{"name", "mac_in_use", "ofport", "type"}},
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

	ovsVersion, err := monitor.OVSVersion()
	if err == nil {
		agentInfo.OVSInfo.Version = ovsVersion
	}

	hostname, err := os.Hostname()
	if err == nil {
		agentInfo.Hostname = hostname
	}

	for uuid := range monitor.ovsdbCache["Bridge"] {
		bridge, err := monitor.fetchBridge(ovsdb.UUID{GoUuid: uuid})
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

func (monitor *agentMonitor) HandleOfportUpdates(ofports map[int32][]types.IPAddress) {
	monitor.cacheLock.Lock()
	defer monitor.cacheLock.Unlock()

	for ofport, ips := range ofports {
		monitor.ofportsCache[ofport] = ips
	}

	monitor.syncQueue.Add(monitor.Name())
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
				monitor.ovsdbCache[table][uuid] = row.New
			} else {
				delete(monitor.ovsdbCache[table], uuid)
			}
		}
	}

	monitor.syncQueue.Add(monitor.Name())
}

func (monitor *agentMonitor) Name() string {
	return monitor.agentName
}

func (monitor *agentMonitor) OVSVersion() (string, error) {
	monitor.cacheLock.RLock()
	defer monitor.cacheLock.RUnlock()

	tableOvs := monitor.ovsdbCache["Open_vSwitch"]
	if len(tableOvs) == 0 {
		return "", fmt.Errorf("couldn't find table %s, agentMonitor may haven't start", "Open_vSwitch")
	}

	for _, raw := range tableOvs {
		return raw.Fields["ovs_version"].(string), nil
	}

	return "", nil
}

func (monitor *agentMonitor) fetchPort(uuid ovsdb.UUID) (*agentv1alpha1.OVSPort, error) {
	monitor.cacheLock.RLock()
	defer monitor.cacheLock.RUnlock()

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
		iface, err := monitor.fetchInterface(uuid)
		if err != nil {
			return nil, err
		}
		port.Interfaces = append(port.Interfaces, *iface)
	}

	return port, nil
}

func (monitor *agentMonitor) fetchInterface(uuid ovsdb.UUID) (*agentv1alpha1.OVSInterface, error) {
	monitor.cacheLock.RLock()
	defer monitor.cacheLock.RUnlock()

	ovsIface, ok := monitor.ovsdbCache["Interface"][uuid.GoUuid]
	if !ok {
		return nil, fmt.Errorf("ovs interface %s not found in cache", uuid)
	}

	iface := agentv1alpha1.OVSInterface{
		Name: ovsIface.Fields["name"].(string),
		Type: ovsIface.Fields["type"].(string),
	}

	// field type is ovsdb.OvsSet instead of string when field empty
	iface.Mac, _ = ovsIface.Fields["mac_in_use"].(string)

	ofport, ok := ovsIface.Fields["ofport"].(float64)
	if ok && ofport >= 0 {
		iface.Ofport = int32(ofport)
		iface.IPs = monitor.ofportsCache[iface.Ofport]
	}

	return &iface, nil
}

func (monitor *agentMonitor) fetchBridge(uuid ovsdb.UUID) (*agentv1alpha1.OVSBridge, error) {
	monitor.cacheLock.RLock()
	defer monitor.cacheLock.RUnlock()

	ovsBri, ok := monitor.ovsdbCache["Bridge"][uuid.GoUuid]
	if !ok {
		return nil, fmt.Errorf("ovs bridge %s not found in cache", uuid)
	}

	bridge := &agentv1alpha1.OVSBridge{
		Name: ovsBri.Fields["name"].(string),
	}

	for _, uuid := range listUUID(ovsBri.Fields["ports"]) {
		port, err := monitor.fetchPort(uuid)
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
