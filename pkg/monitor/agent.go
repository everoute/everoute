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
	"net"
	"os"
	"sync"
	"time"

	ovsdb "github.com/contiv/libovsdb"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8stypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog"
	"sigs.k8s.io/controller-runtime/pkg/client"

	agentv1alpha1 "github.com/everoute/everoute/pkg/apis/agent/v1alpha1"
	"github.com/everoute/everoute/pkg/types"
	"github.com/everoute/everoute/pkg/utils"
)

const (
	LocalEndpointIdentity = "attached-mac"
	AgentInfoSyncInterval = 5
)

// AgentMonitor monitor agent state, update agentinfo to apiserver.
type AgentMonitor struct {
	// k8sClient used to create/read/update agentinfo
	k8sClient client.Client
	// ovsdbMonitor used to access ovsdb cache
	ovsdbMonitor *OVSDBMonitor

	// agentName is the name and uuid of this agent
	agentName                  string
	ipCacheLock                sync.RWMutex
	ipCache                    map[string]map[types.IPAddress]metav1.Time
	ofPortIPAddressMonitorChan chan map[string]net.IP

	// syncQueue used to notify agentMonitor synchronize AgentInfo
	syncQueue workqueue.RateLimitingInterface
}

// NewAgentMonitor return a new agentMonitor with kubernetes client and ipMonitor.
func NewAgentMonitor(client client.Client, ovsdbMonitor *OVSDBMonitor, ofPortIPAddressMonitorChan chan map[string]net.IP) *AgentMonitor {
	return &AgentMonitor{
		k8sClient:                  client,
		agentName:                  utils.CurrentAgentName(),
		ipCacheLock:                sync.RWMutex{},
		ipCache:                    make(map[string]map[types.IPAddress]metav1.Time),
		ofPortIPAddressMonitorChan: ofPortIPAddressMonitorChan,
		ovsdbMonitor:               ovsdbMonitor,
		syncQueue:                  ovsdbMonitor.GetSyncQueue(),
	}
}

func (monitor *AgentMonitor) Run(stopChan <-chan struct{}) {
	defer monitor.syncQueue.ShutDown()

	klog.Infof("start agent %s monitor", monitor.Name())
	defer klog.Infof("shutting down agent %s monitor", monitor.Name())

	go monitor.handleOfPortIPAddressUpdate(monitor.ofPortIPAddressMonitorChan, stopChan)
	go wait.Until(monitor.syncAgentInfoWorker, 0, stopChan)
	go monitor.periodicallySyncAgentInfo(AgentInfoSyncInterval, stopChan)
	<-stopChan
}

func (monitor *AgentMonitor) handleOfPortIPAddressUpdate(ofPortIPAddressMonitorChan <-chan map[string]net.IP, stopChan <-chan struct{}) {
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

func (monitor *AgentMonitor) periodicallySyncAgentInfo(cycle int, stopChan <-chan struct{}) {
	ticker := time.NewTicker(time.Duration(cycle) * time.Second)
	for {
		select {
		case <-ticker.C:
			monitor.syncQueue.Add(monitor.Name())
		case <-stopChan:
			return
		}
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

	monitor.ipCacheLock.Lock()
	defer monitor.ipCacheLock.Unlock()
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

	monitor.mergeAgentInfo(agentInfo, cpAgentInfo)
	agentInfo.ObjectMeta = cpAgentInfo.ObjectMeta
	err = monitor.k8sClient.Update(ctx, agentInfo)
	if err != nil {
		return err
	}
	monitor.ipCache = make(map[string]map[types.IPAddress]metav1.Time)

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
					if localAgentInfo.OVSInfo.Bridges[i].Ports[j].Interfaces[k].IPMap == nil {
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
	agentInfo := &agentv1alpha1.AgentInfo{
		ObjectMeta: metav1.ObjectMeta{
			Name:      monitor.Name(),
			Namespace: metav1.NamespaceNone,
		},
	}

	hostname, err := os.Hostname()
	if err == nil {
		agentInfo.Hostname = hostname
	}

	err = monitor.ovsdbMonitor.LockedAccessCache(func(ovsdbCache OVSDBCache) error {
		ovsVersion, err := monitor.fetchOvsVersionLocked(ovsdbCache)
		if err == nil {
			agentInfo.OVSInfo.Version = ovsVersion
		}

		for uuid := range ovsdbCache["Bridge"] {
			bridge, err := monitor.fetchBridgeLocked(ovsdbCache, ovsdb.UUID{GoUuid: uuid})
			if err != nil {
				return fmt.Errorf("unable fetch bridge %s: %s", uuid, err)
			}
			agentInfo.OVSInfo.Bridges = append(agentInfo.OVSInfo.Bridges, *bridge)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	agentHealthCondition := agentv1alpha1.AgentCondition{
		Type:              agentv1alpha1.AgentHealthy,
		Status:            corev1.ConditionTrue,
		LastHeartbeatTime: metav1.NewTime(time.Now()),
	}
	agentInfo.Conditions = []agentv1alpha1.AgentCondition{agentHealthCondition}

	return agentInfo, nil
}

func (monitor *AgentMonitor) Name() string {
	return monitor.agentName
}

func (monitor *AgentMonitor) fetchOvsVersionLocked(ovsdbCache OVSDBCache) (string, error) {
	tableOvs := ovsdbCache["Open_vSwitch"]
	if len(tableOvs) == 0 {
		return "", fmt.Errorf("couldn't find table %s, agentMonitor may haven't start", "Open_vSwitch")
	}

	for _, raw := range tableOvs {
		return raw.Fields["ovs_version"].(string), nil
	}

	return "", nil
}

func (monitor *AgentMonitor) fetchPortLocked(ovsdbCache OVSDBCache, uuid ovsdb.UUID, bridgeName string) (*agentv1alpha1.OVSPort, error) {
	ovsPort, ok := ovsdbCache["Port"][uuid.GoUuid]
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
		iface := monitor.fetchInterfaceLocked(ovsdbCache, uuid, bridgeName)
		if iface != nil {
			port.Interfaces = append(port.Interfaces, *iface)
		}
	}

	return port, nil
}

func (monitor *AgentMonitor) fetchInterfaceLocked(ovsdbCache OVSDBCache, uuid ovsdb.UUID, bridgeName string) *agentv1alpha1.OVSInterface {
	ovsIface, ok := ovsdbCache["Interface"][uuid.GoUuid]
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

	if mac, ok := iface.ExternalIDs[LocalEndpointIdentity]; ok {
		// if attached-mac found, use attached-mac as endpoint mac
		iface.Mac = mac
	} else {
		// field type is ovsdb.OvsSet instead of string when field empty
		iface.Mac, _ = ovsIface.Fields["mac_in_use"].(string)
	}

	ofport, ok := ovsIface.Fields["ofport"].(float64)
	if ok && ofport >= 0 {
		iface.Ofport = int32(ofport)
		iface.IPMap = monitor.ipCache[fmt.Sprintf("%s-%d", bridgeName, iface.Ofport)]
	}

	return &iface
}

func (monitor *AgentMonitor) fetchBridgeLocked(ovsdbCache OVSDBCache, uuid ovsdb.UUID) (*agentv1alpha1.OVSBridge, error) {
	ovsBri, ok := ovsdbCache["Bridge"][uuid.GoUuid]
	if !ok {
		return nil, fmt.Errorf("ovs bridge %s not found in cache", uuid)
	}

	bridge := &agentv1alpha1.OVSBridge{
		Name: ovsBri.Fields["name"].(string),
	}

	for _, uuid := range listUUID(ovsBri.Fields["ports"]) {
		port, err := monitor.fetchPortLocked(ovsdbCache, uuid, bridge.Name)
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
