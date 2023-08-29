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

package datapath

import (
	"fmt"
	"net"
	"strings"

	"github.com/contiv/libOpenflow/openflow13"
	"github.com/contiv/ofnet/ofctrl"
	log "github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"

	proxycache "github.com/everoute/everoute/pkg/agent/controller/proxy/cache"
	"github.com/everoute/everoute/pkg/agent/datapath/cache"
	everoutesvc "github.com/everoute/everoute/pkg/apis/service/v1alpha1"
	"github.com/everoute/everoute/pkg/constants"
)

var (
	NatBrInputTable                uint8 = 0
	NatBrInPortTable               uint8 = 4
	NatBrCTZoneTable               uint8 = 5
	NatBrCTStateTable              uint8 = 10
	NatBrSessionAffinityTable      uint8 = 30
	NatBrServiceLBTable            uint8 = 35
	NatBrSessionAffinityLearnTable uint8 = 40
	NatBrDnatTable                 uint8 = 50
	NatBrL3ForwardTable            uint8 = 90
	NatBrOutputTable               uint8 = 100
)

var (
	CTZoneReg             string              = "nxm_nx_reg0"
	CTZoneRange           *openflow13.NXRange = openflow13.NewNXRange(0, 15)
	CTZoneForPktFromLocal uint16              = 65505

	ChooseBackendFlagReg   string              = "nxm_nx_reg0"
	ChooseBackendFlagRange *openflow13.NXRange = openflow13.NewNXRange(16, 16)
	ChooseBackendFlagStart int                 = 16
	NeedChoose             uint8               = 0
	NoNeedChoose           uint8               = 1

	BackendIPReg         string              = "nxm_nx_reg1"
	BackendIPRegNumber   int                 = 1
	BackendIPRange       *openflow13.NXRange = openflow13.NewNXRange(0, 31)
	BackendPortReg       string              = "nxm_nx_reg2"
	BackendPortRegNumber int                 = 2
	BackendPortRange     *openflow13.NXRange = openflow13.NewNXRange(0, 15)

	ChooseBackendFlagLength uint16 = 1
)

const (
	SelectGroupWeight = 100
)

type NatBridge struct {
	BaseBridge

	inputTable                *ofctrl.Table
	inPortTable               *ofctrl.Table
	ctZoneTable               *ofctrl.Table
	ctStateTable              *ofctrl.Table
	sessionAffinityTable      *ofctrl.Table
	serviceLBTable            *ofctrl.Table
	sessionAffinityLearnTable *ofctrl.Table
	dnatTable                 *ofctrl.Table
	l3ForwardTable            *ofctrl.Table
	outputTable               *ofctrl.Table

	svcIndexCache *cache.SvcIndex // service flow and group database
	// l3FlowMap the key is interface uuid, the value is l3ForwardTable flow
	l3FlowMap map[string]*ofctrl.Flow
}

func NewNatBridge(brName string, datapathManager *DpManager) *NatBridge {
	natBr := new(NatBridge)
	natBr.name = fmt.Sprintf("%s-nat", brName)
	natBr.datapathManager = datapathManager
	natBr.svcIndexCache = cache.NewSvcIndex()
	natBr.l3FlowMap = make(map[string]*ofctrl.Flow)

	return natBr
}

func (n *NatBridge) ResetSvcIndexCache() {
	n.svcIndexCache = cache.NewSvcIndex()
}

func (n *NatBridge) BridgeInit() {}

func (n *NatBridge) BridgeInitCNI() {
	if !n.datapathManager.IsEnableProxy() {
		return
	}
	sw := n.OfSwitch

	_ = ofctrl.DeleteGroup(sw, openflow13.OFPG_ALL)

	n.inputTable = sw.DefaultTable()
	n.inPortTable, _ = sw.NewTable(NatBrInPortTable)
	n.ctZoneTable, _ = sw.NewTable(NatBrCTZoneTable)
	n.ctStateTable, _ = sw.NewTable(NatBrCTStateTable)
	n.sessionAffinityTable, _ = sw.NewTable(NatBrSessionAffinityTable)
	n.serviceLBTable, _ = sw.NewTable(NatBrServiceLBTable)
	n.sessionAffinityLearnTable, _ = sw.NewTable(NatBrSessionAffinityLearnTable)
	n.dnatTable, _ = sw.NewTable(NatBrDnatTable)
	n.l3ForwardTable, _ = sw.NewTable(NatBrL3ForwardTable)
	n.outputTable, _ = sw.NewTable(NatBrOutputTable)

	if err := n.initInputTable(); err != nil {
		log.Fatalf("Init Input table %d of nat bridge failed: %s", NatBrInputTable, err)
	}
	if err := n.initInPortTable(); err != nil {
		log.Fatalf("Init InPort table %d of nat bridge failed: %s", NatBrInPortTable, err)
	}
	if err := n.initCTZoneTable(); err != nil {
		log.Fatalf("Init CTZone table %d of nat bridge failed: %s", NatBrCTZoneTable, err)
	}
	if err := n.initCTStateTable(); err != nil {
		log.Fatalf("Init CTState table %d of nat bridge failed: %s", NatBrCTStateTable, err)
	}
	if err := n.initSessionAffinityTable(); err != nil {
		log.Fatalf("Init SessionAffinity table %d of nat bridge failed: %s", NatBrSessionAffinityTable, err)
	}
	if err := n.initServiceLBTable(); err != nil {
		log.Fatalf("Init ServiceLB table %d of nat bridge failed: %s", NatBrServiceLBTable, err)
	}
	if err := n.initSessionAffinityLearnTable(); err != nil {
		log.Fatalf("Init SessionAffinityLearn table %d of nat bridge failed: %s", NatBrSessionAffinityLearnTable, err)
	}
	if err := n.initL3ForwardTable(); err != nil {
		log.Fatalf("Init L3Forward table %d of nat bridge failed: %s", NatBrL3ForwardTable, err)
	}
	if err := n.initOutputTable(); err != nil {
		log.Fatalf("Init Output table %d of nat bridge failed: %s", NatBrOutputTable, err)
	}
}

func (n *NatBridge) BridgeReset() {}

func (n *NatBridge) AddLocalEndpoint(endpoint *Endpoint) error {
	if endpoint == nil {
		return nil
	}
	if n.l3FlowMap[endpoint.InterfaceUUID] != nil {
		log.Infof("The endpoint %+v related flow has been installed, skip add again", endpoint)
		return nil
	}

	macAddr, err := net.ParseMAC(endpoint.MacAddrStr)
	if err != nil {
		log.Errorf("The endpoint %+v has invalid mac addr, err: %s", endpoint, err)
		return err
	}

	if endpoint.IPAddr == nil {
		log.Infof("the endpoint %+v IPAddr is empty, skip add flow to l3 forward of nat bridge", endpoint)
		return nil
	}

	if endpoint.IPAddr.To4() == nil {
		log.Errorf("Failed to add local endpoint flow to l3 forward of nat bridge: the endpoint %+v IPAddr is not valid ipv4", endpoint)
		return fmt.Errorf("the endpoint %+v IPAddr is not valid ipv4", endpoint)
	}

	flow, err := n.l3ForwardTable.NewFlow(ofctrl.FlowMatch{
		Priority:  MID_MATCH_FLOW_PRIORITY,
		Ethertype: PROTOCOL_IP,
		IpDa:      &endpoint.IPAddr,
	})
	if err != nil {
		log.Errorf("Failed to new a flow in l3Forward table %d for endpoint %+v, err: %s", NatBrL3ForwardTable, endpoint, err)
		return err
	}

	if err := flow.SetMacDa(macAddr); err != nil {
		log.Errorf("Failed to add setMacDa action to flow %+v, endpoint %+v, err: %s", flow, endpoint, err)
		return err
	}

	if err := flow.Resubmit(nil, &NatBrOutputTable); err != nil {
		log.Errorf("Failed to add resubmit action to flow  %+v, endpoint: %+v, err: %s", flow, endpoint, err)
		return err
	}

	if err := flow.Next(ofctrl.NewEmptyElem()); err != nil {
		log.Errorf("Failed to install flow %+v, endpoint: %+v, err: %s", flow, endpoint, err)
		return err
	}
	n.l3FlowMap[endpoint.InterfaceUUID] = flow
	log.Infof("Nat bridge success add flow %+v for local endpoint interfaceUUID %s", flow, endpoint.InterfaceUUID)
	return nil
}

func (n *NatBridge) RemoveLocalEndpoint(endpoint *Endpoint) error {
	if endpoint == nil {
		return nil
	}

	if flow, ok := n.l3FlowMap[endpoint.InterfaceUUID]; ok && flow != nil {
		if err := flow.Delete(); err != nil {
			log.Errorf("Delete endpoint correspond l3 forward flow failed, endpoint: %+v, err: %s", endpoint, err)
			return err
		}
	}
	delete(n.l3FlowMap, endpoint.InterfaceUUID)
	log.Infof("Nat bridge success delete l3 forward flow for local endpoint interfaceUUID %s", endpoint.InterfaceUUID)
	return nil
}

func (n *NatBridge) GetSvcIndexCache() *cache.SvcIndex {
	return n.svcIndexCache
}

func (n *NatBridge) DelService(svcID string) error {
	svcOvsCache := n.svcIndexCache.GetSvcOvsInfo(svcID)
	if svcOvsCache == nil {
		log.Infof("The service %s related ovs flow and group has been deleted, skip delete the service", svcID)
		return nil
	}

	lbFlows := svcOvsCache.GetAllLBFlows()
	for i := range lbFlows {
		curEntry := lbFlows[i]
		if curEntry.Flow == nil {
			continue
		}
		if err := curEntry.Flow.Delete(); err != nil {
			log.Errorf("Failed to delete lb flow for service %s ip %s port %s, err: %s", svcID, curEntry.LBIP, curEntry.PortName, err)
			return err
		}
		svcOvsCache.SetLBFlow(curEntry.LBIP, curEntry.PortName, nil)
	}

	groups := svcOvsCache.GetAllGroups()
	for i := range groups {
		curEntry := groups[i]
		if curEntry.Group == nil {
			continue
		}
		curEntry.Group.Delete()
	}
	svcOvsCache.DeleteAllGroup()

	if err := n.DelSessionAffinity(svcID); err != nil {
		log.Errorf("Failed to delete session affinity flows for service %s, err: %s", svcID, err)
		return err
	}

	n.svcIndexCache.DeleteSvcOvsInfo(svcID)
	log.Infof("Dp success delete service %s", svcID)
	return nil
}

func (n *NatBridge) AddLBIP(svcID, ip string, ports []*proxycache.Port, sessionAffinityTimeout int32) error {
	ipDa := net.ParseIP(ip)
	if ipDa == nil {
		log.Errorf("Invalid lb ip %s for service %s", ip, svcID)
		return fmt.Errorf("invalid lb ip: %s", ip)
	}
	svcOvsCache := n.svcIndexCache.GetSvcOvsInfoAndInitIfEmpty(svcID)

	for i := range ports {
		if ports[i] == nil {
			continue
		}
		portName := ports[i].Name
		if svcOvsCache.GetLBFlow(ip, portName) != nil {
			log.Infof("The lb flow has been installed for service: %s, lbip: %s, portname: %s, skip create it", svcID, ip, portName)
			continue
		}
		if svcOvsCache.GetGroup(portName) == nil {
			newGp, err := n.createEmptyGroup()
			if err != nil {
				log.Errorf("Failed to create a empty group %s for service %s, lbip: %s, portname: %s", err, svcID, ip, portName)
				return err
			}
			svcOvsCache.SetGroup(portName, newGp)
		}
		gpID := svcOvsCache.GetGroup(portName).GroupID
		lbFlow, err := n.addLBFlow(&ipDa, ports[i].Protocol, ports[i].Port, gpID)
		if err != nil {
			log.Errorf("Failed to add a lb flow for service %s, ip: %s, portname: %s, err: %s", svcID, ip, portName, err)
			return err
		}
		svcOvsCache.SetLBFlow(ip, portName, lbFlow)
	}

	if sessionAffinityTimeout <= 0 {
		log.Infof("Dp success add service %s lb ip %s", svcID, ip)
		return nil
	}
	for i := range ports {
		if ports[i] == nil {
			continue
		}
		portName := ports[i].Name
		if svcOvsCache.GetSessionAffinityFlow(ip, portName) != nil {
			log.Infof("The session affinity flow has been installed for service %s, lb ip %s, port %s, skip create it", svcID, ip, portName)
			continue
		}
		sessionFlow, err := n.addSessionAffinityFlow(ipDa, ports[i].Protocol, ports[i].Port, sessionAffinityTimeout)
		if err != nil {
			log.Errorf("Failed to add a session affinity flow for service %s, ip: %s, portname: %s, err: %s", svcID, ip, portName, err)
			return err
		}
		svcOvsCache.SetSessionAffinityFlow(ip, portName, sessionFlow)
	}
	log.Infof("Dp success add service %s lb ip %s", svcID, ip)
	return nil
}

func (n *NatBridge) DelLBIP(svcID, ip string) error {
	ipDa := net.ParseIP(ip)
	if ipDa == nil {
		log.Errorf("Invalid lb ip %s for service %s", ip, svcID)
		return fmt.Errorf("invalid lb ip: %s", ip)
	}
	if n.svcIndexCache.GetSvcOvsInfo(svcID) == nil {
		log.Infof("Has no lb flow for svcID: %s", svcID)
		return nil
	}
	svcOvsCache := n.svcIndexCache.GetSvcOvsInfo(svcID)

	lbFlows := svcOvsCache.GetLBFlowsByIP(ip)
	for i := range lbFlows {
		curEntry := lbFlows[i]
		if curEntry.Flow == nil {
			continue
		}
		if err := curEntry.Flow.Delete(); err != nil {
			log.Errorf("Delete lb flow failed for lb ip: %s, port: %s, svcID: %s, flow: %+v, err: %s", ip, curEntry.PortName, svcID, curEntry.Flow, err)
			return err
		}
		svcOvsCache.SetLBFlow(ip, curEntry.PortName, nil)
	}

	sessionAffinityFlows := svcOvsCache.GetSessionAffinityFlowsByIP(ip)
	for i := range sessionAffinityFlows {
		curEntry := sessionAffinityFlows[i]
		if curEntry.Flow == nil {
			continue
		}
		if err := curEntry.Flow.Delete(); err != nil {
			log.Errorf("Delete session affinity flow failed for lb ip: %s, port: %s, svcID: %s, flow: %+v, err: %s", ip, curEntry.PortName, svcID, curEntry.Flow, err)
			return err
		}
		svcOvsCache.SetSessionAffinityFlow(ip, curEntry.PortName, nil)
	}

	log.Infof("Dp success delete service %s lb ip %s", svcID, ip)
	return nil
}

func (n *NatBridge) AddLBPort(svcID string, port *proxycache.Port, ips []string, sessionAffinityTimeout int32) error {
	if port == nil {
		return nil
	}

	portName := port.Name
	svcOvsCache := n.svcIndexCache.GetSvcOvsInfoAndInitIfEmpty(svcID)

	var err error
	gp := svcOvsCache.GetGroup(portName)
	if gp == nil {
		gp, err = n.createEmptyGroup()
		if err != nil {
			log.Errorf("Failed to create empty group for service %s port %+v, err: %s", svcID, *port, err)
			return err
		}
		svcOvsCache.SetGroup(portName, gp)
	}
	gpID := gp.GroupID

	for i := range ips {
		ipDa := net.ParseIP(ips[i])
		if ipDa == nil {
			log.Errorf("Invalid lb ip %s for service %s", ips[i], svcID)
			return fmt.Errorf("invalid lb ip: %s", ips[i])
		}
		if svcOvsCache.GetLBFlow(ips[i], portName) != nil {
			log.Infof("The lb flow for service %s ip %s port %s has been installed, skip create it", svcID, ips[i], portName)
			continue
		}
		lbFlow, err := n.addLBFlow(&ipDa, port.Protocol, port.Port, gpID)
		if err != nil {
			log.Errorf("Failed to add a lb flow for service %s, ip: %s, port: %+v, err: %s", svcID, ips[i], *port, err)
			return err
		}
		svcOvsCache.SetLBFlow(ips[i], portName, lbFlow)
	}

	if sessionAffinityTimeout <= 0 {
		log.Infof("Dp success add service %s port %+v", svcID, *port)
		return nil
	}
	for i := range ips {
		ipDa := net.ParseIP(ips[i])
		if ipDa == nil {
			log.Errorf("Invalid lb ip %s for service %s", ips[i], svcID)
			return fmt.Errorf("invalid lb ip: %s", ips[i])
		}
		if svcOvsCache.GetSessionAffinityFlow(ips[i], portName) != nil {
			log.Infof("The session affinity flow for service %s ip %s port %s has been installed, skip create it", svcID, ips[i], portName)
			continue
		}
		sessionFlow, err := n.addSessionAffinityFlow(ipDa, port.Protocol, port.Port, sessionAffinityTimeout)
		if err != nil {
			log.Errorf("Failed to add session affinity flow for service %s ip %s, port %+v, err: %s", svcID, ips[i], *port, err)
			return err
		}
		svcOvsCache.SetSessionAffinityFlow(ips[i], portName, sessionFlow)
	}

	log.Infof("Dp success add service %s port %+v", svcID, *port)
	return nil
}

func (n *NatBridge) UpdateLBPort(svcID string, port *proxycache.Port, ips []string, sessionAffinityTimeout int32) error {
	if port == nil {
		return nil
	}
	svcOvsCache := n.svcIndexCache.GetSvcOvsInfoAndInitIfEmpty(svcID)

	// delete old flows
	oldLBFlowEntrys := svcOvsCache.GetLBFlowsByPortName(port.Name)
	for i := range oldLBFlowEntrys {
		if err := oldLBFlowEntrys[i].Flow.Delete(); err != nil {
			log.Errorf("Failed to delete old lb flow %+v for service %s port %+v, err: %s", oldLBFlowEntrys[i].Flow, svcID, *port, err)
			return err
		}
		svcOvsCache.SetLBFlow(oldLBFlowEntrys[i].LBIP, port.Name, nil)
	}
	if err := n.delSessionAffinityFlowsByPortName(svcID, port.Name); err != nil {
		log.Errorf("Failed to delete old session affinity flow for service %s port %+v, err: %s", svcID, *port, err)
		return err
	}

	// add new flows
	if err := n.AddLBPort(svcID, port, ips, sessionAffinityTimeout); err != nil {
		log.Errorf("Failed to add new flow for service %s update port %+v, err: %s", svcID, *port, err)
		return err
	}
	log.Infof("Dp success update service %s port %+v", svcID, *port)
	return nil
}

func (n *NatBridge) DelLBPort(svcID, portName string) error {
	svcOvsCache := n.svcIndexCache.GetSvcOvsInfo(svcID)
	if svcOvsCache == nil {
		log.Infof("The Service %s has no related ovs flow and group for port %s", svcID, portName)
		return nil
	}
	if err := n.DelLBGroup(svcID, portName); err != nil {
		log.Errorf("Failed to delete service port related flow and group for service %s port %s, err: %s", svcID, portName, err)
		return err
	}

	if err := n.delSessionAffinityFlowsByPortName(svcID, portName); err != nil {
		log.Errorf("Failed to delete session affinity flow for service %s port %s, err: %s", svcID, portName, err)
		return err
	}

	log.Infof("Dp success delete service %s port %s", svcID, portName)
	return nil
}

func (n *NatBridge) DelSessionAffinity(svcID string) error {
	svcOvsCache := n.svcIndexCache.GetSvcOvsInfo(svcID)
	if svcOvsCache == nil {
		log.Infof("The service %s has no session affinity flow, skip delete session affinity", svcID)
		return nil
	}
	sessionFlows := svcOvsCache.GetAllSessionAffinityFlows()
	for i := range sessionFlows {
		curEntry := sessionFlows[i]
		if curEntry.Flow == nil {
			continue
		}
		if err := curEntry.Flow.Delete(); err != nil {
			log.Errorf("Failed to delete session affinity flow for service %s ip %s port %s, err: %s", svcID, curEntry.LBIP, curEntry.PortName, err)
			return err
		}
		svcOvsCache.SetSessionAffinityFlow(curEntry.LBIP, curEntry.PortName, nil)
	}

	log.Infof("Dp success delete service %s session affinity flows", svcID)
	return nil
}

func (n *NatBridge) AddSessionAffinity(svcID string, ips []string, ports []*proxycache.Port, sessionAffinityTimeout int32) error {
	if sessionAffinityTimeout <= 0 {
		log.Errorf("Invalid sessionAffinityTimeout %d", sessionAffinityTimeout)
		return fmt.Errorf("invalid sessionAffinityTimeout %d", sessionAffinityTimeout)
	}
	svcOvsCache := n.svcIndexCache.GetSvcOvsInfoAndInitIfEmpty(svcID)
	for i := range ips {
		ip := ips[i]
		ipByte := net.ParseIP(ip)
		if ipByte == nil {
			log.Errorf("Invalid dnat ip %s", ip)
			return fmt.Errorf("invalid dnat ip: %s", ip)
		}
		for j := range ports {
			port := ports[j]
			if port == nil {
				continue
			}
			flow, err := n.addSessionAffinityFlow(ipByte, port.Protocol, port.Port, sessionAffinityTimeout)
			if err != nil {
				log.Errorf("Failed to add session affinity flow for service %s ip %s port %+v, session affinity timeout: %d, err: %s", svcID, ip, *port, sessionAffinityTimeout, err)
				return err
			}
			svcOvsCache.SetSessionAffinityFlow(ip, port.Name, flow)
		}
	}
	log.Infof("Dp seccess add service %s session affinity related flows with session affinity timeout %d", svcID, sessionAffinityTimeout)
	return nil
}

func (n *NatBridge) UpdateSessionAffinityTimeout(svcID string, ips []string, ports []*proxycache.Port, sessionAffinityTimeout int32) error {
	if sessionAffinityTimeout <= 0 {
		log.Errorf("Invalid session affinity timeout %d for service %s, skip update session affinity timeout", sessionAffinityTimeout, svcID)
		return fmt.Errorf("invalid session affinity timeout %d for update service %s session affinity timeout", sessionAffinityTimeout, svcID)
	}

	if err := n.DelSessionAffinity(svcID); err != nil {
		log.Errorf("Failed to delete old session affinity flows for update service %s SessionAffinityTimeout to %d, err: %s", svcID, sessionAffinityTimeout, err)
		return err
	}

	if err := n.AddSessionAffinity(svcID, ips, ports, sessionAffinityTimeout); err != nil {
		log.Errorf("Failed to add new session affinity flows for update service %s SessionAffinityTimeout to %d, err: %s", svcID, sessionAffinityTimeout, err)
		return err
	}

	log.Infof("Dp success update service %s session affinity timeout to %d", svcID, sessionAffinityTimeout)
	return nil
}

func (n *NatBridge) UpdateLBGroup(svcID, portName string, backends []everoutesvc.Backend) error {
	svcOvsCache := n.svcIndexCache.GetSvcOvsInfoAndInitIfEmpty(svcID)
	var err error
	creatGpFlag := false
	gp := svcOvsCache.GetGroup(portName)
	if gp == nil {
		creatGpFlag = true
		gp, err = n.newEmptyGroup()
		if err != nil {
			log.Errorf("Failed to new a empty group, err: %s", err)
			return err
		}
	}

	buckets := make([]*ofctrl.Bucket, 0, len(backends))
	for i := range backends {
		b, err := newBucketForLBGroup(backends[i].IP, backends[i].Port)
		if err != nil {
			log.Errorf("Failed to new a bucket for service %s with backend %+v, err: %s", svcID, backends[i], err)
			return nil
		}
		buckets = append(buckets, b)
	}
	gp.ResetBuckets(buckets)

	if creatGpFlag {
		if err := gp.Install(); err != nil {
			log.Errorf("Failed to install group %+v for service: %s, err: %s", gp, svcID, err)
			return err
		}
		svcOvsCache.SetGroup(portName, gp)
	}

	log.Infof("Dp success to update LB group for service %s port %s, backends: %+v", svcID, portName, backends)
	return nil
}

func (n *NatBridge) ResetLBGroup(svcID, portName string) error {
	svcOvsCache := n.svcIndexCache.GetSvcOvsInfo(svcID)
	if svcOvsCache == nil {
		log.Infof("The Service %s has no related ovs group for port %s", svcID, portName)
		return nil
	}
	gp := svcOvsCache.GetGroup(portName)
	if gp == nil {
		log.Infof("The Service %s has no related ovs group for port %s", svcID, portName)
		return nil
	}
	gp.ResetBuckets(make([]*ofctrl.Bucket, 0))
	log.Infof("Dp success clear LB group buckets for service %s port %s", svcID, portName)
	return nil
}

func (n *NatBridge) DelLBGroup(svcID, portName string) error {
	svcOvsCache := n.svcIndexCache.GetSvcOvsInfo(svcID)
	if svcOvsCache == nil {
		log.Infof("The Service %s has no related ovs group for port %s", svcID, portName)
		return nil
	}
	if svcOvsCache.GetGroup(portName) != nil {
		svcOvsCache.GetGroup(portName).Delete()
		svcOvsCache.SetGroup(portName, nil)
	}
	// when a group is deleted, the flow referenced it will be deleted automatically
	svcOvsCache.DeleteLBFlowsByPortName(portName)
	log.Infof("Success delete service %s ovs group related port %s", svcID, portName)
	return nil
}

func (n *NatBridge) AddDNATFlow(ip string, protocol corev1.Protocol, port int32) error {
	ipByte := net.ParseIP(ip)
	if ipByte == nil {
		log.Errorf("Invalid dnat ip %s", ip)
		return fmt.Errorf("invalid dnat ip: %s", ip)
	}
	dnatKey := cache.GenDnatMapKey(ip, string(protocol), port)
	if f := n.svcIndexCache.GetDnatFlow(dnatKey); f != nil {
		log.Infof("The dnat flow has been exists, skip it. ip: %s, protocol: %s, port: %d, flow: %+v", ip, protocol, port, f)
		return nil
	}

	ipProtocol, err := k8sProtocolToOvsProtocol(protocol)
	if err != nil {
		log.Errorf("Transfer protocol failed: %s", err)
		return err
	}
	regs := []*ofctrl.NXRegister{
		{
			RegID: BackendIPRegNumber,
			Data:  ipv4ToUint32(ipByte),
			Range: BackendIPRange,
		}, {
			RegID: BackendPortRegNumber,
			Data:  uint32(port),
			Range: BackendPortRange,
		},
	}
	flow, err := n.dnatTable.NewFlow(ofctrl.FlowMatch{
		Priority:  MID_MATCH_FLOW_PRIORITY,
		Ethertype: PROTOCOL_IP,
		IpProto:   uint8(ipProtocol),
		Regs:      regs,
	})
	if err != nil {
		log.Errorf("Failed to new a dnat flow for ip %s protocol %s port %d, err: %s", ip, protocol, port, err)
		return err
	}

	natAct, _ := ofctrl.NewDNatAction(ofctrl.NewIPRange(ipByte), ofctrl.NewPortRange(uint16(port))).ToOfAction()
	ctAct, err := ofctrl.NewConntrackActionWithZoneField(true, false, &NatBrL3ForwardTable, CTZoneReg, CTZoneRange, natAct)
	if err != nil {
		log.Errorf("Failed to new a conntrack action for ip %s, protocol %s, port %d, err: %s", ip, protocol, port, err)
		return err
	}
	_ = flow.SetConntrack(ctAct)
	if err := flow.Next(ofctrl.NewEmptyElem()); err != nil {
		log.Errorf("Failed to install dnat flow for ip %s protocol %s port %d, err: %s", ip, protocol, port, err)
		return err
	}

	n.svcIndexCache.SetDnatFlow(dnatKey, flow)
	log.Infof("Success add a dnat flow %+v for ip %s protocol: %s port: %d", flow, ip, protocol, port)
	return nil
}

func (n *NatBridge) DelDnatFlow(ip string, protocol corev1.Protocol, port int32) error {
	ipByte := net.ParseIP(ip)
	if ipByte == nil {
		log.Errorf("Invalid dnat ip %s", ip)
		return fmt.Errorf("invalid dnat ip: %s", ip)
	}

	dnatKey := cache.GenDnatMapKey(ip, string(protocol), port)
	flow := n.svcIndexCache.GetDnatFlow(dnatKey)
	if flow == nil {
		log.Infof("The dnat flow has been deleted, skip it. ip: %s, protocol: %s, port: %d", ip, protocol, port)
		return nil
	}

	if err := flow.Delete(); err != nil {
		log.Errorf("Delete dnat flow %+v for %s failed, err: %s", flow, dnatKey, err)
		return err
	}

	n.svcIndexCache.DeleteDnatFlow(dnatKey)
	log.Infof("Success delete dnat flow for %s", dnatKey)
	return nil
}

func (n *NatBridge) addLBFlow(ipDa *net.IP, protocol corev1.Protocol, port int32, gpID uint32) (*ofctrl.Flow, error) {
	newFlow, err := n.newLBFlow(ipDa, protocol, port)
	if err != nil {
		log.Errorf("Failed to New a lb flow: %s", err)
		return nil, err
	}
	if err := newFlow.SetGroup(gpID); err != nil {
		log.Errorf("Failed to set group action to lb flow: %+v, err: %s", newFlow, err)
		return nil, err
	}
	if err := newFlow.Next(ofctrl.NewEmptyElem()); err != nil {
		log.Errorf("Failed to install lb flow: %+v, err: %s", newFlow, err)
		return nil, err
	}
	return newFlow, nil
}

func (n *NatBridge) newLBFlow(ipDa *net.IP, protocol corev1.Protocol, port int32) (*ofctrl.Flow, error) {
	if protocol == corev1.ProtocolTCP {
		newFlow, err := n.serviceLBTable.NewFlow(ofctrl.FlowMatch{
			Priority:       MID_MATCH_FLOW_PRIORITY,
			Ethertype:      PROTOCOL_IP,
			IpProto:        PROTOCOL_TCP,
			IpDa:           ipDa,
			IpDaMask:       &IPMaskMatchFullBit,
			TcpDstPort:     uint16(port),
			TcpDstPortMask: PortMaskMatchFullBit,
		})
		return newFlow, err
	}

	if protocol == corev1.ProtocolUDP {
		newFlow, err := n.serviceLBTable.NewFlow(ofctrl.FlowMatch{
			Priority:       MID_MATCH_FLOW_PRIORITY,
			Ethertype:      PROTOCOL_IP,
			IpProto:        PROTOCOL_UDP,
			IpDa:           ipDa,
			IpDaMask:       &IPMaskMatchFullBit,
			UdpDstPort:     uint16(port),
			UdpDstPortMask: PortMaskMatchFullBit,
		})
		return newFlow, err
	}

	return nil, fmt.Errorf("invalid protocol: %s", protocol)
}

func (n *NatBridge) createEmptyGroup() (*ofctrl.Group, error) {
	newGp, err := n.newEmptyGroup()
	if err != nil {
		log.Errorf("Failed to new a empty group, err: %s", err)
		return nil, err
	}
	if err := newGp.Install(); err != nil {
		log.Errorf("Failed to install group: %+v, err: %s", *newGp, err)
		return nil, err
	}
	return newGp, nil
}

func (n *NatBridge) newEmptyGroup() (*ofctrl.Group, error) {
	sw := n.OfSwitch
	groupID, err := getGroupID()
	if err != nil {
		log.Errorf("Allocate a new group id failed, err: %s", err)
		return nil, err
	}
	newGp, err := sw.NewGroup(groupID, uint8(openflow13.OFPGT_SELECT))
	if err != nil {
		log.Errorf("Failed to new a group, err: %s", err)
		return nil, err
	}
	return newGp, nil
}

func (n *NatBridge) delSessionAffinityFlowsByPortName(svcID, portName string) error {
	svcOvsCache := n.svcIndexCache.GetSvcOvsInfo(svcID)
	if svcOvsCache == nil {
		return nil
	}
	sessionFlows := svcOvsCache.GetSessionAffinityFlowsByPortName(portName)
	for i := range sessionFlows {
		curEntry := sessionFlows[i]
		if curEntry.Flow == nil {
			continue
		}
		if err := curEntry.Flow.Delete(); err != nil {
			log.Errorf("Failed to delete session affinity flow for service %s port %s, err: %s", svcID, portName, err)
			return err
		}
		svcOvsCache.SetSessionAffinityFlow(curEntry.LBIP, portName, nil)
	}

	return nil
}

func (n *NatBridge) initInputTable() error {
	ipFlow, err := n.inputTable.NewFlow(ofctrl.FlowMatch{
		Priority:  MID_MATCH_FLOW_PRIORITY,
		Ethertype: PROTOCOL_IP,
	})
	if err != nil {
		log.Errorf("Failed to new a flow match ip in Input table %d: %s", NatBrInputTable, err)
		return err
	}
	if err = ipFlow.Resubmit(nil, &NatBrInPortTable); err != nil {
		log.Errorf("Failed to add resubmit action to flow in Input table %d: %s", NatBrInputTable, err)
		return err
	}
	if err = ipFlow.Next(ofctrl.NewEmptyElem()); err != nil {
		log.Errorf("Failed to install flow in Input table %d: %s", NatBrInputTable, err)
		return err
	}

	dropFlow, err := n.inputTable.NewFlow(ofctrl.FlowMatch{
		Priority: DEFAULT_DROP_FLOW_PRIORITY,
	})
	if err != nil {
		log.Errorf("Failed to new a flow in Input table %d: %s", NatBrInputTable, err)
		return err
	}
	if err = dropFlow.Next(n.OfSwitch.DropAction()); err != nil {
		log.Errorf("Failed to install a default drop flow in Input table %d: %s", NatBrInputTable, err)
		return err
	}
	return nil
}

func (n *NatBridge) initInPortTable() error {
	localBrName := strings.TrimSuffix(n.name, "-nat")

	flow, err := n.inPortTable.NewFlow(ofctrl.FlowMatch{
		Priority:  MID_MATCH_FLOW_PRIORITY,
		InputPort: n.datapathManager.BridgeChainPortMap[localBrName][NatToLocalSuffix],
	})
	if err != nil {
		log.Errorf("Failed to new a flow in InPort table %d: %s", NatBrInPortTable, err)
		return err
	}
	if err = flow.LoadField(CTZoneReg, uint64(CTZoneForPktFromLocal), CTZoneRange); err != nil {
		log.Errorf("Failed to add load action to flow in InPort table %d: %s", NatBrInPortTable, err)
		return err
	}
	if err = flow.Resubmit(nil, &NatBrCTZoneTable); err != nil {
		log.Errorf("Failed to add resubmit action to flow in InPort table %d: %s", NatBrInPortTable, err)
		return err
	}
	if err = flow.Next(ofctrl.NewEmptyElem()); err != nil {
		log.Errorf("Failed to install flow in InPort table %d: %s", NatBrInPortTable, err)
		return err
	}
	return nil
}

func (n *NatBridge) initCTZoneTable() error {
	flow, err := n.ctZoneTable.NewFlow(ofctrl.FlowMatch{
		Priority:  MID_MATCH_FLOW_PRIORITY,
		Ethertype: PROTOCOL_IP,
	})
	if err != nil {
		log.Errorf("Failed to new a flow in CTZone table %d: %s", NatBrCTZoneTable, err)
		return err
	}
	ctAct, err := ofctrl.NewConntrackActionWithZoneField(false, false, &NatBrCTStateTable, CTZoneReg, CTZoneRange)
	if err != nil {
		log.Errorf("Failed to new a ct action: %s", err)
		return err
	}
	_ = flow.SetConntrack(ctAct)
	if err = flow.Next(ofctrl.NewEmptyElem()); err != nil {
		log.Errorf("Failed to install flow in CTZone table %d: %s", NatBrCTZoneTable, err)
		return err
	}
	return nil
}

func (n *NatBridge) initCTStateTable() error {
	// -new+trk flow commit immediately, and do dnat or snat according to conntrack table
	ctState := openflow13.NewCTStates()
	ctState.UnsetNew()
	ctState.SetTrk()
	trkFlow, err := n.ctStateTable.NewFlow(ofctrl.FlowMatch{
		Priority:  HIGH_MATCH_FLOW_PRIORITY,
		Ethertype: PROTOCOL_IP,
		CtStates:  ctState,
	})
	if err != nil {
		log.Errorf("Failed to new a flow in CTState table %d: %s", NatBrCTStateTable, err)
		return err
	}
	natAct, _ := ofctrl.NewNatAction().ToOfAction()
	ctAct, err := ofctrl.NewConntrackActionWithZoneField(true, false, &NatBrL3ForwardTable, CTZoneReg, CTZoneRange, natAct)
	if err != nil {
		log.Errorf("Failed to new a ct action with nat: %s", err)
		return err
	}
	_ = trkFlow.SetConntrack(ctAct)
	if err = trkFlow.Next(ofctrl.NewEmptyElem()); err != nil {
		log.Errorf("Failed to install flow in CTState table %d: %s", NatBrCTStateTable, err)
		return err
	}

	// the first packet of pod->svc, should choose backend ip
	svcIP := n.datapathManager.Info.ClusterCIDR.IP
	svcMask := (net.IP)(n.datapathManager.Info.ClusterCIDR.Mask)
	svcFlow, err := n.ctStateTable.NewFlow(ofctrl.FlowMatch{
		Priority:  MID_MATCH_FLOW_PRIORITY,
		Ethertype: PROTOCOL_IP,
		IpDa:      &svcIP,
		IpDaMask:  &svcMask,
	})
	if err != nil {
		log.Errorf("Failed to new a flow in CTState table %d: %s", NatBrCTStateTable, err)
		return err
	}
	if err := svcFlow.Resubmit(nil, &NatBrSessionAffinityTable); err != nil {
		log.Errorf("Failed to add a resubmit action to CTState table %d: %s", NatBrCTStateTable, err)
		return err
	}
	if err := svcFlow.Resubmit(nil, &NatBrServiceLBTable); err != nil {
		log.Errorf("Failed to add a resubmit action to CTState table %d: %s", NatBrCTStateTable, err)
		return err
	}
	if err := svcFlow.Next(ofctrl.NewEmptyElem()); err != nil {
		log.Errorf("Failed to install flow in CTState table %d: %s", NatBrCTStateTable, err)
		return err
	}

	// non-service flow, output indirect
	defaultFlow, err := n.ctStateTable.NewFlow(ofctrl.FlowMatch{
		Priority: DEFAULT_FLOW_MISS_PRIORITY,
	})
	if err != nil {
		log.Errorf("Failed to new flow in CTState table %d: %s", NatBrCTStateTable, err)
		return err
	}
	if err := defaultFlow.Resubmit(nil, &NatBrOutputTable); err != nil {
		log.Errorf("Failed to add resubmit action to flow in CTState table %d: %s", NatBrCTStateTable, err)
		return err
	}
	if err := defaultFlow.Next(ofctrl.NewEmptyElem()); err != nil {
		log.Errorf("Failed to install flow in CTState table %d: %s", NatBrCTStateTable, err)
		return err
	}

	return nil
}

func (n *NatBridge) initSessionAffinityTable() error {
	defaultFlow, err := n.sessionAffinityTable.NewFlow(ofctrl.FlowMatch{
		Priority: DEFAULT_FLOW_MISS_PRIORITY,
	})
	if err != nil {
		log.Errorf("Failed to new a flow in SessionAffinity table %d: %s", NatBrSessionAffinityTable, err)
		return err
	}
	if err := defaultFlow.LoadField(ChooseBackendFlagReg, uint64(NeedChoose), ChooseBackendFlagRange); err != nil {
		log.Errorf("Failed to add a load field action to flow in SessionAffinity table %d: %s", NatBrSessionAffinityTable, err)
		return err
	}
	if err := defaultFlow.Next(ofctrl.NewEmptyElem()); err != nil {
		log.Errorf("Failed to install flow in SessionAffinity table %d: %s", NatBrSessionAffinityTable, err)
		return err
	}
	return nil
}

func (n *NatBridge) initServiceLBTable() error {
	flow, err := n.serviceLBTable.NewFlow(ofctrl.FlowMatch{
		Priority: HIGH_MATCH_FLOW_PRIORITY,
		Regs: []*ofctrl.NXRegister{
			{
				RegID: constants.OVSReg0,
				Data:  uint32(NoNeedChoose) << uint32(ChooseBackendFlagStart),
				Range: ChooseBackendFlagRange,
			},
		},
	})
	if err != nil {
		log.Errorf("Failed to new a flow in ServiceLB table %d: %s", NatBrServiceLBTable, err)
		return err
	}
	if err = flow.Resubmit(nil, &NatBrDnatTable); err != nil {
		log.Errorf("Failed to add resubmit action to flow in ServiceLB table %d: %s", NatBrServiceLBTable, err)
		return err
	}
	if err = flow.Next(ofctrl.NewEmptyElem()); err != nil {
		log.Errorf("Failed to install flow in ServiceLB table %d: %s", NatBrServiceLBTable, err)
		return err
	}
	return nil
}

func (n *NatBridge) buildLearnActOfSessionAffinityLearnTable(ipProto uint8, learnActionTimeout int32) (*ofctrl.LearnAction, error) {
	ethTypeField := ofctrl.LearnField{Name: "nxm_of_eth_type", Start: 0}
	ipSrcField := ofctrl.LearnField{Name: "nxm_of_ip_src", Start: 0}
	ipDstField := ofctrl.LearnField{Name: "nxm_of_ip_dst", Start: 0}

	ipProtoField := ofctrl.LearnField{Name: "nxm_of_ip_proto", Start: 0}
	tcpDstField := ofctrl.LearnField{Name: "nxm_of_tcp_dst", Start: 0}
	udpDstField := ofctrl.LearnField{Name: "nxm_of_udp_dst", Start: 0}

	backendIPField := ofctrl.LearnField{Name: BackendIPReg, Start: 0}
	backendPortField := ofctrl.LearnField{Name: BackendPortReg, Start: 0}
	chooseBackendFlagField := ofctrl.LearnField{Name: ChooseBackendFlagReg, Start: uint16(ChooseBackendFlagStart)}

	cookieID, err := getLearnCookieID()
	if err != nil {
		return nil, err
	}
	learnAct := ofctrl.NewLearnAction(NatBrSessionAffinityTable, MID_MATCH_FLOW_PRIORITY, 0, uint16(learnActionTimeout), 0, 0, cookieID)
	learnAct.SetDeleteLearned()

	if err := learnAct.AddLearnedMatch(&ethTypeField, EtherTypeLength, nil, uintToByteBigEndian(uint16(PROTOCOL_IP))); err != nil {
		return nil, err
	}
	if err := learnAct.AddLearnedMatch(&ipSrcField, IPv4Lenth, &ipSrcField, nil); err != nil {
		return nil, err
	}
	if err := learnAct.AddLearnedMatch(&ipDstField, IPv4Lenth, &ipDstField, nil); err != nil {
		return nil, err
	}

	switch ipProto {
	case PROTOCOL_TCP:
		if err := learnAct.AddLearnedMatch(&ipProtoField, ProtocolLength, nil, uintToByteBigEndian(uint16(PROTOCOL_TCP))); err != nil {
			return nil, err
		}
		if err := learnAct.AddLearnedMatch(&tcpDstField, PortLength, &tcpDstField, nil); err != nil {
			return nil, err
		}
	case PROTOCOL_UDP:
		if err := learnAct.AddLearnedMatch(&ipProtoField, ProtocolLength, nil, uintToByteBigEndian(uint16(PROTOCOL_UDP))); err != nil {
			return nil, err
		}
		if err := learnAct.AddLearnedMatch(&udpDstField, PortLength, &udpDstField, nil); err != nil {
			return nil, err
		}
	default:
		log.Errorf("No support for this ip protocol number: %d", ipProto)
		return nil, fmt.Errorf("unsupported ip protocol number %d", ipProto)
	}

	if err := learnAct.AddLearnedLoadAction(&backendIPField, IPv4Lenth, &backendIPField, nil); err != nil {
		return nil, err
	}
	if err := learnAct.AddLearnedLoadAction(&backendPortField, PortLength, &backendPortField, nil); err != nil {
		return nil, err
	}
	if err := learnAct.AddLearnedLoadAction(&chooseBackendFlagField, ChooseBackendFlagLength, nil, uintToByteBigEndian(uint16(NoNeedChoose))); err != nil {
		return nil, err
	}

	return learnAct, nil
}

func (n *NatBridge) addSessionAffinityFlow(dstIP net.IP, protocol corev1.Protocol, dstPort int32, sessionAffinityTimeout int32) (*ofctrl.Flow, error) {
	var flow *ofctrl.Flow
	var ipProto uint8
	var err error
	switch protocol {
	case corev1.ProtocolTCP:
		ipProto = PROTOCOL_TCP
		flow, err = n.sessionAffinityLearnTable.NewFlow(ofctrl.FlowMatch{
			Priority:       MID_MATCH_FLOW_PRIORITY,
			Ethertype:      PROTOCOL_IP,
			IpProto:        ipProto,
			IpDa:           &dstIP,
			IpDaMask:       &IPMaskMatchFullBit,
			TcpDstPort:     uint16(dstPort),
			TcpDstPortMask: PortMaskMatchFullBit,
		})
		if err != nil {
			log.Errorf("Failed to new session affinity flow for ip %s protocol %s port %d: %s", dstIP, protocol, dstPort, err)
			return nil, err
		}
	case corev1.ProtocolUDP:
		ipProto = PROTOCOL_UDP
		flow, err = n.sessionAffinityLearnTable.NewFlow(ofctrl.FlowMatch{
			Priority:       MID_MATCH_FLOW_PRIORITY,
			Ethertype:      PROTOCOL_IP,
			IpProto:        ipProto,
			IpDa:           &dstIP,
			IpDaMask:       &IPMaskMatchFullBit,
			UdpDstPort:     uint16(dstPort),
			UdpDstPortMask: PortMaskMatchFullBit,
		})
		if err != nil {
			log.Errorf("Failed to new session affinity flow for ip %s protocol %s port %d: %s", dstIP, protocol, dstPort, err)
			return nil, err
		}
	default:
		log.Errorf("Unsupport service protocol %s", protocol)
		return nil, fmt.Errorf("unsupport service protocol %s", protocol)
	}

	learnAct, err := n.buildLearnActOfSessionAffinityLearnTable(ipProto, sessionAffinityTimeout)
	if err != nil {
		log.Errorf("Failed to build a learn action: %s", err)
		return nil, err
	}
	if err = flow.Learn(learnAct); err != nil {
		log.Errorf("Failed to add learn action to session affinity flow for ip %s protocol %s port %d: %s", dstIP, protocol, dstPort, err)
		return nil, err
	}
	if err = flow.Resubmit(nil, &NatBrDnatTable); err != nil {
		log.Errorf("Failed to add a resubmit action to session affinity flow for ip %s protocol %s port %d: %s", dstIP, protocol, dstPort, err)
		return nil, err
	}
	if err = flow.Next(ofctrl.NewEmptyElem()); err != nil {
		log.Errorf("Failed to install session affinity flow %+v for ip %s protocol %s port %d: %s", flow, dstIP, protocol, dstPort, err)
		return nil, err
	}

	return flow, nil
}

func (n *NatBridge) initSessionAffinityLearnTable() error {
	defaultFlow, err := n.sessionAffinityLearnTable.NewFlow(ofctrl.FlowMatch{
		Priority: DEFAULT_FLOW_MISS_PRIORITY,
	})
	if err != nil {
		log.Errorf("Failed to new default flow SessionAffinityLearn table %d: %s", NatBrSessionAffinityLearnTable, err)
		return err
	}
	if err := defaultFlow.Resubmit(nil, &NatBrDnatTable); err != nil {
		log.Errorf("Failed to add a resubmit action to default flow in SessionAffinityLearn table %d: %s", NatBrSessionAffinityLearnTable, err)
		return err
	}
	if err := defaultFlow.Next(ofctrl.NewEmptyElem()); err != nil {
		log.Errorf("Failed to install flow in SessionAffinityLearn table %d: %s", NatBrSessionAffinityLearnTable, err)
		return err
	}
	return nil
}

func (n *NatBridge) initL3ForwardTable() error {
	defaultFlow, err := n.l3ForwardTable.NewFlow(ofctrl.FlowMatch{
		Priority: DEFAULT_FLOW_MISS_PRIORITY,
	})
	if err != nil {
		log.Errorf("Failed to new a flow in L3Forward table %d: %s", NatBrL3ForwardTable, err)
		return err
	}
	if err := defaultFlow.Resubmit(nil, &NatBrOutputTable); err != nil {
		log.Errorf("Failed to add resubmit action to flow in L3Forward table %d: %s", NatBrL3ForwardTable, err)
		return err
	}
	if err := defaultFlow.Next(ofctrl.NewEmptyElem()); err != nil {
		log.Errorf("Failed to install flow in L3Forward table %d: %s", NatBrL3ForwardTable, err)
		return err
	}

	return nil
}

func (n *NatBridge) initOutputTable() error {
	defaultFlow, err := n.outputTable.NewFlow(ofctrl.FlowMatch{
		Priority: NORMAL_MATCH_FLOW_PRIORITY,
	})
	if err != nil {
		log.Errorf("Failed to new a flow in L3Forward table %d: %s", NatBrOutputTable, err)
		return err
	}
	outputPort, err := n.OfSwitch.OutputPort(openflow13.P_IN_PORT)
	if err != nil {
		log.Errorf("Failed to make outputPort: %s", err)
		return err
	}
	if err := defaultFlow.Next(outputPort); err != nil {
		log.Errorf("Failed to install flow in L3Forward table %d: %s", NatBrOutputTable, err)
		return err
	}

	return nil
}

func newBucketForLBGroup(ip string, port int32) (*ofctrl.Bucket, error) {
	bucket := ofctrl.NewBucket(SelectGroupWeight)
	ipByte := net.ParseIP(ip)
	if ipByte == nil {
		log.Errorf("Invalid backend ip %s", ip)
		return nil, fmt.Errorf("invalid backend ip: %s", ip)
	}
	act1, err := ofctrl.NewNXLoadAction(BackendIPReg, ipv4ToUint64(ipByte), BackendIPRange)
	if err != nil {
		log.Errorf("Failed to new a NXLoadAction for backend ip %s, err: %s", ip, err)
		return nil, err
	}
	bucket.AddAction(act1)

	act2, err := ofctrl.NewNXLoadAction(BackendPortReg, uint64(port), BackendPortRange)
	if err != nil {
		log.Errorf("Failed to new a NXLoadAction for backend port %d, err: %s", port, err)
		return nil, err
	}
	bucket.AddAction(act2)

	act3 := ofctrl.NewResubmitAction(nil, &NatBrSessionAffinityLearnTable)
	bucket.AddAction(act3)
	return bucket, nil
}
