package datapath

import (
	"strings"

	"k8s.io/klog/v2"

	trconst "github.com/everoute/everoute/pkg/constants/tr"
	"github.com/everoute/everoute/pkg/trafficredirect/action"
	"github.com/everoute/everoute/pkg/types"
)

func IsTREndpoint(endpoint *Endpoint) bool {
	if endpoint.BridgeName == trconst.SvcChainBridgeName {
		return true
	}
	if strings.HasSuffix(endpoint.BridgeName, PolicyBridgeSuffix) {
		return true
	}
	return false
}

func assemblyTRFlowID(roundNumber uint64, seqID uint64) uint64 {
	if seqID >= 1<<trconst.FlowIDVariableLowBits {
		klog.Fatalf("param seqID %d is invalid, max seqID is %d", seqID, 1<<trconst.FlowIDVariableLowBits-1)
	}
	return trconst.FlowIDPrefix + roundNumber<<trconst.FlowIDVariableLowBits + seqID
}

func GetTRNicFlowID(roundNumber uint64) uint64 {
	return assemblyTRFlowID(roundNumber, trconst.FlowIDForTRNicSuffix)
}

func GetTRHealthyFlowID(roundNumber uint64) uint64 {
	return assemblyTRFlowID(roundNumber, trconst.FlowIDForHealthySuffix)
}

func (dm *DpManager) IsEnableTR() bool {
	if dm.Config == nil {
		return false
	}
	return len(dm.Config.TRConfig) != 0
}

func (dm *DpManager) AddTREndpoint(ep *Endpoint) error {
	klog.Infof("Begin to process tr endpoint %v add", ep)
	if ep.IfaceID == "" {
		klog.Infof("tr endpoint %s(uuid: %s) ifaceID is null, skip process it", ep.InterfaceName, ep.InterfaceUUID)
		return nil
	}
	if ep.BridgeName == trconst.SvcChainBridgeName {
		dm.mustRemountTRNic(ep)
		return nil
	}

	localBridge, ok := strings.CutSuffix(ep.BridgeName, PolicyBridgeSuffix)
	if !ok {
		klog.Warningf("tr endpoint %v doesn't connect policy bridge or svcchain bridge", ep)
		return nil
	}
	for vdsID, ovsbrname := range dm.Config.ManagedVDSMap {
		if localBridge != ovsbrname {
			continue
		}
		return dm.BridgeChainMap[vdsID][POLICY_BRIDGE_KEYWORD].UpdateTREndpoint(ep)
	}

	klog.Warningf("Endpoint %s(uuid: %s) connected policy bridge %s doesn't managed by everoute, skip process it", ep.InterfaceName, ep.InterfaceUUID, ep.BridgeName)
	return nil
}

func (dm *DpManager) mustRemountTRNic(ep *Endpoint) {
	ifaceID := ep.IfaceID
	for v, tr := range dm.Config.TRConfig {
		b := dm.Config.ManagedVDSMap[v]
		if tr.NicOut == ifaceID {
			klog.Infof("Endpoint %s(uuid: %s) with ifaceID %s is policy bridge %s-policy tr egress nic, begin to mount to policy bridge",
				ep.InterfaceName, ep.InterfaceUUID, ifaceID, b)
			action.MustMountTRNic(b, ep.InterfaceName, ifaceID, types.NicOut)
			return
		}
		if tr.NicIn == ifaceID {
			klog.Infof("Endpoint %s(uuid: %s) with ifaceID %s is policy bridge %s-policy tr ingress nic, begin to mount to policy bridge",
				ep.InterfaceName, ep.InterfaceUUID, ifaceID, b)
			action.MustMountTRNic(b, ep.InterfaceName, ifaceID, types.NicIn)
			return
		}
	}

	klog.Infof("Endpoint %s(uuid: %s) with ifaceID %s is not config to policy bridge as tr nic, skip process it", ep.InterfaceName, ep.InterfaceUUID)
}

func (dm *DpManager) UpdateTREndpoint(ep *Endpoint) error {
	klog.Infof("Begin to process tr endpoint %v update", ep)
	if ep.IfaceID == "" {
		klog.Infof("tr endpoint %s(uuid: %s) ifaceID is null, skip process it", ep.InterfaceName, ep.InterfaceUUID)
		return nil
	}
	if ep.BridgeName == trconst.SvcChainBridgeName {
		return nil
	}

	localBridge, ok := strings.CutSuffix(ep.BridgeName, PolicyBridgeSuffix)
	if !ok {
		klog.Warningf("tr endpoint %v doesn't connect policy bridge or svcchain bridge", ep)
		return nil
	}
	for vdsID, ovsbrname := range dm.Config.ManagedVDSMap {
		if localBridge != ovsbrname {
			continue
		}
		return dm.BridgeChainMap[vdsID][POLICY_BRIDGE_KEYWORD].UpdateTREndpoint(ep)
	}

	klog.Warningf("Endpoint %s(uuid: %s) connected policy bridge %s doesn't managed by everoute, skip process it", ep.InterfaceName, ep.InterfaceUUID, ep.BridgeName)
	return nil
}

func (dm *DpManager) DeleteTREndpoint(ep *Endpoint) error {
	klog.Infof("Begin to process tr endpoint %v delete", ep)
	if ep.IfaceID == "" {
		klog.Infof("tr endpoint %s(uuid: %s) ifaceID is null, skip process it", ep.InterfaceName, ep.InterfaceUUID)
		return nil
	}
	if ep.BridgeName == trconst.SvcChainBridgeName {
		return nil
	}

	localBridge, ok := strings.CutSuffix(ep.BridgeName, PolicyBridgeSuffix)
	if !ok {
		klog.Warningf("tr endpoint %v doesn't connect policy bridge or svcchain bridge", ep)
		return nil
	}
	for vdsID, ovsbrname := range dm.Config.ManagedVDSMap {
		if localBridge != ovsbrname {
			continue
		}
		return dm.BridgeChainMap[vdsID][POLICY_BRIDGE_KEYWORD].DeleteTREndpoint(ep)
	}

	klog.Warningf("Endpoint %s(uuid: %s) connected policy bridge %s doesn't managed by everoute, skip process it", ep.InterfaceName, ep.InterfaceUUID, ep.BridgeName)
	return nil
}

func (dm *DpManager) ProcessDPIHealthyStatus(s types.DPIStatus) {
	dm.lockflowReplayWithTimeout()
	defer dm.flowReplayMutex.Unlock()

	if !dm.IsEnableTR() {
		return
	}

	dpiHealthy := s.ToHealthy()
	for k := range dm.Config.TRConfig {
		dm.BridgeChainMap[k][POLICY_BRIDGE_KEYWORD].UpdateDPIHealthy(dpiHealthy)
	}
	klog.Infof("Success process dpi Healthy status %s(healthy: %s)", s, dpiHealthy)
}
