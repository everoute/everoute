package datapath

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"

	trconst "github.com/everoute/everoute/pkg/constants/tr"
	"github.com/everoute/everoute/pkg/trafficredirect/action"
	"github.com/everoute/everoute/pkg/types"
	"github.com/everoute/everoute/pkg/utils"
)

const (
	TRModuleName = "trafficredirect"
)

type DPTRRuleSpec struct {
	SrcMac string
	DstMac string
	Direct DPDirect
}

func (s *DPTRRuleSpec) Valid() error {
	if s.SrcMac == "" && s.DstMac == "" {
		return fmt.Errorf("rule must set srcMac or dstMac")
	}

	if s.Direct != DirEgress && s.Direct != DirIngress {
		return fmt.Errorf("invalid direct %d", s.Direct)
	}
	return nil
}

type DPTRRule struct {
	DPTRRuleSpec
	// key 是 vds
	FlowIDs map[string]uint64
	// 关联的 TrafficRedirectRule CR namespace/name
	Refs sets.Set[string]
}

func (d *DPTRRule) DeepCopy() *DPTRRule {
	res := &DPTRRule{
		DPTRRuleSpec: DPTRRuleSpec{
			SrcMac: d.SrcMac,
			DstMac: d.DstMac,
			Direct: d.Direct,
		},
		Refs:    d.Refs.Clone(),
		FlowIDs: make(map[string]uint64),
	}

	for k, v := range d.FlowIDs {
		res.FlowIDs[k] = v
	}
	return res
}

func (s DPTRRuleSpec) genTRRuleID() string {
	return utils.HashName(20, s)
}

func IsTREndpoint(endpoint *Endpoint) bool {
	if endpoint.BridgeName == trconst.SvcChainBridgeName {
		return true
	}
	if strings.HasSuffix(endpoint.BridgeName, PolicyBridgeSuffix) {
		return true
	}
	return false
}

func NewTRFlowIDAlloctor() *FlowIDAlloctor {
	return NewFlowIDAlloctor(TRModuleName, trconst.FlowIDRuleBegin, trconst.FlowIDRuleEnd, trconst.FlowIDPrefix)
}

func (dm *DpManager) GetTRNicFlowID(roundNumber uint64) uint64 {
	return dm.FlowIDAlloctorForTR.AssemblyFlowID(roundNumber, trconst.FlowIDForTRNicSuffix)
}

func (dm *DpManager) GetTRHealthyFlowID(roundNumber uint64) uint64 {
	return dm.FlowIDAlloctorForTR.AssemblyFlowID(roundNumber, trconst.FlowIDForHealthySuffix)
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
	klog.Infof("Success process dpi Healthy status %s(healthy: %v)", s, dpiHealthy)
}

func (dm *DpManager) AddTRRule(ctx context.Context, spec *DPTRRuleSpec, k string) error {
	log := ctrl.LoggerFrom(ctx, "dpRule", *spec)
	if err := spec.Valid(); err != nil {
		log.Error(err, "dpRule is invalid")
		return err
	}
	dm.lockflowReplayWithTimeout()
	defer dm.flowReplayMutex.Unlock()
	if !dm.IsBridgesConnected() {
		dm.WaitForBridgeConnected()
	}

	id := spec.genTRRuleID()
	cur := dm.TRRules[id]
	if cur != nil {
		if cur.Refs == nil {
			cur.Refs = sets.New[string]()
		}
		cur.Refs.Insert(k)
		// should check flow has add to each vds when support multi vds in future
		log.Info("flow for rule has been add, skip")
		return nil
	}

	seqID, err := dm.FlowIDAlloctorForTR.Allocate()
	if err != nil {
		log.Error(err, "Failed to allocate seq id")
		return err
	}
	dpRule := DPTRRule{
		DPTRRuleSpec: *spec,
		Refs:         sets.New[string](k),
		FlowIDs:      make(map[string]uint64),
	}
	ctx = ctrl.LoggerInto(ctx, log)
	for vds := range dm.Config.TRConfig {
		fid, err := dm.BridgeChainMap[vds][POLICY_BRIDGE_KEYWORD].AddTRRule(ctx, spec, seqID)
		if err != nil {
			return err
		}
		dpRule.FlowIDs[vds] = fid
		dm.FlowIDToTRRules[fid] = &dpRule
	}
	dm.TRRules[id] = &dpRule
	return nil
}

func (dm *DpManager) DelTRRule(ctx context.Context, oldSpec *DPTRRuleSpec, k string) error {
	log := ctrl.LoggerFrom(ctx, "oldDpRule", *oldSpec)
	dm.lockflowReplayWithTimeout()
	defer dm.flowReplayMutex.Unlock()
	if !dm.IsBridgesConnected() {
		dm.WaitForBridgeConnected()
	}

	id := oldSpec.genTRRuleID()
	cur := dm.TRRules[id]
	if cur == nil {
		log.Info("flow for rule has been deleted, skip")
		return nil
	}

	var errs []error
	var delFlowIDs, resFlowIDs []uint64
	defer func() {
		dm.FlowIDAlloctorForTR.Release(ctx, delFlowIDs, resFlowIDs)
	}()
	ctx = ctrl.LoggerInto(ctx, log)
	if len(cur.Refs) == 0 {
		log.Info("old rule doesn't associated any TRRules")
		if len(cur.FlowIDs) == 0 {
			delete(dm.TRRules, id)
			log.Info("flow for rule has been deleted, only delete it from dp cache")
			return nil
		}
		for vds, fid := range cur.FlowIDs {
			if err := dm.BridgeChainMap[vds][POLICY_BRIDGE_KEYWORD].DeleteTRRuleFlow(ctx, &cur.DPTRRuleSpec, fid); err != nil {
				errs = append(errs, err)
				resFlowIDs = append(resFlowIDs, fid)
				continue
			}
			delete(dm.FlowIDToTRRules, fid)
			delFlowIDs = append(delFlowIDs, fid)
		}
		if len(errs) > 0 {
			return errors.Join(errs...)
		}
		delete(dm.TRRules, id)
		return nil
	}

	if !cur.Refs.Has(k) {
		log.Info("old rule doesn't associated current trrule, skip")
		return nil
	}

	otherRefs := cur.Refs.Clone().Delete(k)
	if len(otherRefs) != 0 {
		log.Info("old rule has associated other TRRules, skip delete flow", "otherTRRules", otherRefs)
		cur.Refs.Delete(k)
		return nil
	}

	log.Info("old rule only associated current TRRule, should delete flow")
	for vds, fid := range cur.FlowIDs {
		if err := dm.BridgeChainMap[vds][POLICY_BRIDGE_KEYWORD].DeleteTRRuleFlow(ctx, &cur.DPTRRuleSpec, fid); err != nil {
			errs = append(errs, err)
			resFlowIDs = append(resFlowIDs, fid)
			continue
		}
		delete(dm.FlowIDToTRRules, fid)
		delFlowIDs = append(delFlowIDs, fid)
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	delete(dm.TRRules, id)
	return nil
}

func (dm *DpManager) ReplayVDSTRFlow(vdsID string) error {
	var errs error
	for ruleID, entry := range dm.TRRules {
		// Add new policy rule flow to datapath
		seqID, err := dm.getSeqIDForReplayTRRule(vdsID, entry)
		if err != nil {
			errs = errors.Join(errs, err)
			continue
		}
		flowID, err := dm.BridgeChainMap[vdsID][POLICY_BRIDGE_KEYWORD].AddTRRule(context.Background(), &entry.DPTRRuleSpec, seqID)
		if err != nil {
			errs = errors.Join(errs,
				fmt.Errorf("failed to add TRRule to vdsID %v, bridge %s, error: %v",
					vdsID, dm.BridgeChainMap[vdsID][POLICY_BRIDGE_KEYWORD].GetName(), err))
			continue
		}

		// udpate new tr rule flow to datapath flow cache
		dm.TRRules[ruleID].FlowIDs[vdsID] = flowID

		// update new flowID to flowID map
		dm.FlowIDToTRRules[flowID] = entry
	}

	return errs
}

func (dm *DpManager) getSeqIDForReplayTRRule(vdsID string, entry *DPTRRule) (uint32, error) {
	if entry.FlowIDs[vdsID] != 0 {
		seqID, err := dm.FlowIDAlloctorForTR.GetSeqIDByFlowID(entry.FlowIDs[vdsID])
		if err == nil {
			return seqID, nil
		}
		klog.Errorf("Failed to get TRRule seqID from flowID, allocate another one, err: %s", err)
	}
	return dm.FlowIDAlloctorForTR.Allocate()
}

func (dm *DpManager) GetTRRulesByFlowIDs(fids ...uint64) []*DPTRRule {
	dm.lockRflowReplayWithTimeout()
	defer dm.flowReplayMutex.RUnlock()
	res := []*DPTRRule{}
	for _, fid := range fids {
		r := dm.FlowIDToTRRules[fid]
		if r == nil {
			continue
		}
		res = append(res, r.DeepCopy())
	}
	return res
}

func (dm *DpManager) GetTRRulesByRuleKeys(ks ...string) []*DPTRRule {
	dm.lockRflowReplayWithTimeout()
	defer dm.flowReplayMutex.RUnlock()

	if len(ks) == 0 {
		return nil
	}

	res := []*DPTRRule{}
	for i := range dm.TRRules {
		if dm.TRRules[i] == nil {
			continue
		}
		if dm.TRRules[i].Refs.HasAny(ks...) {
			res = append(res, dm.TRRules[i].DeepCopy())
		}
	}
	return res
}
