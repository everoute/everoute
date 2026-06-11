package rpcserver

import (
	"context"
	"fmt"
	"runtime/debug"
	"strconv"

	emptypb "google.golang.org/protobuf/types/known/emptypb"
	"k8s.io/klog/v2"

	policyctrl "github.com/everoute/everoute/pkg/agent/controller/policy"
	ctrlProxy "github.com/everoute/everoute/pkg/agent/controller/proxy"
	"github.com/everoute/everoute/pkg/agent/datapath"
	"github.com/everoute/everoute/pkg/apis/rpc/v1alpha1"
)

var _ v1alpha1.CLIServer = &CLITool{}

type CLITool struct {
	dpManager         *datapath.DpManager
	proxyCache        *ctrlProxy.Cache
	pprofSwitch       *PprofSwitch
	policyGuardSetter policyctrl.GuardRuntimeSetter
}

func (g *CLITool) GetAllRules(req *v1alpha1.StreamRulesRequest, sendFunc v1alpha1.CLI_GetAllRulesServer) error {
	return g.dpManager.GetAllRules(sendFunc.Send, int(req.BatchSize))
}

func (g *CLITool) GetRulesByName(_ context.Context, ruleIDs *v1alpha1.RuleIDs) (*v1alpha1.RuleEntries, error) {
	rules := g.dpManager.GetRulesByRuleIDs(ruleIDs.RuleIDs...)
	return &v1alpha1.RuleEntries{RuleEntries: rules}, nil
}

func (g *CLITool) GetRulesByFlow(_ context.Context, flowIDs *v1alpha1.FlowIDs) (*v1alpha1.RuleEntries, error) {
	rules := g.dpManager.GetRulesByFlowIDs(flowIDs.FlowIDs...)
	return &v1alpha1.RuleEntries{RuleEntries: rules}, nil
}

func (g *CLITool) GetSvcInfoBySvcID(_ context.Context, svcID *v1alpha1.SvcID) (*v1alpha1.SvcInfo, error) {
	if g.proxyCache == nil {
		return nil, fmt.Errorf("agent doesn't enable proxy feature")
	}
	svcLBs, backends, svcPortNames := g.proxyCache.GetCacheBySvcID(svcID.ID)
	svcCache := &v1alpha1.SvcCache{
		SvcID:        svcID.ID,
		SvcPortNames: svcPortNames,
		SvcLBs:       make([]*v1alpha1.SvcLB, len(svcLBs)),
		Backends:     make([]*v1alpha1.Backend, len(backends)),
	}
	for i := range svcLBs {
		svcCache.SvcLBs[i] = &v1alpha1.SvcLB{
			IP:                     svcLBs[i].IP,
			PortName:               svcLBs[i].Port.Name,
			Port:                   svcLBs[i].Port.Port,
			Protocol:               string(svcLBs[i].Port.Protocol),
			NodePort:               svcLBs[i].Port.NodePort,
			TrafficPolicy:          string(svcLBs[i].TrafficPolicy),
			SessionAffinity:        string(svcLBs[i].SessionAffinity),
			SessionAffinityTimeout: svcLBs[i].SessionAffinityTimeout,
		}
	}
	for i := range backends {
		svcCache.Backends[i] = &v1alpha1.Backend{
			IP:       backends[i].IP,
			Port:     backends[i].Port,
			Protocol: string(backends[i].Protocol),
			Node:     backends[i].Node,
		}
	}

	svcInfo := &v1alpha1.SvcInfo{SvcCache: svcCache}

	natBrs := g.dpManager.GetNatBridges()
	if len(natBrs) == 0 {
		return svcInfo, fmt.Errorf("there is no nat bridge")
	}
	svcDpCache := natBrs[0].GetSvcIndexCache().GetSvcOvsInfo(svcID.ID)
	groupEntries := svcDpCache.GetAllGroups()
	for i := range groupEntries {
		svcInfo.SvcGroup = append(svcInfo.SvcGroup, &v1alpha1.SvcGroup{
			PortName:      groupEntries[i].PortName,
			TrafficPolicy: string(groupEntries[i].TrafficPolicy),
			GroupID:       groupEntries[i].GroupID,
		})
	}

	svcFlow := &v1alpha1.SvcFlow{}
	flowEntries := svcDpCache.GetAllLBFlows()
	for i := range flowEntries {
		svcFlow.LBFlows = append(svcFlow.LBFlows, &v1alpha1.SvcFlowEntry{
			IP:       flowEntries[i].LBIP,
			PortName: flowEntries[i].PortName,
			FlowID:   flowEntries[i].FlowID,
		})
	}
	affinityEntries := svcDpCache.GetAllSessionAffinityFlows()
	for i := range affinityEntries {
		svcFlow.SessionAffinityFlows = append(svcFlow.SessionAffinityFlows, &v1alpha1.SvcFlowEntry{
			IP:       affinityEntries[i].LBIP,
			PortName: affinityEntries[i].PortName,
			FlowID:   affinityEntries[i].FlowID,
		})
	}
	for i := range backends {
		dnatKey := backends[i].IP + "-" + strconv.Itoa(int(backends[i].Port)) + "-" + string(backends[i].Protocol)
		backendFlowID := natBrs[0].GetSvcIndexCache().GetDnatFlow(dnatKey)
		svcFlow.DnatFlows = append(svcFlow.DnatFlows, &v1alpha1.SvcDnatFlowEntry{
			Backend: &v1alpha1.Backend{
				IP:       backends[i].IP,
				Port:     backends[i].Port,
				Protocol: string(backends[i].Protocol),
			},
			FlowID: backendFlowID,
		})
	}

	svcInfo.SvcFlow = svcFlow
	return svcInfo, nil
}

func (g *CLITool) GetTRRulesByFlowIDs(_ context.Context, in *v1alpha1.FlowIDs) (*v1alpha1.TRRules, error) {
	fids := in.FlowIDs
	dpRules := g.dpManager.GetTRRulesByFlowIDs(fids...)
	return &v1alpha1.TRRules{TRRules: trRulesDpToRPC(dpRules)}, nil
}

func (g *CLITool) GetTRRulesByRuleKeys(_ context.Context, in *v1alpha1.TRRuleKeys) (*v1alpha1.TRRules, error) {
	ks := in.TRRuleKeys
	dpRules := g.dpManager.GetTRRulesByRuleKeys(ks...)
	return &v1alpha1.TRRules{TRRules: trRulesDpToRPC(dpRules)}, nil
}

func (g *CLITool) GetGOMemLimit(context.Context, *emptypb.Empty) (*v1alpha1.GetGOMemLimitResponse, error) {
	return &v1alpha1.GetGOMemLimitResponse{
		Limit: debug.SetMemoryLimit(-1),
	}, nil
}

func (g *CLITool) SetGOMemLimit(_ context.Context, in *v1alpha1.SetGOMemLimitRequest) (*v1alpha1.SetGOMemLimitResponse, error) {
	newL := in.GetLimit()
	if newL <= 0 {
		return nil, fmt.Errorf("invalid memory limit: %d", newL)
	}
	prevL := debug.SetMemoryLimit(newL)
	curL := debug.SetMemoryLimit(-1)
	klog.Infof("Set Go memory limit, prev: %d, new: %d, current: %d", prevL, newL, curL)
	return &v1alpha1.SetGOMemLimitResponse{
		PrevLimit:    prevL,
		CurrentLimit: curL,
	}, nil
}

func (g *CLITool) GetPolicyRuleEstimateLimit(context.Context, *emptypb.Empty) (*v1alpha1.GetPolicyRuleEstimateLimitResponse, error) {
	if g.policyGuardSetter == nil {
		return nil, fmt.Errorf("policy guard is not available")
	}
	return &v1alpha1.GetPolicyRuleEstimateLimitResponse{
		Limit: g.policyGuardSetter.GetRuleEstimateLimit(),
	}, nil
}

func (g *CLITool) SetPolicyMemoryThreshold(_ context.Context,
	in *v1alpha1.SetPolicyMemoryThresholdRequest) (*v1alpha1.SetPolicyMemoryThresholdResponse, error) {
	if g.policyGuardSetter == nil {
		return nil, fmt.Errorf("policy guard is not available")
	}
	prevThreshold, curThreshold := g.policyGuardSetter.SetMemoryThreshold(in.GetThreshold())
	klog.Infof("Set policy memory guard threshold, prev: %d, current: %d", prevThreshold, curThreshold)
	return &v1alpha1.SetPolicyMemoryThresholdResponse{
		PrevThreshold:    prevThreshold,
		CurrentThreshold: curThreshold,
	}, nil
}

func (g *CLITool) SetPolicyRuleEstimateLimit(_ context.Context,
	in *v1alpha1.SetPolicyRuleEstimateLimitRequest) (*v1alpha1.SetPolicyRuleEstimateLimitResponse, error) {
	if g.policyGuardSetter == nil {
		return nil, fmt.Errorf("policy guard is not available")
	}
	prevLimit, curLimit := g.policyGuardSetter.SetRuleEstimateLimit(in.GetLimit())
	klog.Infof("Set policy rule estimate limit, prev: %d, current: %d", prevLimit, curLimit)
	return &v1alpha1.SetPolicyRuleEstimateLimitResponse{
		PrevLimit:    prevLimit,
		CurrentLimit: curLimit,
	}, nil
}

func (g *CLITool) SetPolicyGuardEnabled(_ context.Context,
	in *v1alpha1.SetPolicyGuardEnabledRequest) (*v1alpha1.SetPolicyGuardEnabledResponse, error) {
	if g.policyGuardSetter == nil {
		return nil, fmt.Errorf("policy guard is not available")
	}
	prevEnabled, currentEnabled, err := g.policyGuardSetter.SetGuardEnabled(in.GetGuard(), in.GetEnabled())
	if err != nil {
		return nil, err
	}
	klog.Infof("Set policy guard enabled, guard: %s, prev: %t, current: %t",
		in.GetGuard(), prevEnabled, currentEnabled)
	return &v1alpha1.SetPolicyGuardEnabledResponse{
		Guard:          in.GetGuard(),
		PrevEnabled:    prevEnabled,
		CurrentEnabled: currentEnabled,
	}, nil
}

func (g *CLITool) GetPolicyGuardStatus(context.Context, *emptypb.Empty) (*v1alpha1.PolicyGuardStatus, error) {
	if g.policyGuardSetter == nil {
		return nil, fmt.Errorf("policy guard is not available")
	}
	status := g.policyGuardSetter.GetGuardStatus()
	return &v1alpha1.PolicyGuardStatus{
		MemoryEnabled:     status.MemoryEnabled,
		MemoryBreakerOpen: status.MemoryBreakerOpen,
		MemoryThreshold:   status.MemoryThreshold,
		RuleEnabled:       status.RuleEnabled,
		RuleEstimateLimit: status.RuleEstimateLimit,
	}, nil
}

func (g *CLITool) EnablePprof(context.Context, *emptypb.Empty) (*v1alpha1.PprofStatus, error) {
	g.pprofSwitch.Enable()
	klog.Infof("Enabled pprof handler on %s", PprofPath)
	return g.pprofStatus(), nil
}

func (g *CLITool) DisablePprof(context.Context, *emptypb.Empty) (*v1alpha1.PprofStatus, error) {
	g.pprofSwitch.Disable()
	klog.Infof("Disabled pprof handler on %s", PprofPath)
	return g.pprofStatus(), nil
}

func (g *CLITool) GetPprofStatus(context.Context, *emptypb.Empty) (*v1alpha1.PprofStatus, error) {
	return g.pprofStatus(), nil
}

func (g *CLITool) pprofStatus() *v1alpha1.PprofStatus {
	return &v1alpha1.PprofStatus{
		Enabled: g.pprofSwitch.Enabled(),
		URL:     g.pprofSwitch.URL(),
	}
}

func trRulesDpToRPC(dpRules []*datapath.DPTRRule) []*v1alpha1.TRRule {
	res := []*v1alpha1.TRRule{}
	for i := range dpRules {
		if dpRules[i] == nil {
			continue
		}
		res = append(res, &v1alpha1.TRRule{
			SrcMac:  dpRules[i].SrcMac,
			DstMac:  dpRules[i].DstMac,
			Direct:  dpRules[i].Direct.String(),
			FlowIDs: dpRules[i].FlowIDs,
			Refs:    dpRules[i].Refs.UnsortedList(),
		})
	}
	return res
}

func NewCLIToolServer(datapathManager *datapath.DpManager, proxyCache *ctrlProxy.Cache, pprofSwitch *PprofSwitch,
	policyGuardSetter policyctrl.GuardRuntimeSetter) *CLITool {
	s := &CLITool{
		dpManager:         datapathManager,
		proxyCache:        proxyCache,
		pprofSwitch:       pprofSwitch,
		policyGuardSetter: policyGuardSetter,
	}

	return s
}
