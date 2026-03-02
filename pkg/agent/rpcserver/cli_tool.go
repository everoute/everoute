package rpcserver

import (
	"context"
	"fmt"
	"runtime/debug"
	"strconv"

	emptypb "google.golang.org/protobuf/types/known/emptypb"
	"k8s.io/klog/v2"

	ctrlProxy "github.com/everoute/everoute/pkg/agent/controller/proxy"
	"github.com/everoute/everoute/pkg/agent/datapath"
	"github.com/everoute/everoute/pkg/apis/rpc/v1alpha1"
)

var _ v1alpha1.CLIServer = &CLITool{}

type CLITool struct {
	dpManager  *datapath.DpManager
	proxyCache *ctrlProxy.Cache
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

func NewCLIToolServer(datapathManager *datapath.DpManager, proxyCache *ctrlProxy.Cache) *CLITool {
	s := &CLITool{
		dpManager:  datapathManager,
		proxyCache: proxyCache,
	}

	return s
}
