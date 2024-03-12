package rpcserver

import (
	"context"
	"fmt"
	"strconv"

	"google.golang.org/protobuf/types/known/emptypb"

	ctrlProxy "github.com/everoute/everoute/pkg/agent/controller/proxy"
	"github.com/everoute/everoute/pkg/agent/datapath"
	"github.com/everoute/everoute/pkg/apis/rpc/v1alpha1"
)

type Getter struct {
	dpManager  *datapath.DpManager
	proxyCache *ctrlProxy.Cache
}

func (g *Getter) GetAllRules(context.Context, *emptypb.Empty) (*v1alpha1.RuleEntries, error) {
	rules := g.dpManager.GetAllRules()
	return &v1alpha1.RuleEntries{RuleEntries: rules}, nil
}

func (g *Getter) GetRulesByName(ctx context.Context, ruleIDs *v1alpha1.RuleIDs) (*v1alpha1.RuleEntries, error) {
	rules := g.dpManager.GetRulesByRuleIDs(ruleIDs.RuleIDs...)
	return &v1alpha1.RuleEntries{RuleEntries: rules}, nil
}

func (g *Getter) GetRulesByFlow(ctx context.Context, flowIDs *v1alpha1.FlowIDs) (*v1alpha1.RuleEntries, error) {
	rules := g.dpManager.GetRulesByFlowIDs(flowIDs.FlowIDs...)
	return &v1alpha1.RuleEntries{RuleEntries: rules}, nil
}

func (g *Getter) GetSvcInfoBySvcID(ctx context.Context, svcID *v1alpha1.SvcID) (*v1alpha1.SvcInfo, error) {
	if g.proxyCache == nil {
		return nil, fmt.Errorf("agent doesn't enable proxy feature")
	}
	svc, backends, svcPortNames := g.proxyCache.GetCacheBySvcID(svcID.ID)
	svcCache := &v1alpha1.SvcCache{
		SvcID:                  svc.SvcID,
		SvcType:                string(svc.SvcType),
		ClusterIP:              svc.ClusterIPs,
		SessionAffinity:        string(svc.SessionAffinity),
		SessionAffinityTimeout: svc.SessionAffinityTimeout,
		InternalTrafficPolicy:  string(svc.InternalTrafficPolicy),
		SvcPortResourceNames:   svcPortNames,
	}
	for portName := range svc.Ports {
		svcCache.Ports = append(svcCache.Ports, &v1alpha1.SvcPort{
			Name:     portName,
			Port:     svc.Ports[portName].Port,
			Protocol: string(svc.Ports[portName].Protocol),
		})
	}
	for i := range backends {
		svcCache.Backends = append(svcCache.Backends, &v1alpha1.Backend{
			IP:       backends[i].IP,
			Port:     backends[i].Port,
			Protocol: string(backends[i].Protocol),
			Node:     backends[i].Node,
		})
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
			GroupID:       groupEntries[i].Group.GroupID,
		})
	}

	svcFlow := &v1alpha1.SvcFlow{}
	flowEntries := svcDpCache.GetAllLBFlows()
	for i := range flowEntries {
		svcFlow.LBFlows = append(svcFlow.LBFlows, &v1alpha1.SvcFlowEntry{
			IP:       flowEntries[i].LBIP,
			PortName: flowEntries[i].PortName,
			FlowID:   flowEntries[i].Flow.FlowID,
		})
	}
	affinityEntries := svcDpCache.GetAllSessionAffinityFlows()
	for i := range affinityEntries {
		svcFlow.SessionAffinityFlows = append(svcFlow.SessionAffinityFlows, &v1alpha1.SvcFlowEntry{
			IP:       affinityEntries[i].LBIP,
			PortName: affinityEntries[i].PortName,
			FlowID:   affinityEntries[i].Flow.FlowID,
		})
	}
	for i := range backends {
		dnatKey := backends[i].IP + "-" + strconv.Itoa(int(backends[i].Port)) + "-" + string(backends[i].Protocol)
		backendFlow := natBrs[0].GetSvcIndexCache().GetDnatFlow(dnatKey)
		svcFlow.DnatFlows = append(svcFlow.DnatFlows, &v1alpha1.SvcDnatFlowEntry{
			Backend: &v1alpha1.Backend{
				IP:       backends[i].IP,
				Port:     backends[i].Port,
				Protocol: string(backends[i].Protocol),
			},
			FlowID: backendFlow.FlowID,
		})
	}

	svcInfo.SvcFlow = svcFlow
	return svcInfo, nil
}

func NewGetterServer(datapathManager *datapath.DpManager, proxyCache *ctrlProxy.Cache) *Getter {
	s := &Getter{
		dpManager:  datapathManager,
		proxyCache: proxyCache,
	}

	return s
}
