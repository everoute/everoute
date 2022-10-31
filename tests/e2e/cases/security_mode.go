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

package cases

import (
	"fmt"
	"net"
	"strings"

	"k8s.io/klog"

	policyagent "github.com/everoute/everoute/pkg/agent/controller/policy"
	"github.com/everoute/everoute/pkg/agent/controller/policy/cache"
	securityv1alpha1 "github.com/everoute/everoute/pkg/apis/security/v1alpha1"
	"github.com/everoute/everoute/pkg/constants"
	"github.com/everoute/everoute/pkg/labels"
	"github.com/everoute/everoute/tests/e2e/framework/model"
)

type SecurityModel struct {
	Policies  []*securityv1alpha1.SecurityPolicy
	Endpoints []*model.Endpoint
}

// ExpectedRelativeFlows compute only expected open flows which relative with per endpoint by security model.
// It returns a map from a host name to some flows, and asserts the host name is same as the agent name.
func (m *SecurityModel) ExpectedRelativeFlows() map[string][]string {
	var allFlows = make(map[string][]string)
	for _, ep := range m.Endpoints {
		var flows []string
		name := ep.Status.Host
		ip := func() string {
			ipAddr, _, _ := net.ParseCIDR(ep.Status.IPAddr)
			return ipAddr.String()
		}()

		for _, policy := range m.Policies {
			flows = append(flows, m.collectPolicyFlowsByIP(policy, ip)...)
		}

		allFlows[name] = append(allFlows[name], flows...)
	}
	return allFlows
}

// NewEmptyTruthTable returned endpoint TruthTable with defaultExpectation.
// It could used to build expected TruthTable.
func (m *SecurityModel) NewEmptyTruthTable(defaultExpectation bool) *model.TruthTable {
	var epList []string

	for _, ep := range m.Endpoints {
		epList = append(epList, ep.Name)
	}

	return model.NewTruthTableFromItems(epList, &defaultExpectation)
}

// The specific implementation of the collectPolicyFlows
func (m *SecurityModel) collectPolicyFlowsByIP(policy *securityv1alpha1.SecurityPolicy, appliedIP string) []string {
	var ingressIPs, egressIPs []string
	var ingressPorts, egressPorts []cache.RulePort

	applied := func() bool {
		for _, appliedPeer := range policy.Spec.AppliedTo {
			var appliedEndpoint *securityv1alpha1.NamespacedName
			if appliedPeer.Endpoint != nil {
				appliedEndpoint = &securityv1alpha1.NamespacedName{
					Name:      *appliedPeer.Endpoint,
					Namespace: policy.GetNamespace(),
				}
			}
			peerIPs := m.getPeerIPs(&securityv1alpha1.SecurityPolicyPeer{
				Endpoint:         appliedEndpoint,
				EndpointSelector: appliedPeer.EndpointSelector,
			})
			for _, peerIP := range peerIPs {
				if appliedIP == peerIP {
					return true
				}
			}
		}
		return false
	}()

	if !applied {
		return nil
	}

	for _, rule := range policy.Spec.IngressRules {
		for index := range rule.From {
			ingressIPs = append(ingressIPs, m.getPeerIPs(&rule.From[index])...)
		}

		rulePorts, err := policyagent.FlattenPorts(rule.Ports)
		if err != nil {
			klog.Fatalf("failed to flatten ports: %s", err)
		}
		ingressPorts = append(ingressPorts, rulePorts...)
	}

	for _, rule := range policy.Spec.EgressRules {
		for index := range rule.To {
			egressIPs = append(egressIPs, m.getPeerIPs(&rule.To[index])...)
		}

		rulePorts, err := policyagent.FlattenPorts(rule.Ports)
		if err != nil {
			klog.Fatalf("failed to flatten ports: %s", err)
		}
		egressPorts = append(egressPorts, rulePorts...)
	}
	return computePolicyFlow(policy.Spec.Tier, policy.Spec.SecurityPolicyEnforcementMode,
		[]string{appliedIP}, ingressIPs, egressIPs, ingressPorts, egressPorts)
}

func (m *SecurityModel) getPeerIPs(peer *securityv1alpha1.SecurityPolicyPeer) []string {
	var matchIPs []string

	matchEp := matchEndpoint(peer, m.Endpoints)
	for _, ep := range matchEp {
		// remove ip mask, e.g. 127.0.0.1/8 => 127.0.0.1
		ip, _, _ := net.ParseCIDR(ep.Status.IPAddr)
		matchIPs = append(matchIPs, ip.String())
	}

	return matchIPs
}

func matchEndpoint(peer *securityv1alpha1.SecurityPolicyPeer, endpoints []*model.Endpoint) []*model.Endpoint {
	var matchEp []*model.Endpoint

	for _, ep := range endpoints {
		labelsSet, _ := labels.AsSet(nil, ep.Labels)
		if peer.EndpointSelector.Matches(labelsSet) {
			matchEp = append(matchEp, ep)
		}
		if peer.Endpoint != nil && peer.Endpoint.Name == ep.Name {
			matchEp = append(matchEp, ep)
		}
	}

	return matchEp
}

func computePolicyFlow(tier string, mode securityv1alpha1.PolicyMode, appliedToIPs, ingressIPs, egressIPs []string, ingressPorts, egressGroupPorts []cache.RulePort) []string {
	var flows []string
	priority := constants.NormalPolicyRulePriority
	ingressTableID, ingressNextTableID, egressTableID, egressNextTableID, err := getTableIds(tier, mode)
	if err != nil {
		klog.Infof("Failed to computePolicyFlow, error: %v", err)
		return nil
	}

	ctLableRange := ""
	if mode == securityv1alpha1.MonitorMode {
		ctLableRange = "32..59"
	} else {
		ctLableRange = "60..87"
	}

	for _, appliedToIP := range appliedToIPs {
		flowsForIP := computePolicyFlowWithIP(appliedToIP, ingressIPs, egressIPs, ingressPorts, egressGroupPorts,
			priority, *ingressTableID, *ingressNextTableID, *egressTableID, *egressNextTableID, ctLableRange)
		flows = append(flows, flowsForIP...)
	}

	return flows
}

func computePolicyFlowWithIP(appliedToIP string, ingressIPs, egressIPs []string, ingressPorts, egressGroupPorts []cache.RulePort,
	priority int, ingressTableID, ingressNextTableID, egressTableID, egressNextTableID int, ctLableRange string) []string {
	var flows []string = nil
	for _, srcIP := range ingressIPs {
		if appliedToIP != "" && srcIP != "" && appliedToIP == srcIP {
			continue
		}
		// Except appliedToIP == srcIP, NOTE error implement in policyrule controller
		for _, ingressGroupPort := range ingressPorts {
			var flow string
			protocol := strings.ToLower(string(ingressGroupPort.Protocol))

			if ingressGroupPort.DstPort == 0 && ingressGroupPort.SrcPort == 0 {
				flow = fmt.Sprintf("table=%d, priority=%d,%s,nw_src=%s,nw_dst=%s actions=load:0x->NXM_NX_XXREG0[%s],load:0x->NXM_NX_XXREG0[0..3],goto_table:%d",
					ingressTableID, priority, protocol, srcIP, appliedToIP, ctLableRange, ingressNextTableID)
			} else if ingressGroupPort.DstPort != 0 {
				flow = fmt.Sprintf("table=%d, priority=%d,%s,nw_src=%s,nw_dst=%s,tp_dst=%d actions=load:0x->NXM_NX_XXREG0[%s],load:0x->NXM_NX_XXREG0[0..3],goto_table:%d",
					ingressTableID, priority, protocol, srcIP, appliedToIP, ingressGroupPort.DstPort, ctLableRange,
					ingressNextTableID)
				if ingressGroupPort.DstPort != 0 && ingressGroupPort.DstPortMask != 0xffff {
					flow = fmt.Sprintf("table=%d, priority=%d,%s,nw_src=%s,nw_dst=%s,tp_dst=0x%x/0x%x actions=load:0x->NXM_NX_XXREG0[%s],load:0x->NXM_NX_XXREG0[0..3],goto_table:%d",
						ingressTableID, priority, protocol, srcIP, appliedToIP, ingressGroupPort.DstPort, ingressGroupPort.DstPortMask, ctLableRange,
						ingressNextTableID)
				}
			}
			flows = append(flows, flow)
		}

		if len(ingressPorts) == 0 {
			flow := fmt.Sprintf("table=%d, priority=%d,ip,nw_src=%s,nw_dst=%s actions=drop", ingressTableID,
				priority, srcIP, appliedToIP)
			flows = append(flows, flow)
		}
	}

	for _, dstIP := range egressIPs {
		if appliedToIP != "" && dstIP != "" && appliedToIP == dstIP {
			continue
		}
		for _, egressGroupPort := range egressGroupPorts {
			var flow string
			protocol := strings.ToLower(string(egressGroupPort.Protocol))

			if egressGroupPort.DstPort == 0 && egressGroupPort.SrcPort == 0 {
				flow = fmt.Sprintf("table=%d, priority=%d,%s,nw_src=%s,nw_dst=%s actions=load:0x->NXM_NX_XXREG0[%s],load:0x->NXM_NX_XXREG0[0..3],goto_table:%d",
					egressTableID, priority, protocol, appliedToIP, dstIP, ctLableRange, egressNextTableID)
			} else if egressGroupPort.DstPort != 0 {
				flow = fmt.Sprintf("table=%d, priority=%d,%s,nw_src=%s,nw_dst=%s,tp_dst=%d actions=load:0x->NXM_NX_XXREG0[%s],load:0x->NXM_NX_XXREG0[0..3],goto_table:%d",
					egressTableID, priority, protocol, appliedToIP, dstIP, egressGroupPort.DstPort, ctLableRange, egressNextTableID)
				if egressGroupPort.DstPort != 0 && egressGroupPort.DstPortMask != 0xffff {
					flow = fmt.Sprintf("table=%d, priority=%d,%s,nw_src=%s,nw_dst=%s,tp_dst=0x%x/0x%x actions=load:0x->NXM_NX_XXREG0[%s],load:0x->NXM_NX_XXREG0[0..3],goto_table:%d",
						ingressTableID, priority, protocol, dstIP, appliedToIP, egressGroupPort.DstPort, egressGroupPort.DstPortMask, ctLableRange,
						egressNextTableID)
				}
			}
			flows = append(flows, flow)
		}

		if len(egressGroupPorts) == 0 {
			flow := fmt.Sprintf("table=%d, priority=%d,ip,nw_src=%s,nw_dst=%s actions=drop", egressTableID,
				priority, appliedToIP, dstIP)
			flows = append(flows, flow)
		}
	}
	return flows
}

func getTableIds(tier string, mode securityv1alpha1.PolicyMode) (*int, *int, *int, *int, error) {
	var ingressTableID, ingressNextTableID, egressTableID, egressNextTableID int
	switch tier {
	case "tier0":
		egressTableID = 20
		egressNextTableID = 70
		ingressTableID = 50
		ingressNextTableID = 70
	case "tier1":
		if mode == securityv1alpha1.MonitorMode {
			egressTableID = 24
			egressNextTableID = 25
			ingressTableID = 54
			ingressNextTableID = 55
		} else {
			egressTableID = 25
			egressNextTableID = 70
			ingressTableID = 55
			ingressNextTableID = 70
		}
	case "tier2":
		if mode == securityv1alpha1.MonitorMode {
			egressTableID = 29
			egressNextTableID = 30
			ingressTableID = 59
			ingressNextTableID = 60
		} else {
			egressTableID = 30
			egressNextTableID = 70
			ingressTableID = 60
			ingressNextTableID = 70
		}
	default:
		return nil, nil, nil, nil, fmt.Errorf("failed to get tableId")
	}

	return &ingressTableID, &ingressNextTableID, &egressTableID, &egressNextTableID, nil
}
