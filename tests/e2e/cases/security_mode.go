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

package cases

import (
	"fmt"
	"net"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/klog"

	groupv1alpha1 "github.com/smartxworks/lynx/pkg/apis/group/v1alpha1"
	securityv1alpha1 "github.com/smartxworks/lynx/pkg/apis/security/v1alpha1"
	"github.com/smartxworks/lynx/pkg/controller/policy/cache"
	"github.com/smartxworks/lynx/tests/e2e/framework/model"
)

type SecurityModel struct {
	Policies  []*securityv1alpha1.SecurityPolicy
	Groups    []*groupv1alpha1.EndpointGroup
	Endpoints []*model.Endpoint
}

// ExpectedFlows compute expected open flows by security model.
func (m *SecurityModel) ExpectedFlows() []string {
	var flows []string
	for _, policy := range m.Policies {
		flows = append(flows, m.collectPolicyFlows(policy)...)
	}
	return flows
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

// fixme: need to deal rule matches all src/dst and default deny rule
func (m *SecurityModel) collectPolicyFlows(policy *securityv1alpha1.SecurityPolicy) []string {
	var appliedIPs, ingressIPs, egressIPs []string
	var ingressPorts, egressPorts []cache.RulePort

	for _, rule := range policy.Spec.IngressRules {
		for _, groupName := range rule.From.EndpointGroups {
			ingressIPs = append(ingressIPs, m.getGroupIPs(groupName)...)
		}

		rulePorts, err := flattenPorts(rule.Ports)
		if err != nil {
			klog.Fatalf("failed to flatten ports: %s", err)
		}
		ingressPorts = append(ingressPorts, rulePorts...)
	}

	for _, rule := range policy.Spec.EgressRules {
		for _, groupName := range rule.To.EndpointGroups {
			egressIPs = append(egressIPs, m.getGroupIPs(groupName)...)
		}

		rulePorts, err := flattenPorts(rule.Ports)
		if err != nil {
			klog.Fatalf("failed to flatten ports: %s", err)
		}
		egressPorts = append(egressPorts, rulePorts...)
	}

	for _, groupName := range policy.Spec.AppliedTo.EndpointGroups {
		appliedIPs = append(appliedIPs, m.getGroupIPs(groupName)...)
	}

	return computePolicyFlow(policy, appliedIPs, ingressIPs, egressIPs, ingressPorts, egressPorts)
}

func (m *SecurityModel) getGroupIPs(groupName string) []string {
	var expectGroup *groupv1alpha1.EndpointGroup
	var matchIPs []string

	for _, group := range m.Groups {
		if group.Name == groupName {
			expectGroup = group
		}
	}
	if expectGroup == nil {
		klog.Fatalf("unexpect group %s not found", groupName)
	}

	matchEp := matchEndpoint(expectGroup, m.Endpoints)
	for _, ep := range matchEp {
		// remove ip mask, e.g. 127.0.0.1/8 => 127.0.0.1
		ip, _, _ := net.ParseCIDR(ep.Status.IPAddr)
		matchIPs = append(matchIPs, ip.String())
	}

	return matchIPs
}

func matchEndpoint(group *groupv1alpha1.EndpointGroup, endpoints []*model.Endpoint) []*model.Endpoint {
	var selector, _ = metav1.LabelSelectorAsSelector(group.Spec.Selector)
	var matchEp []*model.Endpoint

	for _, ep := range endpoints {
		if selector.Matches(labels.Set(ep.Labels)) {
			matchEp = append(matchEp, ep)
		}
	}

	return matchEp
}

func computePolicyFlow(policy *securityv1alpha1.SecurityPolicy, appliedToIPs, ingressIPs, egressIPs []string, ingressPorts, egressGroupPorts []cache.RulePort) []string {
	var flows []string
	priority := policy.Spec.Priority + 10
	ingressTableID, egressTableID := getTableIds(policy.Spec.Tier)

	if ingressTableID == nil || egressTableID == nil {
		return nil
	}
	ingressNextTableID, egressNextTableID := 20, 45

	for _, appliedToIP := range appliedToIPs {
		for _, srcIP := range ingressIPs {
			// Except appliedToIP == srcIP, NOTE error implement in policyrule controller
			for _, ingressGroupPort := range ingressPorts {
				var flow string
				protocol := strings.ToLower(string(ingressGroupPort.Protocol))

				if ingressGroupPort.DstPort == 0 && ingressGroupPort.SrcPort == 0 {
					flow = fmt.Sprintf("table=%d, priority=%d,%s,nw_src=%s,nw_dst=%s actions=goto_table:%d",
						*ingressTableID, priority, protocol, srcIP, appliedToIP, ingressNextTableID)
				} else if ingressGroupPort.DstPort != 0 {
					flow = fmt.Sprintf("table=%d, priority=%d,%s,nw_src=%s,nw_dst=%s,tp_dst=%d actions=goto_table:%d",
						*ingressTableID, priority, protocol, srcIP, appliedToIP, ingressGroupPort.DstPort,
						ingressNextTableID)
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
			for _, egressGroupPort := range egressGroupPorts {
				var flow string
				protocol := strings.ToLower(string(egressGroupPort.Protocol))

				if egressGroupPort.DstPort == 0 && egressGroupPort.SrcPort == 0 {
					flow = fmt.Sprintf("table=%d, priority=%d,%s,nw_src=%s,nw_dst=%s actions=goto_table:%d",
						*egressTableID, priority, protocol, appliedToIP, dstIP, egressNextTableID)
				} else if egressGroupPort.DstPort != 0 {
					flow = fmt.Sprintf("table=%d, priority=%d,%s,nw_src=%s,nw_dst=%s,tp_dst=%d actions=goto_table:%d",
						*egressTableID, priority, protocol, appliedToIP, dstIP, egressGroupPort.DstPort, egressNextTableID)
				}
				flows = append(flows, flow)
			}

			if len(egressGroupPorts) == 0 {
				flow := fmt.Sprintf("table=%d, priority=%d,ip,nw_src=%s,nw_dst=%s actions=drop", egressTableID,
					priority, appliedToIP, dstIP)
				flows = append(flows, flow)
			}
		}
	}

	return flows
}

func flattenPorts(ports []securityv1alpha1.SecurityPolicyPort) ([]cache.RulePort, error) {
	var rulePortList []cache.RulePort
	var rulePortMap = make(map[cache.RulePort]struct{})

	for _, port := range ports {
		if port.Protocol == securityv1alpha1.ProtocolICMP {
			portItem := cache.RulePort{
				Protocol: port.Protocol,
			}
			rulePortMap[portItem] = struct{}{}
			continue
		}

		begin, end, err := cache.UnmarshalPortRange(port.PortRange)
		if err != nil {
			return nil, fmt.Errorf("portrange %s unavailable: %s", port.PortRange, err)
		}

		for portNumber := int(begin); portNumber <= int(end); portNumber++ {
			portItem := cache.RulePort{
				DstPort:  uint16(portNumber),
				Protocol: port.Protocol,
			}
			rulePortMap[portItem] = struct{}{}
		}
	}

	for port := range rulePortMap {
		rulePortList = append(rulePortList, port)
	}

	return rulePortList, nil
}

func getTableIds(tier string) (*int, *int) {
	var ingressTableID, egressTableID int
	switch tier {
	case "tier0":
		ingressTableID = 10
		egressTableID = 30
	case "tier1":
		ingressTableID = 11
		egressTableID = 31
	case "tier2":
		ingressTableID = 12
		egressTableID = 32
	}

	return &ingressTableID, &egressTableID
}
