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

package policy

import (
	"fmt"
	"reflect"
	"runtime/debug"
	"strings"

	"k8s.io/apimachinery/pkg/types"
	"k8s.io/klog/v2"

	policycache "github.com/everoute/everoute/pkg/agent/controller/policy/cache"
	"github.com/everoute/everoute/pkg/agent/datapath"
	securityv1alpha1 "github.com/everoute/everoute/pkg/apis/security/v1alpha1"
	"github.com/everoute/everoute/pkg/constants"
	ertypes "github.com/everoute/everoute/pkg/types"
)

const GroupMembersRscType = "groupMembers"

func NewGroupMembersNotFoundErr(groupName string) error {
	return ertypes.NewRscInCacheNotFoundErr(GroupMembersRscType, types.NamespacedName{Name: groupName})
}

func IsGroupMembersNotFoundErr(e error) bool {
	err, ok := e.(*ertypes.RscInCacheNotFoundErr)
	if !ok {
		return false
	}
	return err.RscType() == GroupMembersRscType
}

func toEveroutePolicyRule(ruleID string, rule *policycache.PolicyRule) *datapath.EveroutePolicyRule {
	ipProtoNo := protocolToInt(rule.IPProtocol)
	ruleAction := getRuleAction(rule.Action)

	var rulePriority int
	switch rule.RuleType {
	case policycache.RuleTypeDefaultRule:
		if rule.Tier == constants.Tier2 {
			rulePriority = constants.NormalPolicyRuleStartPriority + int(rule.PriorityOffset)
		} else {
			rulePriority = constants.DefaultPolicyRulePriority
		}
	case policycache.RuleTypeGlobalDefaultRule:
		rulePriority = constants.GlobalDefaultPolicyRulePriority
	default:
		rulePriority = constants.NormalPolicyRuleStartPriority + int(rule.PriorityOffset)
	}

	everoutePolicyRule := &datapath.EveroutePolicyRule{
		RuleID:      ruleID,
		Priority:    rulePriority,
		SrcIPAddr:   rule.SrcIPAddr,
		DstIPAddr:   rule.DstIPAddr,
		IPProtocol:  ipProtoNo,
		SrcPort:     rule.SrcPort,
		SrcPortMask: rule.SrcPortMask,
		DstPort:     rule.DstPort,
		DstPortMask: rule.DstPortMask,
		Action:      ruleAction,
	}

	return everoutePolicyRule
}

func protocolToInt(ipProtocol string) uint8 {
	var protoNo uint8
	switch ipProtocol {
	case "ICMP":
		protoNo = 1
	case "TCP":
		protoNo = 6
	case "UDP":
		protoNo = 17
	case "IPIP":
		protoNo = 4
	case "VRRP":
		protoNo = 112
	case "":
		protoNo = 0
	default:
		klog.Fatalf("unsupport ipProtocol %s in policyRule", ipProtocol)
	}
	return protoNo
}

func getRuleAction(ruleAction policycache.RuleAction) string {
	var action string
	switch ruleAction {
	case policycache.RuleActionAllow:
		action = "allow"
	case policycache.RuleActionDrop:
		action = "deny"
	default:
		klog.Fatalf("unsupport ruleAction %s in policyrule.", ruleAction)
	}
	return action
}

func getRuleDirection(ruleDir policycache.RuleDirection) uint8 {
	var direction uint8
	switch ruleDir {
	case policycache.RuleDirectionOut:
		direction = 0
	case policycache.RuleDirectionIn:
		direction = 1
	default:
		klog.Fatalf("unsupport ruleDirection %s in policyRule.", ruleDir)
	}
	return direction
}

func getRuleTier(ruleTier string) uint8 {
	var tier uint8
	switch ruleTier {
	case constants.Tier0:
		tier = datapath.POLICY_TIER1
	case constants.Tier1:
		tier = datapath.POLICY_TIER2
	case constants.Tier2:
		tier = datapath.POLICY_TIER3
	case constants.TierECP:
		tier = datapath.POLICY_TIER_ECP
	default:
		debug.PrintStack()
		klog.Fatalf("unsupport ruleTier %s in policyRule.", ruleTier)
	}
	return tier
}

func flowKeyFromRuleName(ruleName string) string {
	// rule name format like: policyname-rulename-namehash-flowkey
	keys := strings.Split(ruleName, "-")
	return keys[len(keys)-1]
}

func ruleIsSame(r1, r2 *policycache.PolicyRule) bool {
	return r1 != nil && r2 != nil && reflect.DeepEqual(r1, r2)
}

func posToMask(pos int) uint16 {
	var ret uint16 = 0xffff
	for i := 16; i > pos; i-- {
		ret <<= 1
	}

	return ret
}

func calPortRangeMask(begin uint16, end uint16, protocol securityv1alpha1.Protocol) []policycache.RulePort {
	var rulePortList []policycache.RulePort

	if begin == 0 && end == 0 {
		return append(rulePortList, policycache.RulePort{
			Protocol: protocol,
			DstPort:  0,
		})
	}

	var pos int
	for begin <= end && begin != 0 {
		// find "1" pos from right
		var temp = begin
		pos = 16
		for {
			if temp%2 == 1 {
				break
			}
			temp >>= 1
			pos--
		}
		// check from pos to end
		for i := pos; i <= 16; i++ {
			if end >= begin+(1<<(16-i))-1 {
				rulePortList = append(rulePortList, policycache.RulePort{
					Protocol:    protocol,
					DstPort:     begin,
					DstPortMask: posToMask(i),
				})
				begin += 1 << (16 - i)
				break
			}
		}
	}
	return rulePortList
}

func processFlattenPorts(portMap [65536]bool, protocol securityv1alpha1.Protocol) []policycache.RulePort {
	var rulePortList []policycache.RulePort
	// generate port with mask
	begin := -1
	end := -1
	for index, port := range portMap {
		// mark begin pos
		if port && begin == -1 {
			begin = index
		}
		// mask end pos at the last element
		if port && begin != -1 && index == len(portMap)-1 {
			end = index
		}
		// mask end pos at the end of each port range
		if !port && begin != -1 {
			end = index - 1
		}
		// calculate rule
		if begin != -1 && end != -1 {
			rulePortList = append(rulePortList, calPortRangeMask(uint16(begin), uint16(end), protocol)...)
			begin = -1
			end = -1
		}
	}
	return rulePortList
}

func FlattenPorts(ports []securityv1alpha1.SecurityPolicyPort) ([]policycache.RulePort, error) {
	// empty Ports matches all ports
	if len(ports) == 0 {
		return []policycache.RulePort{{}}, nil
	}

	var rulePortList []policycache.RulePort
	var portMapTCP [65536]bool
	var portMapUDP [65536]bool
	var portlessProtocol = make(map[securityv1alpha1.Protocol]bool, 0)

	for _, port := range ports {
		if port.Protocol != securityv1alpha1.ProtocolTCP && port.Protocol != securityv1alpha1.ProtocolUDP {
			// ignore port when Protocol neither TCP nor UDP
			portlessProtocol[port.Protocol] = true
			continue
		}

		if port.Type == securityv1alpha1.PortTypeName {
			portNameList := strings.Split(port.PortRange, ",")
			for _, portName := range portNameList {
				rulePortList = append(rulePortList, policycache.RulePort{
					DstPortName: portName,
					Protocol:    port.Protocol,
				})
			}
			continue
		}

		// Split port range to multiple port range, e.g. "22,80-82" to ["22","80-82"]
		portRange := strings.Split(port.PortRange, ",")

		for _, subPortRange := range portRange {
			begin, end, err := policycache.UnmarshalPortRange(subPortRange)
			if err != nil {
				return nil, fmt.Errorf("portrange %s unavailable: %s", subPortRange, err)
			}

			if port.Protocol == securityv1alpha1.ProtocolTCP {
				// If defined portNumber as type uint16 here, an infinite loop will occur when end is
				// 65535 (uint16 value will never bigger than 65535, for condition would always true).
				// So we defined portNumber as type int here.
				for portNumber := int(begin); portNumber <= int(end); portNumber++ {
					portMapTCP[portNumber] = true
				}
			}

			if port.Protocol == securityv1alpha1.ProtocolUDP {
				for portNumber := int(begin); portNumber <= int(end); portNumber++ {
					portMapUDP[portNumber] = true
				}
			}
		}
	}
	rulePortList = append(rulePortList, processFlattenPorts(portMapTCP, securityv1alpha1.ProtocolTCP)...)
	rulePortList = append(rulePortList, processFlattenPorts(portMapUDP, securityv1alpha1.ProtocolUDP)...)

	// add portless protocol to rulePortList
	for protocol := range portlessProtocol {
		rulePortList = append(rulePortList, policycache.RulePort{
			Protocol: protocol,
		})
	}

	return rulePortList, nil
}

func toRuleMap(ruleList []policycache.PolicyRule) map[string]*policycache.PolicyRule {
	var ruleMap = make(map[string]*policycache.PolicyRule, len(ruleList))
	for item, rule := range ruleList {
		if _, ok := ruleMap[rule.Name]; !ok {
			ruleMap[rule.Name] = &ruleList[item]
		}
	}
	return ruleMap
}
