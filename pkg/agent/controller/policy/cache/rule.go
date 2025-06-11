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

package cache

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"

	securityv1alpha1 "github.com/everoute/everoute/pkg/apis/security/v1alpha1"
	"github.com/everoute/everoute/pkg/constants"
	"github.com/everoute/everoute/pkg/utils"
)

type RuleType string
type RuleAction string
type RuleDirection string

type PolicyType string

const (
	RuleTypeGlobalDefaultRule RuleType = "GlobalDefaultRule"
	RuleTypeDefaultRule       RuleType = "DefaultRule"
	RuleTypeNormalRule        RuleType = "NormalRule"

	RuleActionAllow RuleAction = "Allow"
	RuleActionDrop  RuleAction = "Drop"

	RuleDirectionIn  RuleDirection = "Ingress"
	RuleDirectionOut RuleDirection = "Egress"

	NormalPolicy   PolicyType = "normal"
	GlobalPolicy   PolicyType = "global"
	InternalPolicy PolicyType = "internal"

	BlockReverseRuleNameUnit = ".rev"
)

type PolicyRule struct {
	// Name format policyNamespace/policyName/policyType/ruleName-flowKey
	Name   string     `json:"name"`
	Policy string     `json:"policy"`
	Action RuleAction `json:"action"`

	// match fields
	Direction       RuleDirection `json:"direction"`
	RuleType        RuleType      `json:"ruleType"`
	Tier            string        `json:"tier,omitempty"`
	PriorityOffset  int32         `json:"priorityOffset,omitempty"`
	EnforcementMode string        `json:"enforcementMode,omitempty"`
	SrcIPAddr       string        `json:"srcIPAddr,omitempty"`
	DstIPAddr       string        `json:"dstIPAddr,omitempty"`
	IPProtocol      string        `json:"ipProtocol"`
	IPFamily        uint8         `json:"ipFamily"`
	SrcPort         uint16        `json:"srcPort,omitempty"`
	DstPort         uint16        `json:"dstPort,omitempty"`
	SrcPortMask     uint16        `json:"srcPortMask,omitempty"`
	DstPortMask     uint16        `json:"dstPortMask,omitempty"`
	IcmpType        uint8
	IcmpTypeEnable  bool
}

func (p *PolicyRule) DeepCopy() *PolicyRule {
	return &PolicyRule{
		Name:            p.Name,
		Policy:          p.Policy,
		RuleType:        p.RuleType,
		Tier:            p.Tier,
		PriorityOffset:  p.PriorityOffset,
		EnforcementMode: p.EnforcementMode,
		IPProtocol:      p.IPProtocol,
		IPFamily:        p.IPFamily,
		Action:          p.Action,
		Direction:       p.Direction,
		SrcIPAddr:       p.SrcIPAddr,
		SrcPort:         p.SrcPort,
		SrcPortMask:     p.SrcPortMask,
		DstIPAddr:       p.DstIPAddr,
		DstPort:         p.DstPort,
		DstPortMask:     p.DstPortMask,
		IcmpType:        p.IcmpType,
		IcmpTypeEnable:  p.IcmpTypeEnable,
	}
}

func (p *PolicyRule) IsBlock() bool {
	if p.Action != RuleActionDrop {
		return false
	}

	if p.Tier != constants.Tier2 {
		return false
	}

	return p.RuleType == RuleTypeNormalRule
}

func (p *PolicyRule) ContainsTCP() bool {
	return p.IPProtocol == string(securityv1alpha1.ProtocolTCP) || p.IPProtocol == ""
}

type DeepCopyBase interface {
	DeepCopy() interface{}
}

type IPBlockItem struct {
	// AgentRef means this ip has appeared in these agents.
	// if sets is empty, this ip will apply to all agents.
	AgentRef sets.Set[string]
	Ports    []securityv1alpha1.NamedPort
}

func (item *IPBlockItem) DeepCopy() interface{} {
	if item == nil {
		var ptr *IPBlockItem
		return ptr
	}
	return &IPBlockItem{
		AgentRef: sets.New(item.AgentRef.UnsortedList()...),
		Ports:    item.Ports,
	}
}

func NewIPBlockItem() *IPBlockItem {
	item := &IPBlockItem{}
	item.AgentRef = sets.New[string]()
	return item
}

type CompleteRule struct {
	lock sync.RWMutex

	// RuleID is a unique identifier of rule, it's always set to policyNamespace/policyName/policyType/ruleName.
	RuleID string
	Policy string

	Tier            string
	Priority        int32
	EnforcementMode string
	Action          RuleAction
	Direction       RuleDirection

	// SymmetricMode will ignore direction, generate both ingress and egress rule
	SymmetricMode bool

	// DefaultPolicyRule is true when the it's the default egress or ingress rule in policy.
	DefaultPolicyRule bool

	// SrcGroups is a groupName sets
	SrcGroups sets.Set[string]
	DstGroups sets.Set[string]

	// SrcIPs is a static source IP set. This schema is used to calculate
	// If you want matches all source, you should write like {""}.
	SrcIPs sets.Set[string]

	// DstIPs is a static destination IP set. This schema is used to calculate
	// If you want matches all destination, you should write like {""}.
	DstIPs sets.Set[string]

	// Ports is a list of srcport and dstport with protocol. This filed must not empty.
	Ports []RulePort
}

type RulePort struct {
	// SrcPort is source port, 0 matches all ports.
	SrcPort uint16
	// DstPort is destination port, 0 matches all ports.
	DstPort uint16
	// SrcPortMask is source port mask, 0x0000 & 0xffff have no effect.
	SrcPortMask uint16
	// DstPortMask is destination port mask, 0x0000 & 0xffff have no effect.
	DstPortMask uint16

	// SrcPortName is a source port name, the mapped port depends on each endpoint.
	SrcPortName string
	// DstPortName is a destination port name, the mapped port depends on each endpoint.
	DstPortName string

	// Protocol should set "" if want match all protocol.
	Protocol securityv1alpha1.Protocol
}

func (rule *CompleteRule) Clone() *CompleteRule {
	if rule == nil {
		return nil
	}
	rule.lock.RLock()
	defer rule.lock.RUnlock()

	return &CompleteRule{
		RuleID:            rule.RuleID,
		Policy:            rule.Policy,
		Tier:              rule.Tier,
		Priority:          rule.Priority,
		EnforcementMode:   rule.EnforcementMode,
		Action:            rule.Action,
		Direction:         rule.Direction,
		SymmetricMode:     rule.SymmetricMode,
		DefaultPolicyRule: rule.DefaultPolicyRule,
		SrcGroups:         rule.SrcGroups.Clone(),
		DstGroups:         rule.DstGroups.Clone(),
		SrcIPs:            rule.SrcIPs.Clone(),
		DstIPs:            rule.DstIPs.Clone(),
		Ports:             append([]RulePort{}, rule.Ports...),
	}
}

// ListRules return a list of security.everoute.io/v1alpha1 PolicyRule
func (rule *CompleteRule) ListRules(ctx context.Context, groupCache *GroupCache) []PolicyRule {
	rule.lock.RLock()
	defer rule.lock.RUnlock()

	return rule.GenerateRuleList(ctx, rule.assemblySrcIPBlocks(ctx, groupCache), rule.assemblyDstIPBlocks(ctx, groupCache), rule.Ports)
}

func (rule *CompleteRule) GenerateRuleList(ctx context.Context, srcIPBlocks map[string]*IPBlockItem, dstIPBlocks map[string]*IPBlockItem, ports []RulePort) []PolicyRule {
	log := ctrl.LoggerFrom(ctx)
	var policyRuleList []PolicyRule

	for srcIP, srcIPBlock := range srcIPBlocks {
		for dstIP, dstIPBlock := range dstIPBlocks {
			// filter un-necessary rules generated by intra group policy
			if (strings.Contains(srcIP, "/32") || strings.Contains(srcIP, "/128")) && srcIP == dstIP {
				continue
			}

			// filter src and dst with different ip family
			// "" will match both v4 & v6
			if !utils.IsSameIPFamily(srcIP, dstIP) {
				continue
			}

			for _, port := range ports {
				dstPorts := []RulePort{port}
				if port.DstPortName != "" {
					if dstIPBlock == nil {
						log.Info("dstIPBlock is nil, can't resolve portname", "ipBlock", dstIP, "portname", port)
						continue
					}
					dstPorts = resolveDstPort(port, dstIPBlock.Ports)
					if len(dstPorts) == 0 {
						// dstIPBlocks has no namedPort map the port, skip
						log.Info("dstIPBlocks ports has no namedPort map the policy portname", "ipBlock", dstIP, "ipBlockPorts", dstIPBlock.Ports, "portname", port)
						continue
					}
				}
				for _, dstPort := range dstPorts {
					if rule.SymmetricMode {
						// SymmetricMode will ignore rule direction, create both ingress and egress
						if rule.hasLocalRule(dstIPBlock) {
							policyRuleList = append(policyRuleList, rule.generateRule(srcIP, dstIP, RuleDirectionIn, dstPort)...)
						}
						if rule.hasLocalRule(srcIPBlock) {
							policyRuleList = append(policyRuleList, rule.generateRule(srcIP, dstIP, RuleDirectionOut, dstPort)...)
						}
					} else if (rule.Direction == RuleDirectionIn && rule.hasLocalRule(dstIPBlock)) ||
						(rule.Direction == RuleDirectionOut && rule.hasLocalRule(srcIPBlock)) {
						policyRuleList = append(policyRuleList, rule.generateRule(srcIP, dstIP, rule.Direction, dstPort)...)
					}
				}
			}
		}
	}

	return policyRuleList
}

func (rule *CompleteRule) assemblySrcIPBlocks(ctx context.Context, groupCache *GroupCache) map[string]*IPBlockItem {
	ipBlocks, err := AssembleStaticIPAndGroup(ctx, rule.SrcIPs, rule.SrcGroups, groupCache)
	if err != nil {
		klog.Fatalf("Failed to assemply rule src ipBlocks: %s", err)
	}
	return ipBlocks
}

func (rule *CompleteRule) assemblyDstIPBlocks(ctx context.Context, groupCache *GroupCache) map[string]*IPBlockItem {
	ipBlocks, err := AssembleStaticIPAndGroup(ctx, rule.DstIPs, rule.DstGroups, groupCache)
	if err != nil {
		klog.Fatalf("Failed to assemply rule dst ipBlocks: %s", err)
	}
	return ipBlocks
}

func (rule *CompleteRule) hasLocalRule(ipBlock *IPBlockItem) bool {
	// apply to all target
	if ipBlock == nil {
		return true
	}
	// apply to src/dst has current agent
	if ipBlock.AgentRef.Len() == 0 || ipBlock.AgentRef.Has(utils.CurrentAgentName()) {
		return true
	}
	return false
}

func (rule *CompleteRule) generateRule(srcIPBlock, dstIPBlock string, direction RuleDirection, port RulePort) []PolicyRule {
	var ruleType = RuleTypeNormalRule
	if rule.DefaultPolicyRule {
		ruleType = RuleTypeDefaultRule
	}

	policyRule := PolicyRule{
		Policy:          rule.Policy,
		Direction:       direction,
		RuleType:        ruleType,
		Tier:            rule.Tier,
		PriorityOffset:  0,
		EnforcementMode: rule.EnforcementMode,
		SrcIPAddr:       srcIPBlock,
		DstIPAddr:       dstIPBlock,
		IPProtocol:      string(port.Protocol),
		SrcPort:         port.SrcPort,
		DstPort:         port.DstPort,
		SrcPortMask:     port.SrcPortMask,
		DstPortMask:     port.DstPortMask,
		Action:          rule.Action,
	}

	if policyRule.Tier == constants.Tier2 {
		if policyRule.RuleType == RuleTypeDefaultRule {
			policyRule.PriorityOffset = 4 * rule.Priority
		}

		// blocklist and allowlist with same policy priroity will generate different flow priority to avoid flowkey conflict
		if policyRule.RuleType == RuleTypeNormalRule {
			// allowlist ingress/egress rule
			if policyRule.Action == RuleActionAllow {
				policyRule.PriorityOffset = 4*rule.Priority + 1
			}
			// blocklist ingress/egress rule
			if policyRule.Action == RuleActionDrop {
				policyRule.PriorityOffset = 4*rule.Priority + 3
			}
		}
	}

	var ruleList []PolicyRule
	if utils.IsIPv4Pair(policyRule.SrcIPAddr, policyRule.DstIPAddr) {
		policyRule.IPFamily = unix.AF_INET
		policyRule.Name = fmt.Sprintf("%s-%s", rule.RuleID, GenerateFlowKey(policyRule))
		ruleList = append(ruleList, policyRule)
	}
	if utils.IsIPv6Pair(policyRule.SrcIPAddr, policyRule.DstIPAddr) {
		policyRuleV6 := *policyRule.DeepCopy()
		policyRuleV6.IPFamily = unix.AF_INET6
		policyRuleV6.Name = fmt.Sprintf("%s-%s", rule.RuleID, GenerateFlowKey(policyRuleV6))
		ruleList = append(ruleList, policyRuleV6)
	}
	return ruleList
}

const (
	GroupIndex  = "GroupIndex"
	PolicyIndex = "PolicyIndex"
)

func ruleKeyFunc(obj interface{}) (string, error) {
	return obj.(*CompleteRule).RuleID, nil
}

func globalRuleKeyFunc(obj interface{}) (string, error) {
	return obj.(PolicyRule).Name, nil
}

func NewGlobalRuleCache() cache.Indexer {
	return cache.NewIndexer(
		globalRuleKeyFunc,
		cache.Indexers{},
	)
}

func groupIndexFunc(obj interface{}) ([]string, error) {
	rule := obj.(*CompleteRule)
	groups := rule.SrcGroups.Union(rule.DstGroups)
	return groups.UnsortedList(), nil
}

func policyIndexFunc(obj interface{}) ([]string, error) {
	rule := obj.(*CompleteRule)
	return []string{rule.Policy}, nil
}

func resolveDstPort(port RulePort, namedPorts []securityv1alpha1.NamedPort) []RulePort {
	resPorts := make([]RulePort, 0)
	if port.DstPortName == "" {
		return resPorts
	}
	for _, namedPort := range namedPorts {
		if namedPort.Name == port.DstPortName && namedPort.Protocol == port.Protocol {
			resPorts = append(resPorts, RulePort{
				Protocol:    port.Protocol,
				DstPort:     uint16(namedPort.Port),
				DstPortMask: 0xffff,
			})
		}
	}
	return resPorts
}

func NewCompleteRuleCache() cache.Indexer {
	return cache.NewIndexer(
		ruleKeyFunc,
		cache.Indexers{
			GroupIndex:  groupIndexFunc,
			PolicyIndex: policyIndexFunc,
		},
	)
}

func GenerateFlowKey(rule PolicyRule) string {
	// ignore rule.Name and rule.Namespace from generate flowkey
	rule.Name = ""
	// ignore rule.Policy
	rule.Policy = ""
	// We consider PolicyRule with the same spec but different action as the same flow.
	// Some we remove the action to generate FlowKey here.
	rule.Action = ""
	return HashName(32, rule)
}

func AppendIPBlockPorts(dst []securityv1alpha1.NamedPort, src []securityv1alpha1.NamedPort) []securityv1alpha1.NamedPort {
	dstMap := make(map[string]securityv1alpha1.NamedPort, len(dst))
	for i := range dst {
		dstMap[dst[i].ToString()] = dst[i]
	}
	for i := range src {
		dstMap[src[i].ToString()] = src[i]
	}
	res := make([]securityv1alpha1.NamedPort, 0, len(dstMap))
	for _, v := range dstMap {
		res = append(res, v)
	}
	return res
}
