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
	"fmt"
	"strings"
	"sync"

	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/tools/cache"

	securityv1alpha1 "github.com/everoute/everoute/pkg/apis/security/v1alpha1"
	"github.com/everoute/everoute/pkg/utils"
)

type RuleType string
type RuleAction string
type RuleDirection string

const (
	RuleTypeGlobalDefaultRule RuleType = "GlobalDefaultRule"
	RuleTypeDefaultRule       RuleType = "DefaultRule"
	RuleTypeNormalRule        RuleType = "NormalRule"

	RuleActionAllow RuleAction = "Allow"
	RuleActionDrop  RuleAction = "Drop"

	RuleDirectionIn  RuleDirection = "Ingress"
	RuleDirectionOut RuleDirection = "Egress"
)

type PolicyRule struct {
	// Name format policyNamespace/policyName/ruleName-flowKey
	Name   string     `json:"name"`
	Action RuleAction `json:"action"`

	// match fields
	Direction       RuleDirection `json:"direction"`
	RuleType        RuleType      `json:"ruleType"`
	Tier            string        `json:"tier,omitempty"`
	EnforcementMode string        `json:"enforcementMode,omitempty"`
	SrcIPAddr       string        `json:"srcIPAddr,omitempty"`
	DstIPAddr       string        `json:"dstIPAddr,omitempty"`
	IPProtocol      string        `json:"ipProtocol"`
	SrcPort         uint16        `json:"srcPort,omitempty"`
	DstPort         uint16        `json:"dstPort,omitempty"`
	SrcPortMask     uint16        `json:"srcPortMask,omitempty"`
	DstPortMask     uint16        `json:"dstPortMask,omitempty"`
}

type DeepCopyBase interface {
	DeepCopy() interface{}
}

type IPBlockItem struct {
	// AgentRef means this ip has appeared in these agents.
	// if sets is empty, this ip will apply to all agents.
	AgentRef sets.String
	// StaticCount is counter for ips which assigned directly in policy
	StaticCount int
}

func (item *IPBlockItem) DeepCopy() interface{} {
	if item == nil {
		var ptr *IPBlockItem
		return ptr
	}
	return &IPBlockItem{
		AgentRef:    sets.NewString(item.AgentRef.List()...),
		StaticCount: item.StaticCount,
	}
}

func NewIPBlockItem() *IPBlockItem {
	item := &IPBlockItem{}
	item.AgentRef = sets.NewString()
	return item
}

type CompleteRule struct {
	lock sync.RWMutex

	// RuleID is a unique identifier of rule, it's always set to policyNamespace/policyName/ruleName.
	RuleID string

	Tier            string
	EnforcementMode string
	Action          RuleAction
	Direction       RuleDirection

	// SymmetricMode will ignore direction, generate both ingress and egress rule
	SymmetricMode bool

	// DefaultPolicyRule is true when the it's the default egress or ingress rule in policy.
	DefaultPolicyRule bool

	// SrcGroups is a map of groupName and revision. Revision is used to determine whether
	// a patch has been executed for this group.
	SrcGroups map[string]int32
	DstGroups map[string]int32

	// SrcIPBlocks is a map of source IPBlocks and other ip infos. This schema is used to calculate
	// whether the patch leads to the added/deleted of IPBlocks. Virtual machine hot migration or
	// configuration conflict may lead to multiple identical IP in the same group at the same time.
	// If you want matches all source, you should write like {"": nil}.
	SrcIPBlocks map[string]*IPBlockItem

	// DstIPBlocks is a map of destination IPBlocks and other ip infos. If you want matches all
	// destination, you should write like {"": nil}.
	DstIPBlocks map[string]*IPBlockItem

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

	// Protocol should set "" if want match all protocol.
	Protocol securityv1alpha1.Protocol
}

// ListRules return a list of security.everoute.io/v1alpha1 PolicyRule
func (rule *CompleteRule) ListRules() []PolicyRule {
	rule.lock.RLock()
	defer rule.lock.RUnlock()

	return rule.generateRuleList(rule.SrcIPBlocks, rule.DstIPBlocks, rule.Ports)
}

func (rule *CompleteRule) generateRuleList(srcIPBlocks, dstIPBlocks map[string]*IPBlockItem, ports []RulePort) []PolicyRule {
	var policyRuleList []PolicyRule

	for srcIP, srcIPBlock := range srcIPBlocks {
		for dstIP, dstIPBlock := range dstIPBlocks {
			// filter un-necessary rules generated by intra group policy
			if srcIP != "" && dstIP != "" && srcIP == dstIP {
				continue
			}
			for _, port := range ports {
				if rule.SymmetricMode {
					// SymmetricMode will ignore rule direction, create both ingress and egress
					if rule.hasLocalRule(dstIPBlock) {
						policyRuleList = append(policyRuleList, rule.generateRule(srcIP, dstIP, RuleDirectionIn, port))
					}
					if rule.hasLocalRule(srcIPBlock) {
						policyRuleList = append(policyRuleList, rule.generateRule(srcIP, dstIP, RuleDirectionOut, port))
					}
				} else {
					if (rule.Direction == RuleDirectionIn && rule.hasLocalRule(dstIPBlock)) ||
						(rule.Direction == RuleDirectionOut && rule.hasLocalRule(srcIPBlock)) {
						policyRuleList = append(policyRuleList, rule.generateRule(srcIP, dstIP, rule.Direction, port))
					}
				}
			}
		}
	}

	return policyRuleList
}

func (rule *CompleteRule) hasLocalRule(ipBlock *IPBlockItem) bool {
	// apply to all target
	if ipBlock == nil {
		return true
	}
	// apply to peer with static ips
	if ipBlock.StaticCount > 0 {
		return true
	}
	// apply to src/dst has current agent
	if ipBlock.AgentRef.Len() == 0 || ipBlock.AgentRef.Has(utils.CurrentAgentName()) {
		return true
	}
	return false
}

func (rule *CompleteRule) generateRule(srcIPBlock, dstIPBlock string, direction RuleDirection, port RulePort) PolicyRule {
	var ruleType = RuleTypeNormalRule
	if rule.DefaultPolicyRule {
		ruleType = RuleTypeDefaultRule
	}

	policyRule := PolicyRule{
		Direction:       direction,
		RuleType:        ruleType,
		Tier:            rule.Tier,
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

	// todo: it is not appropriate to calculate the flowkey here
	// we should get flowkey when add flow to datapath
	flowKey := GenerateFlowKey(policyRule)

	policyRule.Name = fmt.Sprintf("%s-%s", rule.RuleID, flowKey)

	return policyRule
}

func (rule *CompleteRule) GetPatchPolicyRules(patch *GroupPatch) (newPolicyRuleList, oldPolicyRuleList []PolicyRule) {
	rule.lock.RLock()
	defer rule.lock.RUnlock()

	srcIPs := DeepCopyMap(rule.SrcIPBlocks).(map[string]*IPBlockItem)
	dstIPs := DeepCopyMap(rule.DstIPBlocks).(map[string]*IPBlockItem)

	revision, exist := rule.SrcGroups[patch.GroupName]
	if exist && revision == patch.Revision {
		applyCountMap(srcIPs, patch.Add, patch.Del)

		addRules := rule.generateRuleList(patch.Add, dstIPs, rule.Ports)
		newPolicyRuleList = append(newPolicyRuleList, addRules...)

		delRules := rule.generateRuleList(patch.Del, dstIPs, rule.Ports)
		oldPolicyRuleList = append(oldPolicyRuleList, delRules...)
	}

	revision, exist = rule.DstGroups[patch.GroupName]
	if exist && revision == patch.Revision {
		applyCountMap(dstIPs, patch.Add, patch.Del)

		addRules := rule.generateRuleList(srcIPs, patch.Add, rule.Ports)
		newPolicyRuleList = append(newPolicyRuleList, addRules...)

		delRules := rule.generateRuleList(srcIPs, patch.Del, rule.Ports)
		oldPolicyRuleList = append(oldPolicyRuleList, delRules...)
	}

	return
}

func (rule *CompleteRule) ApplyPatch(patch *GroupPatch) {
	rule.lock.Lock()
	defer rule.lock.Unlock()

	revision, exist := rule.SrcGroups[patch.GroupName]

	if exist && revision == patch.Revision {
		applyCountMap(rule.SrcIPBlocks, patch.Add, patch.Del)
		rule.SrcGroups[patch.GroupName] = patch.Revision + 1
	}

	revision, exist = rule.DstGroups[patch.GroupName]

	if exist && revision == patch.Revision {
		applyCountMap(rule.DstIPBlocks, patch.Add, patch.Del)
		rule.DstGroups[patch.GroupName] = patch.Revision + 1
	}
}

func applyCountMap(count map[string]*IPBlockItem, added, deled map[string]*IPBlockItem) {
	for ip, add := range added {
		if _, exist := count[ip]; !exist {
			count[ip] = NewIPBlockItem()
		}
		count[ip].StaticCount += add.StaticCount
		count[ip].AgentRef.Insert(add.AgentRef.List()...)
	}

	for ip, del := range deled {
		if _, exist := count[ip]; !exist {
			continue
		}
		count[ip].StaticCount -= del.StaticCount
		count[ip].AgentRef.Delete(del.AgentRef.List()...)

		if count[ip].StaticCount < 0 {
			count[ip].StaticCount = 0
		}

		if count[ip].StaticCount == 0 && count[ip].AgentRef.Len() == 0 {
			delete(count, ip)
		}
	}

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
	srcGroups := sets.StringKeySet(rule.SrcGroups)
	dstGroups := sets.StringKeySet(rule.DstGroups)
	groups := srcGroups.Union(dstGroups)
	return groups.UnsortedList(), nil
}

func policyIndexFunc(obj interface{}) ([]string, error) {
	rule := obj.(*CompleteRule)
	policyNamespaceName := strings.Join(strings.Split(rule.RuleID, "/")[:2], "/")
	return []string{policyNamespaceName}, nil
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
	// We consider PolicyRule with the same spec but different action as the same flow.
	// Some we remove the action to generate FlowKey here.
	rule.Action = ""
	return HashName(32, rule)
}
