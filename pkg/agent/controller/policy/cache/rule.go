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

	NormalPolicy PolicyType = "normal"
	GlobalPolicy PolicyType = "global"
)

type PolicyRule struct {
	// Name format policyNamespace/policyName/policyType/ruleName-flowKey
	Name   string     `json:"name"`
	Action RuleAction `json:"action"`

	// match fields
	Direction   RuleDirection `json:"direction"`
	RuleType    RuleType      `json:"ruleType"`
	Tier        string        `json:"tier,omitempty"`
	SrcIPAddr   string        `json:"srcIPAddr,omitempty"`
	DstIPAddr   string        `json:"dstIPAddr,omitempty"`
	IPProtocol  string        `json:"ipProtocol"`
	SrcPort     uint16        `json:"srcPort,omitempty"`
	DstPort     uint16        `json:"dstPort,omitempty"`
	SrcPortMask uint16        `json:"srcPortMask,omitempty"`
	DstPortMask uint16        `json:"dstPortMask,omitempty"`
}

type CompleteRule struct {
	lock sync.RWMutex

	// RuleID is a unique identifier of rule, it's always set to policyNamespace/policyName/policyType/ruleName.
	RuleID string

	Tier      string
	Action    RuleAction
	Direction RuleDirection

	// SymmetricMode will ignore direction, generate both ingress and egress rule
	SymmetricMode bool

	// DefaultPolicyRule is true when the it's the default egress or ingress rule in policy.
	DefaultPolicyRule bool

	// SrcGroups is a map of groupName and revision. Revision is used to determine whether
	// a patch has been executed for this group.
	SrcGroups map[string]int32
	DstGroups map[string]int32

	// SrcIPBlocks is a map of source IPBlocks and appear times. This schema is used to calculate
	// whether the patch leads to the added/deleted of IPBlocks. Virtual machine hot migration or
	// configuration conflict may lead to multiple identical IP in the same group at the same time.
	// If you want matches all source, you should write like {"": 1}.
	SrcIPBlocks map[string]int

	// DstIPBlocks is a map of destination IPBlocks and appear times. If you want matches all
	// destination, you should write like {"": 1}.
	DstIPBlocks map[string]int

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

	srcIPBlocks := sets.StringKeySet(rule.SrcIPBlocks).UnsortedList()
	dstIPBlocks := sets.StringKeySet(rule.DstIPBlocks).UnsortedList()

	return rule.generateRuleList(srcIPBlocks, dstIPBlocks, rule.Ports)
}

func (rule *CompleteRule) generateRuleList(srcIPBlocks, dstIPBlocks []string, ports []RulePort) []PolicyRule {
	var policyRuleList []PolicyRule

	for _, srcIPBlock := range srcIPBlocks {
		for _, dstIPBlock := range dstIPBlocks {
			for _, port := range ports {
				if rule.SymmetricMode {
					// SymmetricMode will ignore rule direction, create both ingress and egress
					policyRuleList = append(policyRuleList, rule.generateRule(srcIPBlock, dstIPBlock, RuleDirectionIn, port))
					policyRuleList = append(policyRuleList, rule.generateRule(srcIPBlock, dstIPBlock, RuleDirectionOut, port))
				} else {
					policyRuleList = append(policyRuleList, rule.generateRule(srcIPBlock, dstIPBlock, rule.Direction, port))
				}
			}
		}
	}

	return policyRuleList
}

func (rule *CompleteRule) generateRule(srcIPBlock, dstIPBlock string, direction RuleDirection, port RulePort) PolicyRule {
	var ruleType = RuleTypeNormalRule
	if rule.DefaultPolicyRule {
		ruleType = RuleTypeDefaultRule
	}

	policyRule := PolicyRule{
		Direction:   direction,
		RuleType:    ruleType,
		Tier:        rule.Tier,
		SrcIPAddr:   srcIPBlock,
		DstIPAddr:   dstIPBlock,
		IPProtocol:  string(port.Protocol),
		SrcPort:     port.SrcPort,
		DstPort:     port.DstPort,
		SrcPortMask: port.SrcPortMask,
		DstPortMask: port.DstPortMask,
		Action:      rule.Action,
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

	var srcIPs, dstIPs = DeepCopyMap(rule.SrcIPBlocks).(map[string]int), DeepCopyMap(rule.DstIPBlocks).(map[string]int)
	var srcAddIPs, srcDelIPs, dstAddIPs, dstDelIPs []string

	revision, exist := rule.SrcGroups[patch.GroupName]
	if exist && revision == patch.Revision {
		srcAddIPs, srcDelIPs = applyCountMap(srcIPs, patch.Add, patch.Del)

		addRules := rule.generateRuleList(srcAddIPs, sets.StringKeySet(dstIPs).UnsortedList(), rule.Ports)
		newPolicyRuleList = append(newPolicyRuleList, addRules...)

		delRules := rule.generateRuleList(srcDelIPs, sets.StringKeySet(dstIPs).UnsortedList(), rule.Ports)
		oldPolicyRuleList = append(oldPolicyRuleList, delRules...)
	}

	revision, exist = rule.DstGroups[patch.GroupName]
	if exist && revision == patch.Revision {
		dstAddIPs, dstDelIPs = applyCountMap(dstIPs, patch.Add, patch.Del)

		addRules := rule.generateRuleList(sets.StringKeySet(srcIPs).UnsortedList(), dstAddIPs, rule.Ports)
		newPolicyRuleList = append(newPolicyRuleList, addRules...)

		delRules := rule.generateRuleList(sets.StringKeySet(srcIPs).UnsortedList(), dstDelIPs, rule.Ports)
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

func applyCountMap(count map[string]int, added, deled []string) (new []string, old []string) {
	for _, add := range added {
		if count[add] == 0 {
			new = append(new, add)
		}
		count[add]++
	}

	for _, del := range deled {
		if count[del]--; count[del] == 0 {
			delete(count, del)
			old = append(old, del)
		}
	}

	return
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
