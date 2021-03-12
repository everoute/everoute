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

package cache

import (
	"fmt"
	"strings"
	"sync"

	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/tools/cache"

	policyv1alpha1 "github.com/smartxworks/lynx/pkg/apis/policyrule/v1alpha1"
	securityv1alpha1 "github.com/smartxworks/lynx/pkg/apis/security/v1alpha1"
	lynxctrl "github.com/smartxworks/lynx/pkg/controller"
)

type CompleteRule struct {
	lock sync.RWMutex

	// RuleID is an unique identifier of rule, it's always set to policyName/ruleName.
	RuleID string

	Priority  int32
	Tier      string
	Action    policyv1alpha1.RuleAction
	Direction policyv1alpha1.RuleDirection

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

	// Protocol should set "" if want match all protocol.
	Protocol securityv1alpha1.Protocol
}

// ListRules return a list of security.lynx.smartx.com/v1alpha1 PolicyRule
func (rule *CompleteRule) ListRules() policyv1alpha1.PolicyRuleList {
	rule.lock.RLock()
	defer rule.lock.RUnlock()

	srcIPBlocks := sets.StringKeySet(rule.SrcIPBlocks).UnsortedList()
	dstIPBlocks := sets.StringKeySet(rule.DstIPBlocks).UnsortedList()

	return rule.generateRuleList(srcIPBlocks, dstIPBlocks, rule.Ports)
}

func (rule *CompleteRule) generateRuleList(srcIPBlocks, dstIPBlocks []string, ports []RulePort) policyv1alpha1.PolicyRuleList {
	var policyRuleList policyv1alpha1.PolicyRuleList

	for _, srcIPBlock := range srcIPBlocks {
		for _, dstIPBlock := range dstIPBlocks {
			for _, port := range ports {
				policyRuleList.Items = append(policyRuleList.Items, rule.generateRule(srcIPBlock, dstIPBlock, port))
			}
		}
	}

	return policyRuleList
}

func (rule *CompleteRule) generateRule(srcIPBlock, dstIPBlock string, port RulePort) policyv1alpha1.PolicyRule {
	policyRule := policyv1alpha1.PolicyRule{
		Spec: policyv1alpha1.PolicyRuleSpec{
			Direction:         rule.Direction,
			DefaultPolicyRule: rule.DefaultPolicyRule,
			Tier:              rule.Tier,
			Priority:          rule.Priority,
			SrcIpAddr:         srcIPBlock,
			DstIpAddr:         dstIPBlock,
			IpProtocol:        string(port.Protocol),
			SrcPort:           port.SrcPort,
			DstPort:           port.DstPort,
			Action:            rule.Action,
		},
	}

	ruleName := strings.Split(rule.RuleID, "/")[1]
	policyName := strings.Split(rule.RuleID, "/")[0]

	// use srcIPBlock dstIPBlock and Port as key generate hashID
	hashID := HashName(20, srcIPBlock, dstIPBlock, port)

	policyRule.Name = genRuleName(policyName, ruleName, hashID)
	policyRule.Spec.RuleId = fmt.Sprintf("%s/%s", rule.RuleID, hashID)
	policyRule.Labels = map[string]string{
		lynxctrl.OwnerPolicyLabel: policyName,
	}

	return policyRule
}

func (rule *CompleteRule) GetPatchPolicyRules(patch *GroupPatch) (newPolicyRuleList, oldPolicyRuleList policyv1alpha1.PolicyRuleList) {
	rule.lock.RLock()
	defer rule.lock.RUnlock()

	var srcIPs, dstIPs = DeepCopyMap(rule.SrcIPBlocks).(map[string]int), DeepCopyMap(rule.DstIPBlocks).(map[string]int)
	var srcAddIPs, srcDelIPs, dstAddIPs, dstDelIPs []string

	revision, exist := rule.SrcGroups[patch.GroupName]
	if exist && revision == patch.Revision {
		srcAddIPs, srcDelIPs = applyCountMap(srcIPs, patch.Add, patch.Del)

		addRules := rule.generateRuleList(srcAddIPs, sets.StringKeySet(dstIPs).UnsortedList(), rule.Ports)
		newPolicyRuleList.Items = append(newPolicyRuleList.Items, addRules.Items...)

		delRules := rule.generateRuleList(srcDelIPs, sets.StringKeySet(dstIPs).UnsortedList(), rule.Ports)
		oldPolicyRuleList.Items = append(oldPolicyRuleList.Items, delRules.Items...)
	}

	revision, exist = rule.DstGroups[patch.GroupName]
	if exist && revision == patch.Revision {
		dstAddIPs, dstDelIPs = applyCountMap(dstIPs, patch.Add, patch.Del)

		addRules := rule.generateRuleList(sets.StringKeySet(srcIPs).UnsortedList(), dstAddIPs, rule.Ports)
		newPolicyRuleList.Items = append(newPolicyRuleList.Items, addRules.Items...)

		delRules := rule.generateRuleList(sets.StringKeySet(srcIPs).UnsortedList(), dstDelIPs, rule.Ports)
		oldPolicyRuleList.Items = append(oldPolicyRuleList.Items, delRules.Items...)
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

func groupIndexFunc(obj interface{}) ([]string, error) {
	rule := obj.(*CompleteRule)
	srcGroups := sets.StringKeySet(rule.SrcGroups)
	dstGroups := sets.StringKeySet(rule.DstGroups)
	groups := srcGroups.Union(dstGroups)
	return groups.UnsortedList(), nil
}

func policyIndexFunc(obj interface{}) ([]string, error) {
	rule := obj.(*CompleteRule)
	policyName := strings.Split(rule.RuleID, "/")[1]
	return []string{policyName}, nil
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

// genRuleName generate policy rule name as defined in RFC 1123.
func genRuleName(policyName, ruleName, ruleID string) string {
	var prefix = fmt.Sprintf("%s-%s", policyName, ruleName)
	var suffix = fmt.Sprintf("%s-%s", HashName(10, policyName, ruleName), ruleID)

	maxPrefixLength := validation.DNS1123SubdomainMaxLength - len(suffix) - 1
	if len(prefix) >= maxPrefixLength {
		prefix = prefix[:maxPrefixLength]
	}

	return fmt.Sprintf("%s-%s", prefix, suffix)
}
