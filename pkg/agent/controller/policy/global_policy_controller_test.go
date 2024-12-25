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
	"context"
	"fmt"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"golang.org/x/sys/unix"
	"k8s.io/apimachinery/pkg/util/rand"

	"github.com/everoute/everoute/pkg/agent/controller/policy/cache"
	securityv1alpha1 "github.com/everoute/everoute/pkg/apis/security/v1alpha1"
	"github.com/everoute/everoute/pkg/constants"
)

var _ = Describe("PolicyController", func() {
	var ctx context.Context

	BeforeEach(func() {
		ctx = context.Background()
	})
	AfterEach(func() {
		Expect(k8sClient.DeleteAllOf(ctx, &securityv1alpha1.GlobalPolicy{})).Should(Succeed())
	})

	When("create global policy with global allow", func() {
		var policy *securityv1alpha1.GlobalPolicy

		BeforeEach(func() {
			policy = newTestGlobalPolicy(securityv1alpha1.GlobalDefaultActionAllow)
			By("create global policy " + policy.Name)
			Expect(k8sClient.Create(ctx, policy)).Should(Succeed())
		})

		It("should flatten golbal policy to rules", func() {
			assertGlobalPolicyRulesNum(4)
			assertHasGlobalPolicyRule("GlobalDefaultRule", "Ingress", "Allow", "", "", unix.AF_INET)
			assertHasGlobalPolicyRule("GlobalDefaultRule", "Egress", "Allow", "", "", unix.AF_INET)
			assertHasGlobalPolicyRule("GlobalDefaultRule", "Ingress", "Allow", "", "", unix.AF_INET6)
			assertHasGlobalPolicyRule("GlobalDefaultRule", "Egress", "Allow", "", "", unix.AF_INET6)
		})

		When("update GlobalPolicy to default drop", func() {
			BeforeEach(func() {
				updatePolicy := policy.DeepCopy()
				updatePolicy.Spec.DefaultAction = securityv1alpha1.GlobalDefaultActionDrop

				By(fmt.Sprintf("update global policy %s to default drop", updatePolicy.Name))
				Expect(k8sClient.Update(ctx, updatePolicy)).Should(Succeed())
			})

			It("should flatten golbal policy to rules", func() {
				assertGlobalPolicyRulesNum(4)
				assertHasGlobalPolicyRule("GlobalDefaultRule", "Ingress", "Drop", "", "", unix.AF_INET)
				assertHasGlobalPolicyRule("GlobalDefaultRule", "Egress", "Drop", "", "", unix.AF_INET)
				assertHasGlobalPolicyRule("GlobalDefaultRule", "Ingress", "Drop", "", "", unix.AF_INET6)
				assertHasGlobalPolicyRule("GlobalDefaultRule", "Egress", "Drop", "", "", unix.AF_INET6)
			})
		})
		When("delete GlobalPolicy", func() {
			BeforeEach(func() {
				By(fmt.Sprintf("delete global policy %s", policy.Name))
				Expect(k8sClient.Delete(ctx, policy)).Should(Succeed())
			})

			It("should delete all global rules", func() {
				assertGlobalPolicyRulesNum(0)
			})
		})
	})
})

func newTestGlobalPolicy(defaultAction securityv1alpha1.GlobalDefaultAction) *securityv1alpha1.GlobalPolicy {
	var policy securityv1alpha1.GlobalPolicy

	policy.Name = rand.String(6)
	policy.Spec.DefaultAction = defaultAction
	policy.Spec.GlobalPolicyEnforcementMode = securityv1alpha1.WorkMode

	return &policy
}

func getGlobalRuleFromCache() []cache.PolicyRule {
	var policyRuleList []cache.PolicyRule
	globalRules := globalRuleCacheLister.List()
	for _, rule := range globalRules {
		policyRuleList = append(policyRuleList, rule.(cache.PolicyRule))
	}
	return policyRuleList
}

func assertGlobalPolicyRulesNum(numOfPolicyRules int) {
	Eventually(func() int {
		policyRuleList := getGlobalRuleFromCache()
		return len(policyRuleList)
	}, timeout, interval).Should(Equal(numOfPolicyRules))
}

func assertHasGlobalPolicyRule(ruleType, direction, action, srcCidr, dstCidr string, family uint8) {
	Eventually(func() bool {
		policyRuleList := getGlobalRuleFromCache()
		By(fmt.Sprintf("%+v", policyRuleList))
		for _, rule := range policyRuleList {
			if constants.Tier2 == rule.Tier &&
				ruleType == string(rule.RuleType) &&
				direction == string(rule.Direction) &&
				action == string(rule.Action) &&
				srcCidr == rule.SrcIPAddr &&
				dstCidr == rule.DstIPAddr &&
				family == rule.IPFamily {
				return true
			}
		}
		return false
	}, timeout, interval).Should(BeTrue())
}
