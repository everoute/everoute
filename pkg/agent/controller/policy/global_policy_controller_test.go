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

package policy_test

import (
	"context"
	"fmt"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/util/rand"

	policyv1alpha1 "github.com/everoute/everoute/pkg/apis/policyrule/v1alpha1"
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
			assertGlobalPolicyRulesNum(2)
			assertHasGlobalPolicyRule("GlobalDefaultRule", "Ingress", "Allow", "", "")
			assertHasGlobalPolicyRule("GlobalDefaultRule", "Egress", "Allow", "", "")
		})

		When("update GlobalPolicy to default drop", func() {
			BeforeEach(func() {
				updatePolicy := policy.DeepCopy()
				updatePolicy.Spec.DefaultAction = securityv1alpha1.GlobalDefaultActionDrop

				By(fmt.Sprintf("update global policy %s to default drop", updatePolicy.Name))
				Expect(k8sClient.Update(ctx, updatePolicy)).Should(Succeed())
			})

			It("should flatten golbal policy to rules", func() {
				assertGlobalPolicyRulesNum(2)
				assertHasGlobalPolicyRule("GlobalDefaultRule", "Ingress", "Drop", "", "")
				assertHasGlobalPolicyRule("GlobalDefaultRule", "Egress", "Drop", "", "")
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

	When("create global policy with whitelist", func() {
		var policy *securityv1alpha1.GlobalPolicy
		var whitelist string

		BeforeEach(func() {
			whitelist = "192.168.0.0/24"
			policy = newTestGlobalPolicy(securityv1alpha1.GlobalDefaultActionDrop, whitelist)
			By("create global policy " + policy.Name)
			Expect(k8sClient.Create(ctx, policy)).Should(Succeed())
		})

		It("should flatten golbal policy to rules", func() {
			assertGlobalPolicyRulesNum(4)
			assertHasGlobalPolicyRule("GlobalDefaultRule", "Ingress", "Drop", "", "")
			assertHasGlobalPolicyRule("GlobalDefaultRule", "Egress", "Drop", "", "")
			assertHasGlobalPolicyRule("NormalRule", "Ingress", "Allow", "", whitelist)
			assertHasGlobalPolicyRule("NormalRule", "Egress", "Allow", whitelist, "")
		})

		When("update GlobalPolicy whitelist", func() {
			var newWhitelist string
			BeforeEach(func() {
				updatePolicy := policy.DeepCopy()
				newWhitelist = "192.168.0.0/16"
				updatePolicy.Spec.Whitelist = []networkingv1.IPBlock{{
					CIDR: newWhitelist,
				}}

				By(fmt.Sprintf("update global policy %s whitelist to %+v", updatePolicy.Name, updatePolicy.Spec.Whitelist))
				Expect(k8sClient.Update(ctx, updatePolicy)).Should(Succeed())
			})

			It("should flatten golbal policy to rules", func() {
				assertGlobalPolicyRulesNum(4)
				assertHasGlobalPolicyRule("GlobalDefaultRule", "Ingress", "Drop", "", "")
				assertHasGlobalPolicyRule("GlobalDefaultRule", "Egress", "Drop", "", "")
				assertHasGlobalPolicyRule("NormalRule", "Ingress", "Allow", "", newWhitelist)
				assertHasGlobalPolicyRule("NormalRule", "Egress", "Allow", newWhitelist, "")
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

func newTestGlobalPolicy(defaultAction securityv1alpha1.GlobalDefaultAction, whitelist ...string) *securityv1alpha1.GlobalPolicy {
	var policy securityv1alpha1.GlobalPolicy

	policy.Name = rand.String(6)
	policy.Spec.DefaultAction = defaultAction

	for _, cidr := range whitelist {
		policy.Spec.Whitelist = append(policy.Spec.Whitelist, networkingv1.IPBlock{
			CIDR: cidr,
		})
	}

	return &policy
}

func getGlobalRuleFromCache() policyv1alpha1.PolicyRuleList {
	policyRuleList := policyv1alpha1.PolicyRuleList{}
	globalRules := globalRuleCacheLister.List()
	for _, rule := range globalRules {
		policyRuleList.Items = append(policyRuleList.Items, rule.(policyv1alpha1.PolicyRule))
	}
	return policyRuleList
}

func assertGlobalPolicyRulesNum(numOfPolicyRules int) {
	Eventually(func() int {
		policyRuleList := getGlobalRuleFromCache()
		return len(policyRuleList.Items)
	}, timeout, interval).Should(Equal(numOfPolicyRules))
}

func assertHasGlobalPolicyRule(ruleType, direction, action, srcCidr, dstCidr string) {
	Eventually(func() bool {
		policyRuleList := getGlobalRuleFromCache()

		for _, rule := range policyRuleList.Items {
			if constants.Tier2 == rule.Spec.Tier &&
				ruleType == string(rule.Spec.RuleType) &&
				direction == string(rule.Spec.Direction) &&
				action == string(rule.Spec.Action) &&
				srcCidr == rule.Spec.SrcIPAddr &&
				dstCidr == rule.Spec.DstIPAddr {
				return true
			}
		}
		return false
	}, timeout, interval).Should(BeTrue())
}
