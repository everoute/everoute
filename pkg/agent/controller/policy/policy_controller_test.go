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

	"reflect"
	"testing"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8stypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/rand"
	storecache "k8s.io/client-go/tools/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/everoute/everoute/pkg/agent/controller/policy"
	"github.com/everoute/everoute/pkg/agent/controller/policy/cache"
	groupv1alpha1 "github.com/everoute/everoute/pkg/apis/group/v1alpha1"
	securityv1alpha1 "github.com/everoute/everoute/pkg/apis/security/v1alpha1"
	"github.com/everoute/everoute/pkg/constants"
	ctrlpolicy "github.com/everoute/everoute/pkg/controller/policy"
	"github.com/everoute/everoute/pkg/types"
)

const (
	timeout  = time.Second * 60
	interval = time.Millisecond * 250
)

var _ = Describe("PolicyController", func() {
	var ctx context.Context

	BeforeEach(func() {
		ctx = context.Background()
	})

	AfterEach(func() {
		namespaceDefault := client.InNamespace(metav1.NamespaceDefault)

		By("delete all test policies")
		Expect(k8sClient.DeleteAllOf(ctx, &securityv1alpha1.SecurityPolicy{}, namespaceDefault)).Should(Succeed())
		Eventually(func() int {
			policyList := securityv1alpha1.SecurityPolicyList{}
			Expect(k8sClient.List(ctx, &policyList)).Should(Succeed())
			return len(policyList.Items)
		}, timeout, interval).Should(BeZero())

		By("delete all test groupmembers")
		Expect(k8sClient.DeleteAllOf(ctx, &groupv1alpha1.GroupMembers{})).Should(Succeed())
		Eventually(func() int {
			membersList := groupv1alpha1.GroupMembersList{}
			Expect(k8sClient.List(ctx, &membersList)).Should(Succeed())
			return len(membersList.Items)
		}, timeout, interval).Should(BeZero())

		By("delete all test patches")
		Expect(k8sClient.DeleteAllOf(ctx, &groupv1alpha1.GroupMembersPatch{})).Should(Succeed())
		Eventually(func() int {
			patchList := groupv1alpha1.GroupMembersPatchList{}
			Expect(k8sClient.List(ctx, &patchList)).Should(Succeed())
			return len(patchList.Items)
		}, timeout, interval).Should(BeZero())
	})

	Context("policy needed endpoints and groups has been create", func() {
		var group1, group2, group3 *testGroup
		var ep1, ep2, ep3 *securityv1alpha1.Endpoint

		BeforeEach(func() {
			ep1 = newTestEndpoint("192.168.1.1")
			ep2 = newTestEndpoint("192.168.2.1")
			ep3 = newTestEndpoint("192.168.3.1")
			group1 = newTestGroupMembers(0, endpointToMember(ep1))
			group2 = newTestGroupMembers(0, endpointToMember(ep2))
			group3 = newTestGroupMembers(0, endpointToMember(ep3))

			By(fmt.Sprintf("create endpoints %s and groups %v", []string{ep1.Name, ep2.Name, ep3.Name}, []string{group1.Name, group2.Name, group3.Name}))
			Expect(k8sClient.Create(ctx, group1.GroupMembers)).Should(Succeed())
			Expect(k8sClient.Create(ctx, group2.GroupMembers)).Should(Succeed())
			Expect(k8sClient.Create(ctx, group3.GroupMembers)).Should(Succeed())
		})
		When("create a sample policy with port range", func() {
			var policy *securityv1alpha1.SecurityPolicy

			BeforeEach(func() {
				policy = newTestPolicy(group1, group2, group3, newTestPort("TCP", "1000-1999"), newTestPort("UDP", "80"))

				By("create policy " + policy.Name)
				Expect(k8sClient.Create(ctx, policy)).Should(Succeed())
			})

			It("should flatten policy to rules", func() {
				assertPolicyRulesNum(policy, 10)
				assertCompleteRuleNum(4)

				assertHasPolicyRuleWithPortRange(policy, "Ingress", "Allow", "192.168.2.1/32",
					0, 0, "192.168.1.1/32", 0x03e8, 0xfff8, "TCP")
				assertHasPolicyRuleWithPortRange(policy, "Ingress", "Allow", "192.168.2.1/32",
					0, 0, "192.168.1.1/32", 0x03f0, 0xfff0, "TCP")
				assertHasPolicyRuleWithPortRange(policy, "Ingress", "Allow", "192.168.2.1/32",
					0, 0, "192.168.1.1/32", 0x0400, 0xfe00, "TCP")
				assertHasPolicyRuleWithPortRange(policy, "Ingress", "Allow", "192.168.2.1/32",
					0, 0, "192.168.1.1/32", 0x0600, 0xff00, "TCP")
				assertHasPolicyRuleWithPortRange(policy, "Ingress", "Allow", "192.168.2.1/32",
					0, 0, "192.168.1.1/32", 0x0700, 0xff80, "TCP")
				assertHasPolicyRuleWithPortRange(policy, "Ingress", "Allow", "192.168.2.1/32",
					0, 0, "192.168.1.1/32", 0x0780, 0xffc0, "TCP")
				assertHasPolicyRuleWithPortRange(policy, "Ingress", "Allow", "192.168.2.1/32",
					0, 0, "192.168.1.1/32", 0x07c0, 0xfff0, "TCP")

				// default ingress/egress rule (drop all to/from source)
				assertHasPolicyRule(policy, "Ingress", "Drop", "", 0, "192.168.1.1/32", 0, "")
				assertHasPolicyRule(policy, "Egress", "Drop", "192.168.1.1/32", 0, "", 0, "")
			})
		})

		When("create a sample policy with port range 2", func() {
			var policy *securityv1alpha1.SecurityPolicy

			BeforeEach(func() {
				policy = newTestPolicy(group1, group2, group3, newTestPort("TCP", "65532-65535"), newTestPort("UDP", "80"))

				By("create policy " + policy.Name)
				Expect(k8sClient.Create(ctx, policy)).Should(Succeed())
			})

			It("should flatten policy to rules", func() {
				assertPolicyRulesNum(policy, 4)
				assertCompleteRuleNum(4)

				assertHasPolicyRuleWithPortRange(policy, "Ingress", "Allow", "192.168.2.1/32",
					0, 0, "192.168.1.1/32", 0xfffc, 0xfffc, "TCP")

			})
		})

		When("create a sample policy no port limit", func() {
			var policy *securityv1alpha1.SecurityPolicy

			BeforeEach(func() {
				policy = newTestPolicy(group1, group2, group3, newTestPort("TCP", "0"), newTestPort("UDP", "80"))

				By("create policy " + policy.Name)
				Expect(k8sClient.Create(ctx, policy)).Should(Succeed())
			})

			It("should flatten policy to rules", func() {
				assertPolicyRulesNum(policy, 4)
				assertCompleteRuleNum(4)

				assertHasPolicyRuleWithPortRange(policy, "Ingress", "Allow", "192.168.2.1/32",
					0, 0, "192.168.1.1/32", 0, 0, "TCP")

			})
			When("set applyTo empty", func() {
				var testPolicy *securityv1alpha1.SecurityPolicy

				BeforeEach(func() {
					testPolicy = policy.DeepCopy()
					testPolicy.Spec.AppliedTo = []securityv1alpha1.ApplyToPeer{}

					By(fmt.Sprintf("update policy %s with empty applyTo", testPolicy.Name))
					mustUpdatePolicy(ctx, testPolicy)
				})

				It("should apply to all endpoints", func() {
					assertPolicyRulesNum(testPolicy, 4)
					assertCompleteRuleNum(4)

					assertHasPolicyRuleWithPortRange(testPolicy, "Ingress", "Allow", "192.168.2.1/32",
						0, 0, "", 0, 0, "TCP")
					assertHasPolicyRuleWithPortRange(testPolicy, "Ingress", "Drop", "",
						0, 0, "", 0, 0, "")

					assertHasPolicyRuleWithPortRange(testPolicy, "Egress", "Allow", "",
						0, 0, "192.168.3.1/32", 80, 0xffff, "UDP")
					assertHasPolicyRuleWithPortRange(testPolicy, "Egress", "Drop", "",
						0, 0, "", 0, 0, "")
				})
			})

		})

		When("create a sample policy with ingress and egress", func() {
			var policy *securityv1alpha1.SecurityPolicy

			BeforeEach(func() {
				policy = newTestPolicy(group1, group2, group3, newTestPort("TCP", "22"), newTestPort("UDP", "80"))

				By("create policy " + policy.Name)
				Expect(k8sClient.Create(ctx, policy)).Should(Succeed())
			})

			It("should flatten policy to rules", func() {
				assertPolicyRulesNum(policy, 4)
				assertCompleteRuleNum(4)

				assertHasPolicyRule(policy, "Ingress", "Allow", "192.168.2.1/32", 0, "192.168.1.1/32", 22, "TCP")
				assertHasPolicyRule(policy, "Egress", "Allow", "192.168.1.1/32", 0, "192.168.3.1/32", 80, "UDP")

				// default ingress/egress rule (drop all to/from source)
				assertHasPolicyRule(policy, "Ingress", "Drop", "", 0, "192.168.1.1/32", 0, "")
				assertHasPolicyRule(policy, "Egress", "Drop", "192.168.1.1/32", 0, "", 0, "")
			})

			When("create a patch add member in applied group", func() {
				var patch *groupv1alpha1.GroupMembersPatch
				var addEp *securityv1alpha1.Endpoint

				BeforeEach(func() {
					addEp = newTestEndpoint("192.168.1.2")
					patch = newTestGroupMembersPatch(group1.Name, group1.Revision, endpointToMember(addEp), nil, nil)

					By(fmt.Sprintf("create patch %s for group %s, revision %d", patch.Name, group1.Name, group1.Revision))
					Expect(k8sClient.Create(ctx, patch)).Should(Succeed())
				})
				It("should sync policy rules", func() {
					assertHasPolicyRule(policy, "Ingress", "Allow", "192.168.2.1/32", 0, "192.168.1.2/32", 22, "TCP")
					assertHasPolicyRule(policy, "Egress", "Allow", "192.168.1.2/32", 0, "192.168.3.1/32", 80, "UDP")
				})
			})
			When("create a patch remove member in ingress group", func() {
				var patch *groupv1alpha1.GroupMembersPatch
				var delEp *securityv1alpha1.Endpoint

				BeforeEach(func() {
					delEp = ep2.DeepCopy() // remove ep2 in group2
					patch = newTestGroupMembersPatch(group2.Name, group2.Revision, nil, nil, endpointToMember(delEp))

					By(fmt.Sprintf("create patch %s for group %s, revision %d", patch.Name, group1.Name, group1.Revision))
					Expect(k8sClient.Create(ctx, patch)).Should(Succeed())
				})
				It("should remove ingress policy rules", func() {
					assertNoPolicyRule(policy, "Ingress", "Allow", "192.168.2.1/32", 0, "192.168.1.1/32", 22, "TCP")
				})
			})
			When("create a patch update member in egress group", func() {
				var patch *groupv1alpha1.GroupMembersPatch
				var updEp *securityv1alpha1.Endpoint

				BeforeEach(func() {
					updEp = ep3.DeepCopy() // update ep3 in group3
					updEp.Status.IPs = []types.IPAddress{"192.168.3.2"}
					patch = newTestGroupMembersPatch(group3.Name, group3.Revision, nil, endpointToMember(updEp), nil)

					By(fmt.Sprintf("create patch %s for group %s, revision %d", patch.Name, group1.Name, group1.Revision))
					Expect(k8sClient.Create(ctx, patch)).Should(Succeed())
				})
				It("should replace an egress policy rule", func() {
					assertNoPolicyRule(policy, "Egress", "Allow", "192.168.1.1/32", 0, "192.168.3.1/32", 80, "UDP")
					assertHasPolicyRule(policy, "Egress", "Allow", "192.168.1.1/32", 0, "192.168.3.2/32", 80, "UDP")
				})
			})

			When("add a group into applied groups", func() {
				var newGroup *testGroup
				var updPolicy *securityv1alpha1.SecurityPolicy

				BeforeEach(func() {
					newEp := newTestEndpoint("192.168.1.2")
					newGroup = newTestGroupMembers(0, endpointToMember(newEp))
					updPolicy = policy.DeepCopy()
					updPolicy.Spec.AppliedTo = append(updPolicy.Spec.AppliedTo, securityv1alpha1.ApplyToPeer{
						EndpointSelector: newGroup.endpointSelector,
					})

					By(fmt.Sprintf("update policy %s with new applied group %s", policy.Name, newGroup.Name))
					Expect(k8sClient.Create(ctx, newGroup.GroupMembers)).Should(Succeed())
					mustUpdatePolicy(ctx, updPolicy)
				})
				It("should add ingress egress and default policy rule", func() {
					assertHasPolicyRule(policy, "Ingress", "Allow", "192.168.2.1/32", 0, "192.168.1.2/32", 22, "TCP")
					assertHasPolicyRule(policy, "Egress", "Allow", "192.168.1.2/32", 0, "192.168.3.1/32", 80, "UDP")

					// add endpoint into default rule
					assertHasPolicyRule(policy, "Ingress", "Drop", "", 0, "192.168.1.2/32", 0, "")
					assertHasPolicyRule(policy, "Egress", "Drop", "192.168.1.2/32", 0, "", 0, "")
				})
			})
			When("add a group into ingress groups", func() {
				var newGroup *testGroup
				var updPolicy *securityv1alpha1.SecurityPolicy

				BeforeEach(func() {
					newEp := newTestEndpoint("192.168.2.2")
					newGroup = newTestGroupMembers(0, endpointToMember(newEp))
					updPolicy = policy.DeepCopy()
					updPolicy.Spec.IngressRules[0].From = append(updPolicy.Spec.IngressRules[0].From, securityv1alpha1.SecurityPolicyPeer{
						EndpointSelector: newGroup.endpointSelector,
					})

					By(fmt.Sprintf("update policy %s with new ingress group %s", policy.Name, newGroup.Name))
					Expect(k8sClient.Create(ctx, newGroup.GroupMembers)).Should(Succeed())
					mustUpdatePolicy(ctx, updPolicy)
				})
				It("should add an ingress policy rule", func() {
					assertHasPolicyRule(policy, "Ingress", "Allow", "192.168.2.2/32", 0, "192.168.1.1/32", 22, "TCP")
				})
			})
			When("remove groups from egress groups", func() {
				var updPolicy *securityv1alpha1.SecurityPolicy

				BeforeEach(func() {
					updPolicy = policy.DeepCopy()
					updPolicy.Spec.EgressRules[0].To = nil

					By(fmt.Sprintf("update policy %s with empty egress groups", policy.Name))
					mustUpdatePolicy(ctx, updPolicy)
				})
				It("should remove egress policy rules", func() {
					assertNoPolicyRule(policy, "Egress", "Allow", "192.168.1.1/32", 0, "192.168.3.1/32", 80, "UDP")
				})
				It("should add an egress policy rule allow all destinations", func() {
					// empty to securityPeer match all destinations
					assertHasPolicyRule(policy, "Egress", "Allow", "192.168.1.1/32", 0, "", 80, "UDP")
				})
			})

			When("add an new empty from peer ingress rule", func() {
				var newRule *securityv1alpha1.Rule
				var updPolicy *securityv1alpha1.SecurityPolicy

				BeforeEach(func() {
					newRule = &securityv1alpha1.Rule{
						Name:  rand.String(6),
						Ports: []securityv1alpha1.SecurityPolicyPort{*newTestPort("ICMP", "")},
					}
					updPolicy = policy.DeepCopy()
					updPolicy.Spec.IngressRules = append(updPolicy.Spec.IngressRules, *newRule)

					By(fmt.Sprintf("update policy %s an new empty from peer ingress rule %s", policy.Name, newRule.Name))
					mustUpdatePolicy(ctx, updPolicy)
				})
				It("should add an ingress policy rule allow all sources", func() {
					assertCompleteRuleNum(5)

					// empty from securityPeer match all sources
					assertHasPolicyRule(policy, "Ingress", "Allow", "", 0, "192.168.1.1/32", 0, "ICMP")
				})
			})
			When("remove all egress rules", func() {
				var updPolicy *securityv1alpha1.SecurityPolicy

				BeforeEach(func() {
					updPolicy = policy.DeepCopy()
					updPolicy.Spec.EgressRules = nil

					By(fmt.Sprintf("update policy %s remove all egress rule", policy.Name))
					mustUpdatePolicy(ctx, updPolicy)
				})
				It("should remove egress policy rules", func() {
					assertCompleteRuleNum(3)

					assertNoPolicyRule(policy, "Egress", "Allow", "192.168.1.1/32", 0, "192.168.3.1/32", 80, "UDP")
				})
			})

			When("update policy tier", func() {
				var updPolicy *securityv1alpha1.SecurityPolicy
				var tier string

				BeforeEach(func() {
					tier = constants.Tier1
					updPolicy = policy.DeepCopy()
					updPolicy.Spec.Tier = tier

					By(fmt.Sprintf("update policy %s with new tier %s", policy.Name, tier))
					mustUpdatePolicy(ctx, updPolicy)
				})
				It("should replace policy rules tier", func() {
					assertCompleteRuleNum(4)

					assertNoPolicyRule(policy, "Ingress", "Allow", "192.168.2.1/32", 0, "192.168.1.1/32", 22, "TCP")
					assertNoPolicyRule(policy, "Egress", "Allow", "192.168.1.1/32", 0, "192.168.3.1/32", 80, "UDP")
					assertNoPolicyRule(policy, "Ingress", "Drop", "", 0, "192.168.1.1/32", 0, "")
					assertNoPolicyRule(policy, "Egress", "Drop", "192.168.1.1/32", 0, "", 0, "")

					assertHasPolicyRule(updPolicy, "Ingress", "Allow", "192.168.2.1/32", 0, "192.168.1.1/32", 22, "TCP")
					assertHasPolicyRule(updPolicy, "Egress", "Allow", "192.168.1.1/32", 0, "192.168.3.1/32", 80, "UDP")
					assertHasPolicyRule(updPolicy, "Ingress", "Drop", "", 0, "192.168.1.1/32", 0, "")
					assertHasPolicyRule(updPolicy, "Egress", "Drop", "192.168.1.1/32", 0, "", 0, "")
				})
			})

			When("remove all ingress ports", func() {
				var updPolicy *securityv1alpha1.SecurityPolicy

				BeforeEach(func() {
					updPolicy = policy.DeepCopy()
					updPolicy.Spec.IngressRules[0].Ports = nil

					By(fmt.Sprintf("update policy %s ingress rule with empty ports", policy.Name))
					mustUpdatePolicy(ctx, updPolicy)
				})
				It("should replace ingress policy rule ports", func() {
					assertCompleteRuleNum(4)

					// empty Ports matches all ports
					assertNoPolicyRule(policy, "Ingress", "Allow", "192.168.2.1/32", 0, "192.168.1.1/32", 22, "TCP")
					assertHasPolicyRule(policy, "Ingress", "Allow", "192.168.2.1/32", 0, "192.168.1.1/32", 0, "")
				})
			})
			When("update ingress protocol", func() {
				var updPolicy *securityv1alpha1.SecurityPolicy

				BeforeEach(func() {
					protocol := securityv1alpha1.ProtocolUDP
					updPolicy = policy.DeepCopy()
					updPolicy.Spec.IngressRules[0].Ports[0].Protocol = protocol

					By(fmt.Sprintf("update policy %s ingress rule with new protocol %s", policy.Name, protocol))
					mustUpdatePolicy(ctx, updPolicy)
				})
				It("should replace ingress policy rule protocol", func() {
					assertCompleteRuleNum(4)

					assertNoPolicyRule(policy, "Ingress", "Allow", "192.168.2.1/32", 0, "192.168.1.1/32", 22, "TCP")
					assertHasPolicyRule(policy, "Ingress", "Allow", "192.168.2.1/32", 0, "192.168.1.1/32", 22, "UDP")
				})
			})
			When("update egress portrange", func() {
				var updPolicy *securityv1alpha1.SecurityPolicy

				BeforeEach(func() {
					portRange := "8080-8082"
					updPolicy = policy.DeepCopy()
					updPolicy.Spec.EgressRules[0].Ports[0].PortRange = portRange

					By(fmt.Sprintf("update policy %s ingress rule with new portRange %s", policy.Name, portRange))
					mustUpdatePolicy(ctx, updPolicy)
				})
				It("should sync egress policy rules", func() {
					assertCompleteRuleNum(4)
					assertNoPolicyRule(policy, "Egress", "Allow", "192.168.1.1/32", 0, "192.168.3.1/32", 80, "UDP")
					assertHasPolicyRuleWithPortRange(policy, "Egress", "Allow", "192.168.1.1/32",
						0, 0, "192.168.3.1/32", 8080, 0xfffe, "UDP")
					assertHasPolicyRule(policy, "Egress", "Allow", "192.168.1.1/32",
						0, "192.168.3.1/32", 8082, "UDP")

				})
			})

			When("remove security policy", func() {
				BeforeEach(func() {
					Expect(k8sClient.Delete(ctx, policy)).Should(Succeed())
				})

				It("should remove all the policy generate rules", func() {
					assertPolicyRulesNum(policy, 0)
					assertCompleteRuleNum(0)
				})
			})

			When("enable policy SymmetricMode", func() {
				var updPolicy *securityv1alpha1.SecurityPolicy

				BeforeEach(func() {
					updPolicy = policy.DeepCopy()
					updPolicy.Spec.SymmetricMode = true

					By(fmt.Sprintf("update policy %s with SymmetricMode enable", policy.Name))
					mustUpdatePolicy(ctx, updPolicy)
				})

				It("should generated symmetric policy rules", func() {
					// 2 ingress, 2 egress, 2 default rules
					assertPolicyRulesNum(policy, 6)
					assertCompleteRuleNum(4)

					// ingress symmetry egress rule
					assertHasPolicyRule(policy, "Egress", "Allow", "192.168.2.1/32", 0, "192.168.1.1/32", 22, "TCP")
					// egress symmetry ingress rule
					assertHasPolicyRule(policy, "Ingress", "Allow", "192.168.1.1/32", 0, "192.168.3.1/32", 80, "UDP")
				})
			})

			When("change enable ingress only", func() {
				var updPolicy *securityv1alpha1.SecurityPolicy

				BeforeEach(func() {
					updPolicy = policy.DeepCopy()
					updPolicy.Spec.PolicyTypes = []networkingv1.PolicyType{networkingv1.PolicyTypeIngress}

					By(fmt.Sprintf("update policy %s enable ingress rule only", policy.Name))
					mustUpdatePolicy(ctx, updPolicy)
				})
				It("should delete egress policy rules", func() {
					assertPolicyRulesNum(policy, 2)
					assertCompleteRuleNum(2)

					assertNoPolicyRule(policy, "Egress", "Allow", "192.168.1.1/32", 0, "192.168.3.1/32", 80, "UDP")
					assertNoPolicyRule(policy, "Egress", "Drop", "192.168.1.1/32", 0, "", 0, "")
				})
			})
			When("change enable egress only", func() {
				var updPolicy *securityv1alpha1.SecurityPolicy

				BeforeEach(func() {
					updPolicy = policy.DeepCopy()
					updPolicy.Spec.PolicyTypes = []networkingv1.PolicyType{networkingv1.PolicyTypeEgress}

					By(fmt.Sprintf("update policy %s enable egress rule only", policy.Name))
					mustUpdatePolicy(ctx, updPolicy)
				})
				It("should delete ingress policy rules", func() {
					assertPolicyRulesNum(policy, 2)
					assertCompleteRuleNum(2)

					assertNoPolicyRule(policy, "Ingress", "Allow", "192.168.2.1/32", 0, "192.168.1.1/32", 22, "TCP")
					assertNoPolicyRule(policy, "Ingress", "Drop", "", 0, "192.168.1.1/32", 0, "")
				})
			})
		})

		When("create a sample policy with SymmetricMode enable", func() {
			var policy *securityv1alpha1.SecurityPolicy

			BeforeEach(func() {
				policy = newTestPolicy(group1, group2, group3, newTestPort("TCP", "443"), newTestPort("UDP", "123"))
				policy.Spec.SymmetricMode = true

				By(fmt.Sprintf("create policy %s with SymmetricMode enable", policy.Name))
				Expect(k8sClient.Create(ctx, policy)).Should(Succeed())
			})

			It("should flatten policy to rules", func() {
				assertPolicyRulesNum(policy, 6)
				assertCompleteRuleNum(4)

				assertHasPolicyRule(policy, "Ingress", "Allow", "192.168.2.1/32", 0, "192.168.1.1/32", 443, "TCP")
				assertHasPolicyRule(policy, "Egress", "Allow", "192.168.1.1/32", 0, "192.168.3.1/32", 123, "UDP")

				// symmetry rules
				assertHasPolicyRule(policy, "Egress", "Allow", "192.168.2.1/32", 0, "192.168.1.1/32", 443, "TCP")
				assertHasPolicyRule(policy, "Ingress", "Allow", "192.168.1.1/32", 0, "192.168.3.1/32", 123, "UDP")

				// default ingress/egress rule (drop all to/from source)
				assertHasPolicyRule(policy, "Ingress", "Drop", "", 0, "192.168.1.1/32", 0, "")
				assertHasPolicyRule(policy, "Egress", "Drop", "192.168.1.1/32", 0, "", 0, "")
			})

			When("disable policy SymmetricMode", func() {
				var updPolicy *securityv1alpha1.SecurityPolicy

				BeforeEach(func() {
					updPolicy = policy.DeepCopy()
					updPolicy.Spec.SymmetricMode = false

					By(fmt.Sprintf("update policy %s with SymmetricMode disable", policy.Name))
					mustUpdatePolicy(ctx, updPolicy)
				})

				It("should remove symmetric policy rules", func() {
					assertPolicyRulesNum(policy, 4)
					assertCompleteRuleNum(4)

					assertNoPolicyRule(policy, "Egress", "Allow", "192.168.2.1/32", 0, "192.168.1.1/32", 443, "TCP")
					assertNoPolicyRule(policy, "Ingress", "Allow", "192.168.1.1/32", 0, "192.168.3.1/32", 123, "UDP")
				})
			})
		})

		When("create a sample policy with enable ingress only", func() {
			var policy *securityv1alpha1.SecurityPolicy

			BeforeEach(func() {
				policy = newTestPolicy(group1, group2, group3, newTestPort("TCP", "443"), newTestPort("UDP", "123"))
				policy.Spec.PolicyTypes = []networkingv1.PolicyType{networkingv1.PolicyTypeIngress}

				By(fmt.Sprintf("create policy %s with enable ingress only", policy.Name))
				Expect(k8sClient.Create(ctx, policy)).Should(Succeed())
			})

			It("should flatten policy to rules", func() {
				assertPolicyRulesNum(policy, 2)
				assertCompleteRuleNum(2)

				assertHasPolicyRule(policy, "Ingress", "Allow", "192.168.2.1/32", 0, "192.168.1.1/32", 443, "TCP")
				assertHasPolicyRule(policy, "Ingress", "Drop", "", 0, "192.168.1.1/32", 0, "")

				// Only ingress specified, egress rule should not generate
				assertNoPolicyRule(policy, "Egress", "Allow", "192.168.1.1/32", 0, "192.168.3.1/32", 123, "UDP")
				assertNoPolicyRule(policy, "Egress", "Drop", "192.168.1.1/32", 0, "", 0, "")
			})
		})

		When("create a sample policy with enable egress only", func() {
			var policy *securityv1alpha1.SecurityPolicy

			BeforeEach(func() {
				policy = newTestPolicy(group1, group2, group3, newTestPort("TCP", "443"), newTestPort("UDP", "123"))
				policy.Spec.PolicyTypes = []networkingv1.PolicyType{networkingv1.PolicyTypeEgress}

				By(fmt.Sprintf("create policy %s with enable ingress only", policy.Name))
				Expect(k8sClient.Create(ctx, policy)).Should(Succeed())
			})

			It("should flatten policy to rules", func() {
				assertPolicyRulesNum(policy, 2)
				assertCompleteRuleNum(2)

				assertHasPolicyRule(policy, "Egress", "Allow", "192.168.1.1/32", 0, "192.168.3.1/32", 123, "UDP")
				assertHasPolicyRule(policy, "Egress", "Drop", "192.168.1.1/32", 0, "", 0, "")

				// Only egress specified, ingress rule should not generate
				assertNoPolicyRule(policy, "Ingress", "Allow", "192.168.2.1/32", 0, "192.168.1.1/32", 443, "TCP")
				assertNoPolicyRule(policy, "Ingress", "Drop", "", 0, "192.168.1.1/32", 0, "")

			})
		})
		When("create a simple policy without drop", func() {
			var policy *securityv1alpha1.SecurityPolicy

			BeforeEach(func() {
				policy = newTestPolicy(group1, group2, group3, newTestPort("TCP", "443"), newTestPort("UDP", "123"))
				policy.Spec.PolicyTypes = []networkingv1.PolicyType{networkingv1.PolicyTypeEgress}
				policy.Spec.DefaultRule = securityv1alpha1.DefaultRuleNone
				By(fmt.Sprintf("create policy %s without drop", policy.Name))
				Expect(k8sClient.Create(ctx, policy)).Should(Succeed())
			})

			It("should not have default rules", func() {
				assertPolicyRulesNum(policy, 1)

				assertHasPolicyRule(policy, "Egress", "Allow", "192.168.1.1/32", 0, "192.168.3.1/32", 123, "UDP")
				assertNoPolicyRule(policy, "Egress", "Drop", "192.168.1.1/32", 0, "", 0, "")

				// Only egress specified, ingress rule should not generate
				assertNoPolicyRule(policy, "Ingress", "Allow", "192.168.2.1/32", 0, "192.168.1.1/32", 443, "TCP")
				assertNoPolicyRule(policy, "Ingress", "Drop", "", 0, "192.168.1.1/32", 0, "")

			})
		})

		When("create a sample policy with no PolicyTypes specified", func() {
			var policy *securityv1alpha1.SecurityPolicy

			BeforeEach(func() {
				policy = newTestPolicy(group1, group2, group3, newTestPort("TCP", "443"), newTestPort("UDP", "123"))
				policy.Spec.PolicyTypes = []networkingv1.PolicyType{}

				By(fmt.Sprintf("create policy %s with enable ingress only", policy.Name))
				Expect(k8sClient.Create(ctx, policy)).Should(Succeed())
			})

			It("should flatten policy to rules", func() {
				// Ingress and Egress exists on SecurityPolicy, should generate both ingress rule and egress rule
				assertPolicyRulesNum(policy, 4)
				assertCompleteRuleNum(4)

				assertHasPolicyRule(policy, "Egress", "Allow", "192.168.1.1/32", 0, "192.168.3.1/32", 123, "UDP")
				assertHasPolicyRule(policy, "Egress", "Drop", "192.168.1.1/32", 0, "", 0, "")

				assertHasPolicyRule(policy, "Ingress", "Allow", "192.168.2.1/32", 0, "192.168.1.1/32", 443, "TCP")
				assertHasPolicyRule(policy, "Ingress", "Drop", "", 0, "192.168.1.1/32", 0, "")

			})
		})

		When("create two same sample policy", func() {
			var policy01, policy02 *securityv1alpha1.SecurityPolicy

			BeforeEach(func() {
				policy01 = newTestPolicy(group1, group2, group3, newTestPort("TCP", "443"), newTestPort("UDP", "123"))
				By(fmt.Sprintf("create policy %s without drop", policy01.Name))
				Expect(k8sClient.Create(ctx, policy01)).Should(Succeed())

				policy02 = newTestPolicy(group1, group2, group3, newTestPort("TCP", "443"), newTestPort("UDP", "123"))
				By(fmt.Sprintf("create policy %s without drop", policy02.Name))
				Expect(k8sClient.Create(ctx, policy02)).Should(Succeed())
			})

			It("should flatten policy to rules", func() {
				assertPolicyRulesNum(policy01, 4)
				assertPolicyRulesNum(policy02, 4)
				assertCompleteRuleNum(8)

				assertHasPolicyRule(policy01, "Egress", "Allow", "192.168.1.1/32", 0, "192.168.3.1/32", 123, "UDP")
				assertHasPolicyRule(policy01, "Egress", "Drop", "192.168.1.1/32", 0, "", 0, "")
				assertHasPolicyRule(policy01, "Ingress", "Allow", "192.168.2.1/32", 0, "192.168.1.1/32", 443, "TCP")
				assertHasPolicyRule(policy01, "Ingress", "Drop", "", 0, "192.168.1.1/32", 0, "")
				assertHasPolicyRule(policy02, "Egress", "Allow", "192.168.1.1/32", 0, "192.168.3.1/32", 123, "UDP")
				assertHasPolicyRule(policy02, "Egress", "Drop", "192.168.1.1/32", 0, "", 0, "")
				assertHasPolicyRule(policy02, "Ingress", "Allow", "192.168.2.1/32", 0, "192.168.1.1/32", 443, "TCP")
				assertHasPolicyRule(policy02, "Ingress", "Drop", "", 0, "192.168.1.1/32", 0, "")
			})

			When("remove one of security policy", func() {
				BeforeEach(func() {
					Expect(k8sClient.Delete(ctx, policy01)).Should(Succeed())
				})

				It("should not hang on policy rule remove", func() {
					assertPolicyRulesNum(policy01, 0)
					assertPolicyRulesNum(policy02, 4)
					assertCompleteRuleNum(4)
				})

				When("remove another security policy", func() {
					BeforeEach(func() {
						By("wait for policy rule generated")
						time.Sleep(5 * time.Second)
						By(fmt.Sprintf("delete policy %+v", policy02))
						Expect(k8sClient.Delete(ctx, policy02)).Should(Succeed())
					})

					It("should not hang on policy rule remove", func() {
						assertPolicyRulesNum(policy01, 0)
						assertPolicyRulesNum(policy02, 0)
						assertCompleteRuleNum(0)
					})
				})
			})
		})
	})
})

var _ = Describe("GroupCache", func() {
	var groupCache *cache.GroupCache

	BeforeEach(func() {
		groupCache = cache.NewGroupCache()
	})

	When("add a groupmembers to group cache", func() {
		var members *groupv1alpha1.GroupMembers
		var endpoint *securityv1alpha1.Endpoint

		BeforeEach(func() {
			endpoint = newTestEndpoint("192.168.1.1")
			members = newTestGroupMembers(0, endpointToMember(endpoint)).GroupMembers
			groupCache.AddGroupMembership(members)
		})
		AfterEach(func() {
			groupCache.DelGroupMembership(members.Name)
		})

		It("should list IPBlocks of members", func() {
			revision, ipBlocks, exist := groupCache.ListGroupIPBlocks(members.Name)
			Expect(exist).Should(BeTrue())
			Expect(revision).Should(Equal(members.Revision))
			Expect(ipBlocks).Should(ConsistOf("192.168.1.1/32"))
		})

		When("add and apply a patch to group cache", func() {
			var patch *groupv1alpha1.GroupMembersPatch
			var addEp *securityv1alpha1.Endpoint

			BeforeEach(func() {
				addEp = newTestEndpoint("192.168.1.2")
				patch = newTestGroupMembersPatch(members.Name, members.Revision, endpointToMember(addEp), nil, nil)

				By("add and apply group patch")
				groupCache.AddPatch(patch)
				nextPatch := groupCache.NextPatch(members.Name)
				Expect(nextPatch).NotTo(BeNil())
				groupCache.ApplyPatch(nextPatch)
			})

			It("should applied to members and patch length be zero", func() {
				revision, ipBlocks, exist := groupCache.ListGroupIPBlocks(members.Name)
				Expect(exist).Should(BeTrue())
				Expect(revision).Should(Equal(members.Revision + 1))
				Expect(ipBlocks).Should(ConsistOf("192.168.1.1/32", "192.168.1.2/32"))

				Expect(groupCache.PatchLen(members.Name)).Should(BeZero())
			})
		})
	})
})

var _ = Describe("CompleteRuleCache", func() {
	var completeRuleCache storecache.Indexer

	BeforeEach(func() {
		completeRuleCache = cache.NewCompleteRuleCache()
	})

	When("add a completerule to rule cache", func() {
		var policyNamespacedName, ruleID, srcGroup, dstGroup string

		BeforeEach(func() {
			policyNamespacedName = rand.String(6) + "/" + rand.String(6)
			ruleID = fmt.Sprintf("%s/%s", policyNamespacedName, rand.String(6))
			srcGroup = rand.String(6)
			dstGroup = rand.String(6)

			Expect(completeRuleCache.Add(newTestCompleteRule(ruleID, srcGroup, dstGroup))).Should(Succeed())
		})
		AfterEach(func() {
			Expect(completeRuleCache.Delete(&cache.CompleteRule{RuleID: ruleID})).Should(Succeed())
		})

		It("should get complete rule by policy index", func() {
			objs, err := completeRuleCache.ByIndex(cache.PolicyIndex, policyNamespacedName)
			Expect(err).Should(Succeed())
			Expect(objs).Should(HaveLen(1))
			Expect(objs[0].(*cache.CompleteRule).RuleID).Should(Equal(ruleID))
		})

		It("should get complete rule by source group index", func() {
			objs, err := completeRuleCache.ByIndex(cache.GroupIndex, srcGroup)
			Expect(err).Should(Succeed())
			Expect(objs).Should(HaveLen(1))
			Expect(objs[0].(*cache.CompleteRule).RuleID).Should(Equal(ruleID))
		})

		It("should get complete rule by destination group index", func() {
			objs, err := completeRuleCache.ByIndex(cache.GroupIndex, dstGroup)
			Expect(err).Should(Succeed())
			Expect(objs).Should(HaveLen(1))
			Expect(objs[0].(*cache.CompleteRule).RuleID).Should(Equal(ruleID))
		})

		It("should get complete rule by ruleID", func() {
			obj, exists, err := completeRuleCache.GetByKey(ruleID)
			Expect(err).Should(Succeed())
			Expect(exists).Should(BeTrue())
			Expect(obj.(*cache.CompleteRule).RuleID).Should(Equal(ruleID))
		})
	})
})

func TestFlattenPorts(t *testing.T) {
	testCases := map[string]struct {
		portRange      *securityv1alpha1.SecurityPolicyPort
		expectRulePort []cache.RulePort
		expectError    bool
	}{
		"should unmarshal single port": {
			portRange: newTestPort("TCP", "80"),
			expectRulePort: []cache.RulePort{
				{DstPort: 80, DstPortMask: 0xffff, Protocol: "TCP"},
			},
		},
		"should unmarshal portRange": {
			portRange: newTestPort("TCP", "20-25"),
			expectRulePort: []cache.RulePort{
				{DstPort: 20, DstPortMask: 0xfffc, Protocol: "TCP"},
				{DstPort: 24, DstPortMask: 0xfffe, Protocol: "TCP"},
			},
		},
		"should unmarshal multiple portRange": {
			portRange: newTestPort("TCP", "20-25,80"),
			expectRulePort: []cache.RulePort{
				{DstPort: 20, DstPortMask: 0xfffc, Protocol: "TCP"},
				{DstPort: 24, DstPortMask: 0xfffe, Protocol: "TCP"},
				{DstPort: 80, DstPortMask: 0xffff, Protocol: "TCP"},
			},
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			ports, err := policy.FlattenPorts([]securityv1alpha1.SecurityPolicyPort{*tc.portRange})
			if tc.expectError && err == nil || !tc.expectError && err != nil {
				t.Fatalf("expect error: %t, but get error: %s", tc.expectError, err)
			}
			if !reflect.DeepEqual(ports, tc.expectRulePort) {
				t.Fatalf("expect rule ports: %+v, get rule ports: %+v", tc.expectRulePort, ports)
			}
		})
	}
}

func newTestPort(protocol, portRange string) *securityv1alpha1.SecurityPolicyPort {
	return &securityv1alpha1.SecurityPolicyPort{
		Protocol:  securityv1alpha1.Protocol(protocol),
		PortRange: portRange,
	}
}

func newTestPolicy(appliedTo, ingress, egress *testGroup, ingressPort, egressPort *securityv1alpha1.SecurityPolicyPort) *securityv1alpha1.SecurityPolicy {
	var name = "policy-test-" + rand.String(6)

	return &securityv1alpha1.SecurityPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: metav1.NamespaceDefault,
		},
		Spec: securityv1alpha1.SecurityPolicySpec{
			AppliedTo: []securityv1alpha1.ApplyToPeer{
				{
					EndpointSelector: appliedTo.endpointSelector,
				},
			},
			IngressRules: []securityv1alpha1.Rule{
				{
					Name: "ingress",
					Ports: []securityv1alpha1.SecurityPolicyPort{
						*ingressPort,
					},
					From: []securityv1alpha1.SecurityPolicyPeer{
						{
							EndpointSelector: ingress.endpointSelector,
						},
					},
				},
			},
			EgressRules: []securityv1alpha1.Rule{
				{
					Name: "egress",
					Ports: []securityv1alpha1.SecurityPolicyPort{
						*egressPort,
					},
					To: []securityv1alpha1.SecurityPolicyPeer{
						{
							EndpointSelector: egress.endpointSelector,
						},
					},
				},
			},
			PolicyTypes: []networkingv1.PolicyType{
				networkingv1.PolicyTypeIngress,
				networkingv1.PolicyTypeEgress,
			},
			Tier: constants.Tier2,
		},
	}
}

func newTestEndpoint(ip types.IPAddress) *securityv1alpha1.Endpoint {
	name := "endpoint-test-" + rand.String(6)
	id := name

	return &securityv1alpha1.Endpoint{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: metav1.NamespaceDefault,
		},
		Spec: securityv1alpha1.EndpointSpec{
			Reference: securityv1alpha1.EndpointReference{
				ExternalIDName:  id,
				ExternalIDValue: id,
			},
		},
		Status: securityv1alpha1.EndpointStatus{
			IPs: []types.IPAddress{ip},
		},
	}
}

type testGroup struct {
	*groupv1alpha1.GroupMembers
	endpointSelector *metav1.LabelSelector
}

func newTestGroupMembers(revision int32, members ...*groupv1alpha1.GroupMember) *testGroup {
	var testGroup = new(testGroup)
	var groupMembers []groupv1alpha1.GroupMember
	var namespaceDefault = metav1.NamespaceDefault

	for _, member := range members {
		groupMembers = append(groupMembers, *member)
	}

	testGroup.endpointSelector = &metav1.LabelSelector{
		MatchLabels: map[string]string{
			rand.String(10): rand.String(10),
		},
	}

	testGroup.GroupMembers = &groupv1alpha1.GroupMembers{
		ObjectMeta: metav1.ObjectMeta{
			Name: ctrlpolicy.GenerateGroupName(&groupv1alpha1.EndpointGroupSpec{
				EndpointSelector: testGroup.endpointSelector,
				Namespace:        &namespaceDefault,
			}),
			Namespace: metav1.NamespaceNone,
		},
		Revision:     revision,
		GroupMembers: groupMembers,
	}

	return testGroup
}

func newTestGroupMembersPatch(groupName string, revision int32, addMember, updMember, delMember *groupv1alpha1.GroupMember) *groupv1alpha1.GroupMembersPatch {
	name := "patch-test-" + rand.String(6)
	var addMembers, updMembers, delMembers []groupv1alpha1.GroupMember

	if addMember != nil {
		addMembers = append(addMembers, *addMember)
	}
	if updMember != nil {
		updMembers = append(updMembers, *updMember)
	}
	if delMember != nil {
		delMembers = append(delMembers, *delMember)
	}

	return &groupv1alpha1.GroupMembersPatch{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: metav1.NamespaceNone,
		},
		AppliedToGroupMembers: groupv1alpha1.GroupMembersReference{
			Name:     groupName,
			Revision: revision,
		},
		AddedGroupMembers:   addMembers,
		UpdatedGroupMembers: updMembers,
		RemovedGroupMembers: delMembers,
	}
}

func newTestCompleteRule(ruleId string, srcGroup, dstGroup string) *cache.CompleteRule {
	return &cache.CompleteRule{
		RuleID:    ruleId,
		SrcGroups: map[string]int32{srcGroup: 1},
		DstGroups: map[string]int32{dstGroup: 1},
	}
}

func endpointToMember(ep *securityv1alpha1.Endpoint) *groupv1alpha1.GroupMember {
	return &groupv1alpha1.GroupMember{
		EndpointReference: groupv1alpha1.EndpointReference{
			ExternalIDName:  ep.Spec.Reference.ExternalIDName,
			ExternalIDValue: ep.Spec.Reference.ExternalIDValue,
		},
		IPs: ep.Status.IPs,
	}
}

func mustUpdatePolicy(ctx context.Context, policy *securityv1alpha1.SecurityPolicy) {
	var oldPolicy = &securityv1alpha1.SecurityPolicy{}

	Eventually(func() error {
		err := k8sClient.Get(ctx, k8stypes.NamespacedName{Name: policy.GetName(), Namespace: policy.GetNamespace()}, oldPolicy)
		if err != nil {
			return err
		}
		policy.ObjectMeta = oldPolicy.ObjectMeta
		return k8sClient.Update(ctx, policy)
	}, timeout, interval).Should(Succeed())
}

func assertHasPolicyRule(policy *securityv1alpha1.SecurityPolicy,
	direction, action, srcCidr string, srcPort uint16, dstCidr string, dstPort uint16, protocol string) {

	Eventually(func() bool {
		var policyRuleList = getRuleByPolicy(policy)

		var tier = policy.Spec.Tier

		for _, rule := range policyRuleList {
			if tier == rule.Tier &&
				direction == string(rule.Direction) &&
				action == string(rule.Action) &&
				srcCidr == rule.SrcIPAddr &&
				srcPort == rule.SrcPort &&
				dstCidr == rule.DstIPAddr &&
				dstPort == rule.DstPort &&
				protocol == rule.IPProtocol {
				return true
			}
		}
		return false
	}, timeout, interval).Should(BeTrue())
}

func assertHasPolicyRuleWithPortRange(policy *securityv1alpha1.SecurityPolicy,
	direction, action, srcCidr string, srcPort uint16, srcPortMask uint16, dstCidr string, dstPort uint16, dstPortMask uint16, protocol string) {
	Eventually(func() bool {
		var policyRuleList = getRuleByPolicy(policy)
		var tier = policy.Spec.Tier

		for _, rule := range policyRuleList {
			if tier == rule.Tier &&
				direction == string(rule.Direction) &&
				action == string(rule.Action) &&
				srcCidr == rule.SrcIPAddr &&
				srcPort == rule.SrcPort &&
				srcPortMask == rule.SrcPortMask &&
				dstCidr == rule.DstIPAddr &&
				dstPort == rule.DstPort &&
				dstPortMask == rule.DstPortMask &&
				protocol == rule.IPProtocol {
				return true
			}
		}
		return false
	}, timeout, interval).Should(BeTrue())
}

func assertNoPolicyRule(policy *securityv1alpha1.SecurityPolicy,
	direction, action, srcCidr string, srcPort uint16, dstCidr string, dstPort uint16, protocol string) {

	Eventually(func() bool {
		var policyRuleList = getRuleByPolicy(policy)

		var tier = policy.Spec.Tier

		for _, rule := range policyRuleList {
			if tier == rule.Tier &&
				direction == string(rule.Direction) &&
				action == string(rule.Action) &&
				srcCidr == rule.SrcIPAddr &&
				srcPort == rule.SrcPort &&
				dstCidr == rule.DstIPAddr &&
				dstPort == rule.DstPort &&
				protocol == rule.IPProtocol {
				return true
			}
		}
		return false
	}, timeout, interval).Should(BeFalse())
}

func getRuleByPolicy(policy *securityv1alpha1.SecurityPolicy) []cache.PolicyRule {
	var policyRuleList []cache.PolicyRule
	completeRules, _ := ruleCacheLister.ByIndex(cache.PolicyIndex, policy.Namespace+"/"+policy.Name)
	for _, completeRule := range completeRules {
		policyRuleList = append(policyRuleList, completeRule.(*cache.CompleteRule).ListRules()...)
	}
	return policyRuleList
}

func assertPolicyRulesNum(policy *securityv1alpha1.SecurityPolicy, numOfPolicyRules int) {
	Eventually(func() int {
		policyRuleList := getRuleByPolicy(policy)
		return len(policyRuleList)
	}, timeout, interval).Should(Equal(numOfPolicyRules))
}

func assertCompleteRuleNum(numOfCompleteRules int) {
	Eventually(func() int {
		return len(ruleCacheLister.ListKeys())
	}, timeout, interval).Should(Equal(numOfCompleteRules))
}
