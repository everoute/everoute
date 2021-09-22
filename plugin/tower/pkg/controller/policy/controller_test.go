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
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/rand"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/everoute/everoute/pkg/apis/security/v1alpha1"
	"github.com/everoute/everoute/pkg/constants"
	"github.com/everoute/everoute/plugin/tower/pkg/schema"
	. "github.com/everoute/everoute/plugin/tower/pkg/utils/testing"
)

var _ = Describe("PolicyController", func() {
	var ctx context.Context
	var labelA, labelB, labelC *schema.Label

	BeforeEach(func() {
		ctx = context.Background()

		labelA = NewRandomLabel()
		labelB = NewRandomLabel()
		labelC = NewRandomLabel()

		By(fmt.Sprintf("create labels: %+v, %+v, %+v", labelA, labelB, labelC))
		server.TrackerFactory().Label().CreateOrUpdate(labelA)
		server.TrackerFactory().Label().CreateOrUpdate(labelB)
		server.TrackerFactory().Label().CreateOrUpdate(labelC)
	})
	AfterEach(func() {
		server.TrackerFactory().ResetAll()
		err := crdClient.SecurityV1alpha1().SecurityPolicies(namespace).DeleteCollection(ctx,
			metav1.DeleteOptions{},
			metav1.ListOptions{},
		)
		Expect(err).Should(Succeed())
	})

	Describe("SecurityPolicy", func() {
		Context("Verity SecurityPolicy with ingress and egress", func() {
			When("create SecurityPolicy with Selector", func() {
				var policy *schema.SecurityPolicy
				var ingress, egress *schema.NetworkPolicyRule

				BeforeEach(func() {
					policy = NewSecurityPolicy(everouteCluster, false, labelA, labelB)
					ingress = NewNetworkPolicyRule("tcp", "20-80", "", labelB, labelC)
					egress = NewNetworkPolicyRule("udp", "123", "", labelA, labelC)
					policy.Ingress = append(policy.Ingress, *ingress)
					policy.Egress = append(policy.Egress, *egress)

					By(fmt.Sprintf("create SecurityPolicy %+v", policy))
					server.TrackerFactory().SecurityPolicy().CreateOrUpdate(policy)

					By("wait for v1alpha1.SecurityPolicy created")
					assertPoliciesNum(ctx, 1)
				})
				It("should generate expect policies", func() {
					assertPoliciesNum(ctx, 1)
					assertHasPolicy(ctx, constants.Tier1, true,
						NewSecurityPolicyRuleIngress("tcp", "20-80", "", labelB, labelC),
						NewSecurityPolicyRuleEgress("udp", "123", "", labelA, labelC),
						NewSecurityPolicyApplyPeer("", labelA, labelB),
					)
				})

				When("update SecurityPolicy Selector", func() {
					BeforeEach(func() {
						policy.Ingress[0].Selector = LabelAsReference(labelA)
						policy.Egress[0].Selector = LabelAsReference(labelB)
						By(fmt.Sprintf("update SecurityPolicy %+v", policy))
						server.TrackerFactory().SecurityPolicy().CreateOrUpdate(policy)
					})
					It("should update policy selector", func() {
						assertPoliciesNum(ctx, 1)
						assertHasPolicy(ctx, constants.Tier1, true,
							NewSecurityPolicyRuleIngress("tcp", "20-80", "", labelA),
							NewSecurityPolicyRuleEgress("udp", "123", "", labelB),
							NewSecurityPolicyApplyPeer("", labelA, labelB),
						)
					})
				})

				When("update the selector label value", func() {
					BeforeEach(func() {
						labelA.Value = rand.String(10)
						By(fmt.Sprintf("update Label %+v", labelA))
						server.TrackerFactory().Label().CreateOrUpdate(labelA)
					})
					It("should update policy selector value", func() {
						assertPoliciesNum(ctx, 1)
						assertHasPolicy(ctx, constants.Tier1, true,
							NewSecurityPolicyRuleIngress("tcp", "20-80", "", labelB, labelC),
							NewSecurityPolicyRuleEgress("udp", "123", "", labelA, labelC),
							NewSecurityPolicyApplyPeer("", labelA, labelB),
						)
					})
				})

				When("delete ingress rule", func() {
					BeforeEach(func() {
						policy.Ingress = nil
						By(fmt.Sprintf("update SecurityPolicy %+v", policy))
						server.TrackerFactory().SecurityPolicy().CreateOrUpdate(policy)
					})
					It("should update policy without ingress", func() {
						assertPoliciesNum(ctx, 1)
						assertHasPolicy(ctx, constants.Tier1, true,
							nil,
							NewSecurityPolicyRuleEgress("udp", "123", "", labelA, labelC),
							NewSecurityPolicyApplyPeer("", labelA, labelB),
						)
					})
				})

				When("delete egress rule", func() {
					BeforeEach(func() {
						policy.Egress = nil
						By(fmt.Sprintf("update SecurityPolicy %+v", policy))
						server.TrackerFactory().SecurityPolicy().CreateOrUpdate(policy)
					})
					It("should update policy without egress", func() {
						assertPoliciesNum(ctx, 1)
						assertHasPolicy(ctx, constants.Tier1, true,
							NewSecurityPolicyRuleIngress("tcp", "20-80", "", labelB, labelC),
							nil,
							NewSecurityPolicyApplyPeer("", labelA, labelB),
						)
					})
				})

				When("update SecurityPolicy with intragroup communicable", func() {
					BeforeEach(func() {
						policy.ApplyTo[0].Communicable = true
						By(fmt.Sprintf("update SecurityPolicy %+v", policy))
						server.TrackerFactory().SecurityPolicy().CreateOrUpdate(policy)
					})
					It("should generate policy for intragroup", func() {
						assertPoliciesNum(ctx, 2)
						assertHasPolicy(ctx, constants.Tier1, true,
							NewSecurityPolicyRuleIngress("tcp", "20-80", "", labelB, labelC),
							NewSecurityPolicyRuleEgress("udp", "123", "", labelA, labelC),
							NewSecurityPolicyApplyPeer("", labelA, labelB),
						)
						assertHasPolicy(ctx, constants.Tier1, false,
							NewSecurityPolicyRuleIngress("", "", "", labelA, labelB),
							NewSecurityPolicyRuleEgress("", "", "", labelA, labelB),
							NewSecurityPolicyApplyPeer("", labelA, labelB),
						)
					})
				})

				When("delete the SecurityPolicy", func() {
					BeforeEach(func() {
						By(fmt.Sprintf("delete SecurityPolicy %+v", policy))
						err := server.TrackerFactory().SecurityPolicy().Delete(policy.GetID())
						Expect(err).Should(Succeed())
					})
					It("should delete all policies", func() {
						assertPoliciesNum(ctx, 0)
					})
				})
			})

			When("create SecurityPolicy with IPBlocks", func() {
				var policy *schema.SecurityPolicy
				var ingress, egress *schema.NetworkPolicyRule

				BeforeEach(func() {
					policy = NewSecurityPolicy(everouteCluster, false, labelA, labelB)
					ingress = NewNetworkPolicyRule("tcp", "20-80", "192.168.0.0/24")
					egress = NewNetworkPolicyRule("udp", "123", "192.168.0.0/24")
					policy.Ingress = append(policy.Ingress, *ingress)
					policy.Egress = append(policy.Egress, *egress)

					By(fmt.Sprintf("create SecurityPolicy %+v", policy))
					server.TrackerFactory().SecurityPolicy().CreateOrUpdate(policy)

					By("wait for v1alpha1.SecurityPolicy created")
					assertPoliciesNum(ctx, 1)
				})
				It("should generate expect policies", func() {
					assertPoliciesNum(ctx, 1)
					assertHasPolicy(ctx, constants.Tier1, true,
						NewSecurityPolicyRuleIngress("tcp", "20-80", "192.168.0.0/24"),
						NewSecurityPolicyRuleEgress("udp", "123", "192.168.0.0/24"),
						NewSecurityPolicyApplyPeer("", labelA, labelB),
					)
				})

				When("update SecurityPolicy IPBlocks to IPAddress", func() {
					var newIP string

					BeforeEach(func() {
						newIP = "192.168.1.1"
						policy.Ingress[0].IPBlock = &newIP
						policy.Egress[0].IPBlock = &newIP

						By(fmt.Sprintf("update SecurityPolicy %+v", policy))
						server.TrackerFactory().SecurityPolicy().CreateOrUpdate(policy)
					})
					It("should update policy ipBlock value", func() {
						assertPoliciesNum(ctx, 1)
						assertHasPolicy(ctx, constants.Tier1, true,
							NewSecurityPolicyRuleIngress("tcp", "20-80", newIP+"/32"),
							NewSecurityPolicyRuleEgress("udp", "123", newIP+"/32"),
							NewSecurityPolicyApplyPeer("", labelA, labelB),
						)
					})
				})
			})

			When("create SecurityPolicy with allow all Ports", func() {
				var policy *schema.SecurityPolicy
				var ingress, egress *schema.NetworkPolicyRule

				BeforeEach(func() {
					policy = NewSecurityPolicy(everouteCluster, false, labelA, labelB)
					ingress = NewNetworkPolicyRule("", "", "", labelB, labelC)
					egress = NewNetworkPolicyRule("", "", "", labelA, labelC)
					policy.Ingress = append(policy.Ingress, *ingress)
					policy.Egress = append(policy.Egress, *egress)

					By(fmt.Sprintf("create SecurityPolicy %+v", policy))
					server.TrackerFactory().SecurityPolicy().CreateOrUpdate(policy)

					By("wait for v1alpha1.SecurityPolicy created")
					assertPoliciesNum(ctx, 1)
				})
				It("should create policy with allow all ports", func() {
					assertPoliciesNum(ctx, 1)
					assertHasPolicy(ctx, constants.Tier1, true,
						NewSecurityPolicyRuleIngress("", "", "", labelB, labelC),
						NewSecurityPolicyRuleEgress("", "", "", labelA, labelC),
						NewSecurityPolicyApplyPeer("", labelA, labelB),
					)
				})
			})

			When("create SecurityPolicy with intragroup communicable", func() {
				var policy *schema.SecurityPolicy
				var ingress, egress *schema.NetworkPolicyRule

				BeforeEach(func() {
					policy = NewSecurityPolicy(everouteCluster, true, labelA, labelB)
					ingress = NewNetworkPolicyRule("tcp", "20-80", "", labelB, labelC)
					egress = NewNetworkPolicyRule("udp", "123", "", labelA, labelC)
					policy.Ingress = append(policy.Ingress, *ingress)
					policy.Egress = append(policy.Egress, *egress)

					By(fmt.Sprintf("create SecurityPolicy %+v", policy))
					server.TrackerFactory().SecurityPolicy().CreateOrUpdate(policy)

					By("wait for v1alpha1.SecurityPolicy created")
					assertPoliciesNum(ctx, 2)
				})
				It("should generate expect policies", func() {
					assertPoliciesNum(ctx, 2)
					assertHasPolicy(ctx, constants.Tier1, true,
						NewSecurityPolicyRuleIngress("tcp", "20-80", "", labelB, labelC),
						NewSecurityPolicyRuleEgress("udp", "123", "", labelA, labelC),
						NewSecurityPolicyApplyPeer("", labelA, labelB),
					)
					assertHasPolicy(ctx, constants.Tier1, false,
						NewSecurityPolicyRuleIngress("", "", "", labelA, labelB),
						NewSecurityPolicyRuleEgress("", "", "", labelA, labelB),
						NewSecurityPolicyApplyPeer("", labelA, labelB),
					)
				})

				When("update SecurityPolicy intragroup not communicable", func() {
					BeforeEach(func() {
						policy.ApplyTo[0].Communicable = false
						By(fmt.Sprintf("update SecurityPolicy %+v", policy))
						server.TrackerFactory().SecurityPolicy().CreateOrUpdate(policy)
					})
					It("should delete intragroup policy", func() {
						assertPoliciesNum(ctx, 1)
						assertHasPolicy(ctx, constants.Tier1, true,
							NewSecurityPolicyRuleIngress("tcp", "20-80", "", labelB, labelC),
							NewSecurityPolicyRuleEgress("udp", "123", "", labelA, labelC),
							NewSecurityPolicyApplyPeer("", labelA, labelB),
						)
					})
				})
			})

			When("create SecurityPolicy with allow all traffics", func() {
				var policy *schema.SecurityPolicy

				BeforeEach(func() {
					policy = NewSecurityPolicy(everouteCluster, false, labelA, labelB)
					policy.Ingress = []schema.NetworkPolicyRule{{
						Type: schema.NetworkPolicyRuleTypeAll,
					}}
					policy.Egress = []schema.NetworkPolicyRule{{
						Type: schema.NetworkPolicyRuleTypeAll,
					}}
					By(fmt.Sprintf("create SecurityPolicy %+v", policy))
					server.TrackerFactory().SecurityPolicy().CreateOrUpdate(policy)

					By("wait for v1alpha1.SecurityPolicy created")
					assertPoliciesNum(ctx, 1)
				})
				It("should create policy allow all traffics", func() {
					assertPoliciesNum(ctx, 1)
					assertHasPolicy(ctx, constants.Tier1, true,
						NewSecurityPolicyRuleIngress("", "", ""),
						NewSecurityPolicyRuleEgress("", "", ""),
						NewSecurityPolicyApplyPeer("", labelA, labelB),
					)
				})
			})
		})

		When("create SecurityPolicy out of the EverouteCluster", func() {
			var policy *schema.SecurityPolicy
			var randomEverouteCluster string

			BeforeEach(func() {
				randomEverouteCluster = rand.String(10)
				policy = NewSecurityPolicy(randomEverouteCluster, false, labelA, labelB)

				By(fmt.Sprintf("create SecurityPolicy %+v", policy))
				server.TrackerFactory().SecurityPolicy().CreateOrUpdate(policy)
			})

			It("should not create any policy", func() {
				By("wait some time to wait for controller handle it")
				time.Sleep(3 * time.Second)
				By("should not reconcile SecurityPolicy out of EverouteCluster")
				assertPoliciesNum(ctx, 0)
			})
		})

		When("create SecurityPolicy with ingress only", func() {
			var policy *schema.SecurityPolicy
			var ingress *schema.NetworkPolicyRule

			BeforeEach(func() {
				policy = NewSecurityPolicy(everouteCluster, false, labelA, labelB)
				ingress = NewNetworkPolicyRule("tcp", "20-80", "", labelB, labelC)
				policy.Ingress = append(policy.Ingress, *ingress)

				By(fmt.Sprintf("create SecurityPolicy %+v", policy))
				server.TrackerFactory().SecurityPolicy().CreateOrUpdate(policy)

				By("wait for v1alpha1.SecurityPolicy created")
				assertPoliciesNum(ctx, 1)
			})
			It("should create policy with ingress only", func() {
				assertPoliciesNum(ctx, 1)
				assertHasPolicy(ctx, constants.Tier1, true,
					NewSecurityPolicyRuleIngress("tcp", "20-80", "", labelB, labelC),
					nil,
					NewSecurityPolicyApplyPeer("", labelA, labelB),
				)
			})
		})

		When("create SecurityPolicy with egress only", func() {
			var policy *schema.SecurityPolicy
			var egress *schema.NetworkPolicyRule

			BeforeEach(func() {
				policy = NewSecurityPolicy(everouteCluster, false, labelA, labelB)
				egress = NewNetworkPolicyRule("udp", "123", "", labelA, labelC)
				policy.Egress = append(policy.Egress, *egress)

				By(fmt.Sprintf("create SecurityPolicy %+v", policy))
				server.TrackerFactory().SecurityPolicy().CreateOrUpdate(policy)

				By("wait for v1alpha1.SecurityPolicy created")
				assertPoliciesNum(ctx, 1)
			})
			It("should create policy with egress only", func() {
				assertPoliciesNum(ctx, 1)
				assertHasPolicy(ctx, constants.Tier1, true,
					nil,
					NewSecurityPolicyRuleEgress("udp", "123", "", labelA, labelC),
					NewSecurityPolicyApplyPeer("", labelA, labelB),
				)
			})
		})

		When("create SecurityPolicy with no rules", func() {
			var policy *schema.SecurityPolicy

			BeforeEach(func() {
				policy = NewSecurityPolicy(everouteCluster, false, labelA, labelB)
				By(fmt.Sprintf("create SecurityPolicy %+v", policy))
				server.TrackerFactory().SecurityPolicy().CreateOrUpdate(policy)
			})

			It("should create policy with no rules", func() {
				assertPoliciesNum(ctx, 1)
				assertHasPolicy(ctx, constants.Tier1, true,
					nil,
					nil,
					NewSecurityPolicyApplyPeer("", labelA, labelB),
				)
			})
		})
	})

	Describe("IsolationPolicy", func() {
		var vm *schema.VM
		var vnicA, vnicB *schema.VMNic

		BeforeEach(func() {
			vm = NewRandomVM()
			vnicA = NewRandomVMNicAttachedTo(vm)
			vnicB = NewRandomVMNicAttachedTo(vm)

			By(fmt.Sprintf("create vm %+v with vnic %+v and %+v", vm, vnicA, vnicB))
			server.TrackerFactory().VM().CreateOrUpdate(vm)
		})

		When("create IsolationPolicy with completely isolation", func() {
			var policy *schema.IsolationPolicy

			BeforeEach(func() {
				policy = NewIsolationPolicy(everouteCluster, vm, schema.IsolationModeAll)
				By(fmt.Sprintf("create IsolationPolicy %+v", policy))
				server.TrackerFactory().IsolationPolicy().CreateOrUpdate(policy)
				By("wait for policy generated")
				assertPoliciesNum(ctx, 1)
			})

			It("should generate expect policies", func() {
				assertPoliciesNum(ctx, 1)
				assertHasPolicy(ctx, constants.Tier0, true,
					nil,
					nil,
					NewSecurityPolicyApplyPeer(vnicA.GetID()),
					NewSecurityPolicyApplyPeer(vnicB.GetID()),
				)
			})

			When("add new vnic to isolate vm", func() {
				var newVnic *schema.VMNic

				BeforeEach(func() {
					newVnic = NewRandomVMNicAttachedTo(vm)
					By(fmt.Sprintf("update vm %+v with new vnic %+v", vm, newVnic))
					server.TrackerFactory().VM().CreateOrUpdate(vm)
				})
				It("should update policy applied endpoints", func() {
					assertPoliciesNum(ctx, 1)
					assertHasPolicy(ctx, constants.Tier0, true,
						nil,
						nil,
						NewSecurityPolicyApplyPeer(vnicA.GetID()),
						NewSecurityPolicyApplyPeer(vnicB.GetID()),
						NewSecurityPolicyApplyPeer(newVnic.GetID()),
					)
				})
			})

			When("delete vnic from isolate vm", func() {
				BeforeEach(func() {
					vm.VMNics = []schema.VMNic{*vnicA}
					By(fmt.Sprintf("update vm %+v with delete vnic %+v", vm, vnicB))
					server.TrackerFactory().VM().CreateOrUpdate(vm)
				})
				It("should update policy applied endpoints", func() {
					assertPoliciesNum(ctx, 1)
					assertHasPolicy(ctx, constants.Tier0, true,
						nil,
						nil,
						NewSecurityPolicyApplyPeer(vnicA.GetID()),
					)
				})
			})

			When("delete all vnics from isolate vm", func() {
				BeforeEach(func() {
					By("make sure policies has been create")
					assertPoliciesNum(ctx, 1)

					By(fmt.Sprintf("update vm %+v with delete vnic %+v", vm, vnicB))
					vm.VMNics = nil
					server.TrackerFactory().VM().CreateOrUpdate(vm)
				})
				It("should delete all policies", func() {
					assertPoliciesNum(ctx, 0)
				})
			})
		})

		When("create IsolationPolicy with allow ingress traffics", func() {
			var policy *schema.IsolationPolicy
			var ingress *schema.NetworkPolicyRule

			BeforeEach(func() {
				policy = NewIsolationPolicy(everouteCluster, vm, schema.IsolationModePartial)
				ingress = NewNetworkPolicyRule("tcp", "22-80", "", labelA, labelC)
				policy.Ingress = append(policy.Ingress, *ingress)

				By(fmt.Sprintf("create IsolationPolicy %+v", policy))
				server.TrackerFactory().IsolationPolicy().CreateOrUpdate(policy)
			})

			It("should generate expect policies", func() {
				assertPoliciesNum(ctx, 1)
				assertHasPolicy(ctx, constants.Tier0, true,
					NewSecurityPolicyRuleIngress("tcp", "22-80", "", labelA, labelC),
					nil,
					NewSecurityPolicyApplyPeer(vnicA.GetID()),
					NewSecurityPolicyApplyPeer(vnicB.GetID()),
				)
			})
		})

		When("create IsolationPolicy with allow egress traffics", func() {
			var policy *schema.IsolationPolicy
			var egress *schema.NetworkPolicyRule

			BeforeEach(func() {
				policy = NewIsolationPolicy(everouteCluster, vm, schema.IsolationModePartial)
				egress = NewNetworkPolicyRule("udp", "123", "", labelA, labelB)
				policy.Egress = append(policy.Egress, *egress)

				By(fmt.Sprintf("create IsolationPolicy %+v", policy))
				server.TrackerFactory().IsolationPolicy().CreateOrUpdate(policy)
			})

			It("should generate expect policies", func() {
				assertPoliciesNum(ctx, 1)
				assertHasPolicy(ctx, constants.Tier0, true,
					nil,
					NewSecurityPolicyRuleEgress("udp", "123", "", labelA, labelB),
					NewSecurityPolicyApplyPeer(vnicA.GetID()),
					NewSecurityPolicyApplyPeer(vnicB.GetID()),
				)
			})
		})
	})
})

func assertPoliciesNum(ctx context.Context, numOfPolicies int) {
	Eventually(func() int {
		policyList, err := crdClient.SecurityV1alpha1().SecurityPolicies(namespace).List(ctx, metav1.ListOptions{})
		Expect(err).ShouldNot(HaveOccurred())
		return len(policyList.Items)
	}, timeout, interval).Should(Equal(numOfPolicies))
}

func assertHasPolicy(ctx context.Context, tier string, symmetricMode bool, ingress, egress *v1alpha1.Rule, applyToPeers ...v1alpha1.ApplyToPeer) {
	Eventually(func() bool {
		policyList, err := crdClient.SecurityV1alpha1().SecurityPolicies(namespace).List(ctx, metav1.ListOptions{})
		Expect(err).Should(Succeed())
		for item := range policyList.Items {
			if matchPolicy(&policyList.Items[item], tier, symmetricMode, ingress, egress, applyToPeers...) {
				return true
			}
		}
		return false
	}, timeout, interval).Should(BeTrue())
}

func matchPolicy(policy *v1alpha1.SecurityPolicy, tier string, symmetricMode bool, ingress, egress *v1alpha1.Rule, applyToPeers ...v1alpha1.ApplyToPeer) bool {
	matchAllPolicyTypes := func(policyTypes []networkingv1.PolicyType) bool {
		if len(policyTypes) != 2 {
			return false
		}
		policyTypeSet := sets.NewString(string(networkingv1.PolicyTypeIngress), string(networkingv1.PolicyTypeEgress))
		for _, policyType := range policyTypes {
			policyTypeSet.Delete(string(policyType))
		}
		return policyTypeSet.Len() == 0
	}

	matchRules := func(rule []v1alpha1.Rule, expectRule *v1alpha1.Rule) bool {
		if expectRule == nil {
			return len(rule) == 0
		}
		if len(rule) != 1 {
			return false
		}
		return (len(rule[0].Ports) == 0 && len(expectRule.Ports) == 0 || reflect.DeepEqual(rule[0].Ports, expectRule.Ports)) &&
			(len(rule[0].From) == 0 && len(expectRule.From) == 0 || reflect.DeepEqual(rule[0].From, expectRule.From)) &&
			(len(rule[0].To) == 0 && len(expectRule.To) == 0 || reflect.DeepEqual(rule[0].To, expectRule.To))
	}

	matchApplyPeers := func(applyPeers, expectApplyPeers []v1alpha1.ApplyToPeer) bool {
		if len(applyToPeers) != len(expectApplyPeers) {
			return false
		}
		sort.Sort(ApplyPeers(applyPeers))
		sort.Sort(ApplyPeers(expectApplyPeers))
		return reflect.DeepEqual(applyPeers, expectApplyPeers)
	}

	return policy.Namespace == namespace &&
		policy.Spec.Tier == tier &&
		policy.Spec.SymmetricMode == symmetricMode &&
		matchAllPolicyTypes(policy.Spec.PolicyTypes) &&
		matchRules(policy.Spec.IngressRules, ingress) &&
		matchRules(policy.Spec.EgressRules, egress) &&
		matchApplyPeers(policy.Spec.AppliedTo, applyToPeers)
}

type ApplyPeers []v1alpha1.ApplyToPeer

func (s ApplyPeers) Len() int      { return len(s) }
func (s ApplyPeers) Swap(i, j int) { s[i], s[j] = s[j], s[i] }
func (s ApplyPeers) Less(i, j int) bool {
	rawI, _ := json.Marshal(s[i])
	rawJ, _ := json.Marshal(s[j])
	return string(rawI) < string(rawJ)
}
