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
	"github.com/everoute/everoute/pkg/labels"
	"github.com/everoute/everoute/plugin/tower/pkg/controller/endpoint"
	"github.com/everoute/everoute/plugin/tower/pkg/schema"
	. "github.com/everoute/everoute/plugin/tower/pkg/utils/testing"
)

var _ = Describe("PolicyController", func() {
	var ctx context.Context
	var labelA, labelB, labelC *schema.Label

	BeforeEach(func() {
		ctx = context.Background()

		labelA = NewRandomLabel()
		labelB = NewLabel("@中文标签", "=>中文标签值")
		labelC = NewLabel("@中文标签", "@#!@$%^*)")

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
					policy = NewSecurityPolicy(everouteCluster, false, nil, labelA, labelB)
					ingress = NewNetworkPolicyRule("tcp", "20-80", nil, labelB, labelC)
					egress = NewNetworkPolicyRule("udp", "123", nil, labelA, labelC)
					policy.Ingress = append(policy.Ingress, *ingress)
					policy.Egress = append(policy.Egress, *egress)

					By(fmt.Sprintf("create SecurityPolicy %+v", policy))
					server.TrackerFactory().SecurityPolicy().CreateOrUpdate(policy)

					By("wait for v1alpha1.SecurityPolicy created")
					assertPoliciesNum(ctx, 1)
				})
				It("should generate expect policies", func() {
					assertPoliciesNum(ctx, 1)
					assertHasPolicy(ctx, constants.Tier2, true, "", v1alpha1.DefaultRuleDrop, allPolicyTypes(),
						NewSecurityPolicyRuleIngress("tcp", "20-80", nil, labelB, labelC),
						NewSecurityPolicyRuleEgress("udp", "123", nil, labelA, labelC),
						NewSecurityPolicyApplyPeer("", labelA, labelB),
					)
					assertAllowlist(ctx)
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
						assertHasPolicy(ctx, constants.Tier2, true, "", v1alpha1.DefaultRuleDrop, allPolicyTypes(),
							NewSecurityPolicyRuleIngress("tcp", "20-80", nil, labelA),
							NewSecurityPolicyRuleEgress("udp", "123", nil, labelB),
							NewSecurityPolicyApplyPeer("", labelA, labelB),
						)
						assertAllowlist(ctx)
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
						assertHasPolicy(ctx, constants.Tier2, true, "", v1alpha1.DefaultRuleDrop, allPolicyTypes(),
							NewSecurityPolicyRuleIngress("tcp", "20-80", nil, labelB, labelC),
							NewSecurityPolicyRuleEgress("udp", "123", nil, labelA, labelC),
							NewSecurityPolicyApplyPeer("", labelA, labelB),
						)
						assertAllowlist(ctx)
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
						assertHasPolicy(ctx, constants.Tier2, true, "", v1alpha1.DefaultRuleDrop, allPolicyTypes(),
							nil,
							NewSecurityPolicyRuleEgress("udp", "123", nil, labelA, labelC),
							NewSecurityPolicyApplyPeer("", labelA, labelB),
						)
						assertAllowlist(ctx)
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
						assertHasPolicy(ctx, constants.Tier2, true, "", v1alpha1.DefaultRuleDrop, allPolicyTypes(),
							NewSecurityPolicyRuleIngress("tcp", "20-80", nil, labelB, labelC),
							nil,
							NewSecurityPolicyApplyPeer("", labelA, labelB),
						)
						assertAllowlist(ctx)
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
						assertHasPolicy(ctx, constants.Tier2, true, "", v1alpha1.DefaultRuleDrop, allPolicyTypes(),
							NewSecurityPolicyRuleIngress("tcp", "20-80", nil, labelB, labelC),
							NewSecurityPolicyRuleEgress("udp", "123", nil, labelA, labelC),
							NewSecurityPolicyApplyPeer("", labelA, labelB),
						)
						assertHasPolicy(ctx, constants.Tier2, false, "", v1alpha1.DefaultRuleDrop, allPolicyTypes(),
							NewSecurityPolicyRuleIngress("", "", nil, labelA, labelB),
							NewSecurityPolicyRuleEgress("", "", nil, labelA, labelB),
							NewSecurityPolicyApplyPeer("", labelA, labelB),
						)
						assertAllowlist(ctx)
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

			When("create SecurityPolicy with IPBlocks and Except IPBlock", func() {
				var policy *schema.SecurityPolicy
				var ingress, egress *schema.NetworkPolicyRule

				BeforeEach(func() {
					policy = NewSecurityPolicy(everouteCluster, false, nil, labelA, labelB)
					ingress = NewNetworkPolicyRule("tcp", "20-80", &networkingv1.IPBlock{CIDR: "192.168.0.0/24", Except: []string{"192.168.0.1"}})
					egress = NewNetworkPolicyRule("udp", "123", &networkingv1.IPBlock{CIDR: "192.168.1.0/24"})
					policy.Ingress = append(policy.Ingress, *ingress)
					policy.Egress = append(policy.Egress, *egress)

					By(fmt.Sprintf("create SecurityPolicy %+v", policy))
					server.TrackerFactory().SecurityPolicy().CreateOrUpdate(policy)

					By("wait for v1alpha1.SecurityPolicy created")
					assertPoliciesNum(ctx, 1)
				})
				It("should generate expect policies", func() {
					assertPoliciesNum(ctx, 1)
					assertHasPolicy(ctx, constants.Tier2, true, "", v1alpha1.DefaultRuleDrop, allPolicyTypes(),
						NewSecurityPolicyRuleIngress("tcp", "20-80", &networkingv1.IPBlock{CIDR: "192.168.0.0/24", Except: []string{"192.168.0.1/32"}}),
						NewSecurityPolicyRuleEgress("udp", "123", &networkingv1.IPBlock{CIDR: "192.168.1.0/24"}),
						NewSecurityPolicyApplyPeer("", labelA, labelB),
					)
					assertAllowlist(ctx)
				})

				When("update SecurityPolicy IPBlocks to IPAddress", func() {
					var newIP string

					BeforeEach(func() {
						newIP = "192.168.1.1"
						policy.Ingress[0].IPBlock = &newIP
						policy.Ingress[0].ExceptIPBlock = nil
						policy.Egress[0].IPBlock = &newIP

						By(fmt.Sprintf("update SecurityPolicy %+v", policy))
						server.TrackerFactory().SecurityPolicy().CreateOrUpdate(policy)
					})
					It("should update policy ipBlock value", func() {
						assertPoliciesNum(ctx, 1)
						assertHasPolicy(ctx, constants.Tier2, true, "", v1alpha1.DefaultRuleDrop, allPolicyTypes(),
							NewSecurityPolicyRuleIngress("tcp", "20-80", &networkingv1.IPBlock{CIDR: newIP + "/32"}),
							NewSecurityPolicyRuleEgress("udp", "123", &networkingv1.IPBlock{CIDR: newIP + "/32"}),
							NewSecurityPolicyApplyPeer("", labelA, labelB),
						)
						assertAllowlist(ctx)
					})
				})

				It("update SecurityPolicy peer with disable symmetric", func() {
					policy.Ingress[0].OnlyApplyToExternalTraffic = true
					server.TrackerFactory().SecurityPolicy().CreateOrUpdate(policy)

					assertPoliciesNum(ctx, 1)
					expectIngress := NewSecurityPolicyRuleIngress("tcp", "20-80", &networkingv1.IPBlock{CIDR: "192.168.0.0/24", Except: []string{"192.168.0.1/32"}})
					expectIngress.From[0].DisableSymmetric = true
					assertHasPolicy(ctx, constants.Tier2, true, "", v1alpha1.DefaultRuleDrop, allPolicyTypes(),
						expectIngress,
						NewSecurityPolicyRuleEgress("udp", "123", &networkingv1.IPBlock{CIDR: "192.168.1.0/24"}),
						NewSecurityPolicyApplyPeer("", labelA, labelB),
					)
					assertAllowlist(ctx)
				})
			})

			When("create SecurityPolicy with allow all Ports", func() {
				var policy *schema.SecurityPolicy
				var ingress, egress *schema.NetworkPolicyRule

				BeforeEach(func() {
					policy = NewSecurityPolicy(everouteCluster, false, nil, labelA, labelB)
					ingress = NewNetworkPolicyRule("", "", nil, labelB, labelC)
					egress = NewNetworkPolicyRule("", "", nil, labelA, labelC)
					policy.Ingress = append(policy.Ingress, *ingress)
					policy.Egress = append(policy.Egress, *egress)

					By(fmt.Sprintf("create SecurityPolicy %+v", policy))
					server.TrackerFactory().SecurityPolicy().CreateOrUpdate(policy)

					By("wait for v1alpha1.SecurityPolicy created")
					assertPoliciesNum(ctx, 1)
				})
				It("should create policy with allow all ports", func() {
					assertPoliciesNum(ctx, 1)
					assertHasPolicy(ctx, constants.Tier2, true, "", v1alpha1.DefaultRuleDrop, allPolicyTypes(),
						NewSecurityPolicyRuleIngress("", "", nil, labelB, labelC),
						NewSecurityPolicyRuleEgress("", "", nil, labelA, labelC),
						NewSecurityPolicyApplyPeer("", labelA, labelB),
					)
					assertAllowlist(ctx)
				})
			})

			When("create SecurityPolicy with intragroup communicable", func() {
				var policy *schema.SecurityPolicy
				var ingress, egress *schema.NetworkPolicyRule

				BeforeEach(func() {
					policy = NewSecurityPolicy(everouteCluster, true, nil, labelA, labelB)
					ingress = NewNetworkPolicyRule("tcp", "20-80", nil, labelB, labelC)
					egress = NewNetworkPolicyRule("udp", "123", nil, labelA, labelC)
					policy.Ingress = append(policy.Ingress, *ingress)
					policy.Egress = append(policy.Egress, *egress)

					By(fmt.Sprintf("create SecurityPolicy %+v", policy))
					server.TrackerFactory().SecurityPolicy().CreateOrUpdate(policy)

					By("wait for v1alpha1.SecurityPolicy created")
					assertPoliciesNum(ctx, 2)
				})
				It("should generate expect policies", func() {
					assertPoliciesNum(ctx, 2)
					assertHasPolicy(ctx, constants.Tier2, true, "", v1alpha1.DefaultRuleDrop, allPolicyTypes(),
						NewSecurityPolicyRuleIngress("tcp", "20-80", nil, labelB, labelC),
						NewSecurityPolicyRuleEgress("udp", "123", nil, labelA, labelC),
						NewSecurityPolicyApplyPeer("", labelA, labelB),
					)
					assertAllowlist(ctx)
					assertHasPolicy(ctx, constants.Tier2, false, "", v1alpha1.DefaultRuleDrop, allPolicyTypes(),
						NewSecurityPolicyRuleIngress("", "", nil, labelA, labelB),
						NewSecurityPolicyRuleEgress("", "", nil, labelA, labelB),
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
						assertHasPolicy(ctx, constants.Tier2, true, "", v1alpha1.DefaultRuleDrop, allPolicyTypes(),
							NewSecurityPolicyRuleIngress("tcp", "20-80", nil, labelB, labelC),
							NewSecurityPolicyRuleEgress("udp", "123", nil, labelA, labelC),
							NewSecurityPolicyApplyPeer("", labelA, labelB),
						)
					})
				})

				When("update SecurityPolicy enforce mode to work", func() {
					BeforeEach(func() {
						policy.PolicyMode = schema.PolicyModeWork
						By(fmt.Sprintf("update SecurityPolicy %+v", policy))
						server.TrackerFactory().SecurityPolicy().CreateOrUpdate(policy)
					})
					It("should update intragroup policy", func() {
						assertHasPolicy(ctx, constants.Tier2, true, v1alpha1.WorkMode, v1alpha1.DefaultRuleDrop, allPolicyTypes(),
							NewSecurityPolicyRuleIngress("tcp", "20-80", nil, labelB, labelC),
							NewSecurityPolicyRuleEgress("udp", "123", nil, labelA, labelC),
							NewSecurityPolicyApplyPeer("", labelA, labelB),
						)
						assertHasPolicy(ctx, constants.Tier2, false, v1alpha1.WorkMode, v1alpha1.DefaultRuleDrop, allPolicyTypes(),
							NewSecurityPolicyRuleIngress("", "", nil, labelA, labelB),
							NewSecurityPolicyRuleEgress("", "", nil, labelA, labelB),
							NewSecurityPolicyApplyPeer("", labelA, labelB),
						)
						assertAllowlist(ctx)
					})
				})

				When("update SecurityPolicy enforce mode to monitor", func() {
					BeforeEach(func() {
						policy.PolicyMode = schema.PolicyModeMonitor
						By(fmt.Sprintf("update SecurityPolicy %+v", policy))
						server.TrackerFactory().SecurityPolicy().CreateOrUpdate(policy)
					})
					It("should update intragroup policy", func() {
						assertHasPolicy(ctx, constants.Tier2, true, v1alpha1.MonitorMode, v1alpha1.DefaultRuleDrop, allPolicyTypes(),
							NewSecurityPolicyRuleIngress("tcp", "20-80", nil, labelB, labelC),
							NewSecurityPolicyRuleEgress("udp", "123", nil, labelA, labelC),
							NewSecurityPolicyApplyPeer("", labelA, labelB),
						)
						assertHasPolicy(ctx, constants.Tier2, false, v1alpha1.MonitorMode, v1alpha1.DefaultRuleDrop, allPolicyTypes(),
							NewSecurityPolicyRuleIngress("", "", nil, labelA, labelB),
							NewSecurityPolicyRuleEgress("", "", nil, labelA, labelB),
							NewSecurityPolicyApplyPeer("", labelA, labelB),
						)
						assertAllowlist(ctx)
					})
				})
			})

			When("create SecurityPolicy with allow all traffics", func() {
				var policy *schema.SecurityPolicy

				BeforeEach(func() {
					policy = NewSecurityPolicy(everouteCluster, false, nil, labelA, labelB)
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
					assertHasPolicy(ctx, constants.Tier2, true, "", v1alpha1.DefaultRuleDrop, allPolicyTypes(),
						NewSecurityPolicyRuleIngress("", "", nil),
						NewSecurityPolicyRuleEgress("", "", nil),
						NewSecurityPolicyApplyPeer("", labelA, labelB),
					)
					assertAllowlist(ctx)
				})
			})

			When("create SecurityPolicy with empty apply type", func() {
				var policy *schema.SecurityPolicy
				var ingress, egress *schema.NetworkPolicyRule

				BeforeEach(func() {
					policy = NewSecurityPolicy(everouteCluster, false, nil, labelA, labelB)
					policy.ApplyTo[0].Type = ""
					ingress = NewNetworkPolicyRule("tcp", "20-80", nil, labelB, labelC)
					egress = NewNetworkPolicyRule("udp", "123", nil, labelA, labelC)
					policy.Ingress = append(policy.Ingress, *ingress)
					policy.Egress = append(policy.Egress, *egress)

					By(fmt.Sprintf("create SecurityPolicy %+v", policy))
					server.TrackerFactory().SecurityPolicy().CreateOrUpdate(policy)

					By("wait for v1alpha1.SecurityPolicy created")
					assertPoliciesNum(ctx, 1)
				})
				It("should generate expect policies", func() {
					assertPoliciesNum(ctx, 1)
					assertHasPolicy(ctx, constants.Tier2, true, "", v1alpha1.DefaultRuleDrop, allPolicyTypes(),
						NewSecurityPolicyRuleIngress("tcp", "20-80", nil, labelB, labelC),
						NewSecurityPolicyRuleEgress("udp", "123", nil, labelA, labelC),
						NewSecurityPolicyApplyPeer("", labelA, labelB),
					)
					assertAllowlist(ctx)
				})
			})
			When("create SecurityPolicy with Selector but empty labels", func() {
				var policy *schema.SecurityPolicy
				var ingress, egress *schema.NetworkPolicyRule

				BeforeEach(func() {
					policy = NewSecurityPolicy(everouteCluster, false, nil)
					ingress = NewNetworkPolicyRule("tcp", "20-80", nil, labelB, labelC)
					egress = NewNetworkPolicyRule("udp", "123", nil, labelA, labelC)
					policy.ApplyTo = []schema.SecurityPolicyApply{{Type: schema.SecurityPolicyTypeSelector, Communicable: true}}
					policy.Ingress = append(policy.Ingress, *ingress)
					policy.Egress = append(policy.Egress, *egress)

					By(fmt.Sprintf("create SecurityPolicy %+v", policy))
					server.TrackerFactory().SecurityPolicy().CreateOrUpdate(policy)
				})

				It("should generate expect policies", func() {
					assertPoliciesNum(ctx, 2)
					assertHasPolicy(ctx, constants.Tier2, true, "", v1alpha1.DefaultRuleDrop, allPolicyTypes(),
						NewSecurityPolicyRuleIngress("tcp", "20-80", nil, labelB, labelC),
						NewSecurityPolicyRuleEgress("udp", "123", nil, labelA, labelC),
						v1alpha1.ApplyToPeer{EndpointSelector: &labels.Selector{MatchNothing: true}},
					)

					assertHasPolicy(ctx, constants.Tier2, false, "", v1alpha1.DefaultRuleDrop, allPolicyTypes(),
						&v1alpha1.Rule{From: []v1alpha1.SecurityPolicyPeer{{EndpointSelector: &labels.Selector{MatchNothing: true}}}},
						&v1alpha1.Rule{To: []v1alpha1.SecurityPolicyPeer{{EndpointSelector: &labels.Selector{MatchNothing: true}}}},
						v1alpha1.ApplyToPeer{EndpointSelector: &labels.Selector{MatchNothing: true}},
					)
					assertAllowlist(ctx)
				})
			})

			When("create SecurityPolicy with alg protocol", func() {
				var policy *schema.SecurityPolicy
				var ingress, egress *schema.NetworkPolicyRule

				BeforeEach(func() {
					policy = NewSecurityPolicy(everouteCluster, false, nil, labelA, labelB)
					ingress = NewNetworkPolicyRule("", "", nil, labelB, labelC)
					NetworkPolicyRuleAddPorts(ingress, *NewNetworkPolicyRulePort("ALG", "FTP", "20-80"))
					egress = NewNetworkPolicyRule("", "", nil, labelA, labelC)
					NetworkPolicyRuleAddPorts(egress, *NewNetworkPolicyRulePort("ALG", "TFTP", ""))
					policy.Ingress = append(policy.Ingress, *ingress)
					policy.Egress = append(policy.Egress, *egress)

					By(fmt.Sprintf("create SecurityPolicy %+v", policy))
					server.TrackerFactory().SecurityPolicy().CreateOrUpdate(policy)

					By("wait for v1alpha1.SecurityPolicy created")
					assertPoliciesNum(ctx, 1)
				})
				It("should generate expect policies", func() {
					assertPoliciesNum(ctx, 1)
					assertHasPolicy(ctx, constants.Tier2, true, "", v1alpha1.DefaultRuleDrop, allPolicyTypes(),
						NewSecurityPolicyRuleIngress("TCP", "21", nil, labelB, labelC),
						NewSecurityPolicyRuleEgress("UDP", "69", nil, labelA, labelC),
						NewSecurityPolicyApplyPeer("", labelA, labelB),
					)
					assertAllowlist(ctx)
				})
			})
			When("SecurityPolicy with service", func() {
				var policy *schema.SecurityPolicy
				var ingress, egress *schema.NetworkPolicyRule
				var svcA, svcB, svcC *schema.NetworkPolicyRuleService
				var ipBlock1, ipBlock2 *networkingv1.IPBlock
				BeforeEach(func() {
					By("create service")
					svcA = NewService()
					svcB = NewService(*NewNetworkPolicyRulePort("TCP", "", "33-34"), *NewNetworkPolicyRulePort("ALG", "FTP", ""))
					svcC = NewService(*NewNetworkPolicyRulePort("UDP", "", "12,23"))
					server.TrackerFactory().Service().Create(svcA)
					server.TrackerFactory().Service().Create(svcB)
					server.TrackerFactory().Service().Create(svcC)

					By("create SecurityPolicy with service")
					policy = NewSecurityPolicy(everouteCluster, false, nil, labelA, labelB)
					ipBlock1 = NewRandomIPBlock()
					ipBlock2 = NewRandomIPBlock()
					ingress = NewNetworkPolicyRule("ICMP", "", ipBlock1)
					NetworkPolicyRuleAddServices(ingress, svcA.ID)
					egress = NewNetworkPolicyRule("", "", ipBlock2)
					NetworkPolicyRuleAddServices(egress, svcB.ID, svcC.ID)
					policy.Ingress = append(policy.Ingress, *ingress)
					policy.Egress = append(policy.Egress, *egress)
					server.TrackerFactory().SecurityPolicy().Create(policy)

					assertPoliciesNum(ctx, 1)
				})

				It("should generate expect policies", func() {
					expectIngress := NewSecurityPolicyRuleIngress("ICMP", "", ipBlock1)
					expectEgress := NewSecurityPolicyRuleEgress("TCP", "33-34", ipBlock2)
					RuleAddPorts(expectEgress, "TCP", "21", "UDP", "12,23")
					assertHasPolicy(ctx, constants.Tier2, true, "", v1alpha1.DefaultRuleDrop, allPolicyTypes(),
						expectIngress, expectEgress, NewSecurityPolicyApplyPeer("", labelA, labelB))
					assertAllowlist(ctx)
				})

				It("update service", func() {
					svcA.Members = append(svcA.Members, *NewNetworkPolicyRulePort("TCP", "", "90"), *NewNetworkPolicyRulePort("UDP", "", "3434"))
					svcB.Members = nil
					svcB.Members = append(svcB.Members, *NewNetworkPolicyRulePort("ICMP", "", ""))
					server.TrackerFactory().Service().CreateOrUpdate(svcA)
					server.TrackerFactory().Service().CreateOrUpdate(svcB)

					expectIngress := NewSecurityPolicyRuleIngress("ICMP", "", ipBlock1)
					RuleAddPorts(expectIngress, "TCP", "90", "UDP", "3434")
					expectEgress := NewSecurityPolicyRuleEgress("ICMP", "", ipBlock2)
					RuleAddPorts(expectEgress, "UDP", "12,23")
					assertHasPolicy(ctx, constants.Tier2, true, "", v1alpha1.DefaultRuleDrop, allPolicyTypes(),
						expectIngress, expectEgress, NewSecurityPolicyApplyPeer("", labelA, labelB))
				})

				It("update SecurityPolicy referenced service", func() {
					NetworkPolicyRuleAddServices(&policy.Ingress[0], svcB.ID)
					NetworkPolicyRuleDelServices(&policy.Egress[0], svcB.ID)
					server.TrackerFactory().SecurityPolicy().CreateOrUpdate(policy)

					expectIngress := NewSecurityPolicyRuleIngress("ICMP", "", ipBlock1)
					RuleAddPorts(expectIngress, "TCP", "33-34", "TCP", "21")
					expectEgress := NewSecurityPolicyRuleEgress("UDP", "12,23", ipBlock2)
					assertHasPolicy(ctx, constants.Tier2, true, "", v1alpha1.DefaultRuleDrop, allPolicyTypes(),
						expectIngress, expectEgress, NewSecurityPolicyApplyPeer("", labelA, labelB))
				})

				It("delete SecurityPolicy", func() {
					server.TrackerFactory().SecurityPolicy().Delete(policy.ID)
					assertPoliciesNum(ctx, 0)
				})
			})
		})

		When("create SecurityPolicy with enforce mode", func() {
			var policy *schema.SecurityPolicy

			BeforeEach(func() {
				policy = NewSecurityPolicy(everouteCluster, false, nil, labelA, labelB)
				policy.PolicyMode = schema.PolicyModeMonitor
				By(fmt.Sprintf("create SecurityPolicy %+v", policy))
				server.TrackerFactory().SecurityPolicy().CreateOrUpdate(policy)
			})

			It("should create policy with enforce mode", func() {
				assertPoliciesNum(ctx, 1)
				assertHasPolicy(ctx, constants.Tier2, true, v1alpha1.MonitorMode, v1alpha1.DefaultRuleDrop, allPolicyTypes(),
					nil,
					nil,
					NewSecurityPolicyApplyPeer("", labelA, labelB),
				)
				assertAllowlist(ctx)
			})
		})

		When("create SecurityPolicy out of the EverouteCluster", func() {
			var policy *schema.SecurityPolicy
			var randomEverouteCluster string

			BeforeEach(func() {
				randomEverouteCluster = rand.String(10)
				policy = NewSecurityPolicy(randomEverouteCluster, false, nil, labelA, labelB)

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
				policy = NewSecurityPolicy(everouteCluster, false, nil, labelA, labelB)
				ingress = NewNetworkPolicyRule("tcp", "20-80", nil, labelB, labelC)
				policy.Ingress = append(policy.Ingress, *ingress)

				By(fmt.Sprintf("create SecurityPolicy %+v", policy))
				server.TrackerFactory().SecurityPolicy().CreateOrUpdate(policy)

				By("wait for v1alpha1.SecurityPolicy created")
				assertPoliciesNum(ctx, 1)
			})
			It("should create policy with ingress only", func() {
				assertPoliciesNum(ctx, 1)
				assertHasPolicy(ctx, constants.Tier2, true, "", v1alpha1.DefaultRuleDrop, allPolicyTypes(),
					NewSecurityPolicyRuleIngress("tcp", "20-80", nil, labelB, labelC),
					nil,
					NewSecurityPolicyApplyPeer("", labelA, labelB),
				)
				assertAllowlist(ctx)
			})
		})

		When("create SecurityPolicy with egress only", func() {
			var policy *schema.SecurityPolicy
			var egress *schema.NetworkPolicyRule

			BeforeEach(func() {
				policy = NewSecurityPolicy(everouteCluster, false, nil, labelA, labelB)
				egress = NewNetworkPolicyRule("udp", "123", nil, labelA, labelC)
				policy.Egress = append(policy.Egress, *egress)

				By(fmt.Sprintf("create SecurityPolicy %+v", policy))
				server.TrackerFactory().SecurityPolicy().CreateOrUpdate(policy)

				By("wait for v1alpha1.SecurityPolicy created")
				assertPoliciesNum(ctx, 1)
			})
			It("should create policy with egress only", func() {
				assertPoliciesNum(ctx, 1)
				assertHasPolicy(ctx, constants.Tier2, true, "", v1alpha1.DefaultRuleDrop, allPolicyTypes(),
					nil,
					NewSecurityPolicyRuleEgress("udp", "123", nil, labelA, labelC),
					NewSecurityPolicyApplyPeer("", labelA, labelB),
				)
				assertAllowlist(ctx)
			})
		})

		When("create SecurityPolicy with no rules", func() {
			var policy *schema.SecurityPolicy

			BeforeEach(func() {
				policy = NewSecurityPolicy(everouteCluster, false, nil, labelA, labelB)
				By(fmt.Sprintf("create SecurityPolicy %+v", policy))
				server.TrackerFactory().SecurityPolicy().CreateOrUpdate(policy)
			})

			It("should create policy with no rules", func() {
				assertPoliciesNum(ctx, 1)
				assertHasPolicy(ctx, constants.Tier2, true, "", v1alpha1.DefaultRuleDrop, allPolicyTypes(),
					nil,
					nil,
					NewSecurityPolicyApplyPeer("", labelA, labelB),
				)
				assertAllowlist(ctx)
			})
		})

		When("create blocklist SecurityPolicy", func() {
			var policy *schema.SecurityPolicy

			BeforeEach(func() {
				policy = NewSecurityPolicy(everouteCluster, false, nil, labelA, labelB)
				policy.IsBlocklist = true
				By(fmt.Sprintf("create SecurityPolicy %+v", policy))
				server.TrackerFactory().SecurityPolicy().CreateOrUpdate(policy)
			})

			It("should create policy for blocklist", func() {
				assertPoliciesNum(ctx, 1)
				assertBlocklist(ctx)
				assertHasPolicy(ctx, constants.Tier2, false, "", v1alpha1.DefaultRuleNone, allPolicyTypes(),
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
				assertHasPolicy(ctx, constants.Tier0, true, "", v1alpha1.DefaultRuleDrop, allPolicyTypes(),
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
					assertHasPolicy(ctx, constants.Tier0, true, "", v1alpha1.DefaultRuleDrop, allPolicyTypes(),
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
					assertHasPolicy(ctx, constants.Tier0, true, "", v1alpha1.DefaultRuleDrop, allPolicyTypes(),
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
				ingress = NewNetworkPolicyRule("tcp", "22-80", nil, labelA, labelC)
				policy.Ingress = append(policy.Ingress, *ingress)

				By(fmt.Sprintf("create IsolationPolicy %+v", policy))
				server.TrackerFactory().IsolationPolicy().CreateOrUpdate(policy)
			})

			It("should generate expect policies", func() {
				assertPoliciesNum(ctx, 2)
				assertHasPolicy(ctx, constants.Tier0, true, "", v1alpha1.DefaultRuleDrop,
					[]networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
					nil, nil,
					NewSecurityPolicyApplyPeer(vnicA.GetID()),
					NewSecurityPolicyApplyPeer(vnicB.GetID()),
				)
				assertHasPolicy(ctx, constants.Tier1, true, "", v1alpha1.DefaultRuleDrop,
					[]networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
					NewSecurityPolicyRuleIngress("tcp", "22-80", nil, labelA, labelC),
					nil,
					NewSecurityPolicyApplyPeer(vnicA.GetID()),
					NewSecurityPolicyApplyPeer(vnicB.GetID()),
				)
			})

			It("update ingress with service", func() {
				svcA := NewService(*NewNetworkPolicyRulePort("TCP", "", "34"))
				NetworkPolicyRuleAddServices(&policy.Ingress[0], svcA.ID)
				server.TrackerFactory().Service().Create(svcA)
				server.TrackerFactory().IsolationPolicy().CreateOrUpdate(policy)

				assertPoliciesNum(ctx, 2)
				expectIngress := NewSecurityPolicyRuleIngress("tcp", "22-80", nil, labelA, labelC)
				RuleAddPorts(expectIngress, "TCP", "34")
				assertHasPolicy(ctx, constants.Tier1, true, "", v1alpha1.DefaultRuleDrop,
					[]networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
					expectIngress,
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
				egress = NewNetworkPolicyRule("udp", "123", nil, labelA, labelB)
				egress.OnlyApplyToExternalTraffic = true
				policy.Egress = append(policy.Egress, *egress)

				By(fmt.Sprintf("create IsolationPolicy %+v", policy))
				server.TrackerFactory().IsolationPolicy().CreateOrUpdate(policy)
			})

			It("should generate expect policies", func() {
				assertPoliciesNum(ctx, 2)
				assertHasPolicy(ctx, constants.Tier0, true, "", v1alpha1.DefaultRuleDrop,
					[]networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
					nil, nil,
					NewSecurityPolicyApplyPeer(vnicA.GetID()),
					NewSecurityPolicyApplyPeer(vnicB.GetID()),
				)
				expectEgress := NewSecurityPolicyRuleEgress("udp", "123", nil, labelA, labelB)
				expectEgress.To[0].DisableSymmetric = true
				assertHasPolicy(ctx, constants.Tier1, true, "", v1alpha1.DefaultRuleDrop,
					[]networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
					nil,
					expectEgress,
					NewSecurityPolicyApplyPeer(vnicA.GetID()),
					NewSecurityPolicyApplyPeer(vnicB.GetID()),
				)
			})
		})

		When("create IsolationPolicy with allow alg protocol", func() {
			var policy *schema.IsolationPolicy
			var egress_ftp *schema.NetworkPolicyRule

			BeforeEach(func() {
				policy = NewIsolationPolicy(everouteCluster, vm, schema.IsolationModePartial)
				egress_ftp = NewNetworkPolicyRule("", "", nil, labelA, labelB)
				NetworkPolicyRuleAddPorts(egress_ftp, *NewNetworkPolicyRulePort("ALG", "FTP", "56"))
				policy.Egress = append(policy.Egress, *egress_ftp)

				By(fmt.Sprintf("create IsolationPolicy %+v", policy))
				server.TrackerFactory().IsolationPolicy().CreateOrUpdate(policy)
			})

			It("should generate expect policies", func() {
				assertPoliciesNum(ctx, 2)
				assertHasPolicy(ctx, constants.Tier0, true, "", v1alpha1.DefaultRuleDrop,
					[]networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
					nil, nil,
					NewSecurityPolicyApplyPeer(vnicA.GetID()),
					NewSecurityPolicyApplyPeer(vnicB.GetID()),
				)
				assertHasPolicy(ctx, constants.Tier1, true, "", v1alpha1.DefaultRuleDrop,
					[]networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
					nil,
					NewSecurityPolicyRuleEgress("TCP", "21", nil, labelA, labelB),
					NewSecurityPolicyApplyPeer(vnicA.GetID()),
					NewSecurityPolicyApplyPeer(vnicB.GetID()),
				)
			})
		})
	})

	Context("Global Internal Whitelist Policy", func() {
		When("create systemEndpoints", func() {
			var randomSystemEndpoints *schema.SystemEndpoints

			BeforeEach(func() {
				randomSystemEndpoints = NewSystemEndpoints(2)
				By(fmt.Sprintf("create random systemEndpoints %+v", randomSystemEndpoints))
				server.TrackerFactory().SystemEndpoints().CreateOrUpdate(randomSystemEndpoints)
			})
			It("should create security policy", func() {
				assertPoliciesNum(ctx, 1)
				assertHasPolicy(ctx, constants.Tier2, false, "", v1alpha1.DefaultRuleNone,
					[]networkingv1.PolicyType{networkingv1.PolicyTypeIngress, networkingv1.PolicyTypeEgress},
					getEmptyIngress(), getEmptyEgress(),
					NewSecurityPolicyApplyPeer(endpoint.GetSystemEndpointName(randomSystemEndpoints.IPPortEndpoints[0].Key)),
					NewSecurityPolicyApplyPeer(endpoint.GetSystemEndpointName(randomSystemEndpoints.IPPortEndpoints[1].Key)),
				)
			})

			When("update systemEndpoints", func() {
				BeforeEach(func() {
					randomSystemEndpoints.IPPortEndpoints = append(randomSystemEndpoints.IPPortEndpoints,
						schema.IPPortSystemEndpoint{
							IP:  NewRandomIP().String(),
							Key: rand.String(24),
						})
					By(fmt.Sprintf("update systemEndpoints to %+v", randomSystemEndpoints))
					server.TrackerFactory().SystemEndpoints().CreateOrUpdate(randomSystemEndpoints)
				})
				It("should update security policy", func() {
					assertPoliciesNum(ctx, 1)
					assertHasPolicy(ctx, constants.Tier2, false, "", v1alpha1.DefaultRuleNone,
						[]networkingv1.PolicyType{networkingv1.PolicyTypeIngress, networkingv1.PolicyTypeEgress},
						getEmptyIngress(), getEmptyEgress(),
						NewSecurityPolicyApplyPeer(endpoint.GetSystemEndpointName(randomSystemEndpoints.IPPortEndpoints[0].Key)),
						NewSecurityPolicyApplyPeer(endpoint.GetSystemEndpointName(randomSystemEndpoints.IPPortEndpoints[1].Key)),
						NewSecurityPolicyApplyPeer(endpoint.GetSystemEndpointName(randomSystemEndpoints.IPPortEndpoints[2].Key)),
					)
				})
			})

			When("remove all endpoint for the systemEndpoints", func() {
				BeforeEach(func() {
					randomSystemEndpoints.IPPortEndpoints = nil
					By(fmt.Sprintf("remove all security policy from systemEndpoints: %+v", randomSystemEndpoints))
					server.TrackerFactory().SystemEndpoints().CreateOrUpdate(randomSystemEndpoints)
				})
				It("should delete security policy", func() {
					assertPoliciesNum(ctx, 0)
				})
			})
		})
		When("create EverouteCluster", func() {
			var cluster *schema.EverouteCluster

			BeforeEach(func() {
				cluster = NewEverouteCluster(everouteCluster, schema.GlobalPolicyActionAllow)
				By(fmt.Sprintf("create random everouteCluster %+v", everouteCluster))
				server.TrackerFactory().EverouteCluster().CreateOrUpdate(cluster)
			})
			It("should create security policy", func() {
				assertPoliciesNum(ctx, 1)
				assertHasPolicy(ctx, constants.Tier2, false, "", v1alpha1.DefaultRuleNone,
					[]networkingv1.PolicyType{networkingv1.PolicyTypeIngress, networkingv1.PolicyTypeEgress},
					getEmptyIngress(), getEmptyEgress(),
					NewSecurityPolicyApplyPeer(endpoint.GetCtrlEndpointName(cluster.GetID(), cluster.ControllerInstances[0])),
					NewSecurityPolicyApplyPeer(endpoint.GetCtrlEndpointName(cluster.GetID(), cluster.ControllerInstances[1])),
					NewSecurityPolicyApplyPeer(endpoint.GetCtrlEndpointName(cluster.GetID(), cluster.ControllerInstances[2])),
				)
			})

			When("update everouteCluster", func() {
				BeforeEach(func() {
					cluster.ControllerInstances = append(cluster.ControllerInstances, schema.EverouteControllerInstance{
						IPAddr: NewRandomIP().String(),
					})
					By(fmt.Sprintf("update everouteCluster to %+v", cluster))
					server.TrackerFactory().EverouteCluster().CreateOrUpdate(cluster)
				})
				It("should update security policy", func() {
					assertPoliciesNum(ctx, 1)
					assertHasPolicy(ctx, constants.Tier2, false, "", v1alpha1.DefaultRuleNone,
						[]networkingv1.PolicyType{networkingv1.PolicyTypeIngress, networkingv1.PolicyTypeEgress},
						getEmptyIngress(), getEmptyEgress(),
						NewSecurityPolicyApplyPeer(endpoint.GetCtrlEndpointName(cluster.GetID(), cluster.ControllerInstances[0])),
						NewSecurityPolicyApplyPeer(endpoint.GetCtrlEndpointName(cluster.GetID(), cluster.ControllerInstances[1])),
						NewSecurityPolicyApplyPeer(endpoint.GetCtrlEndpointName(cluster.GetID(), cluster.ControllerInstances[2])),
						NewSecurityPolicyApplyPeer(endpoint.GetCtrlEndpointName(cluster.GetID(), cluster.ControllerInstances[3])),
					)
				})
			})

			When("remove all security policies from everouteCluster", func() {
				BeforeEach(func() {
					cluster.ControllerInstances = nil
					By(fmt.Sprintf("remove all security policy from everouteCluster: %+v", cluster))
					server.TrackerFactory().EverouteCluster().CreateOrUpdate(cluster)
				})
				It("should delete security policy", func() {
					assertPoliciesNum(ctx, 0)
				})
			})
		})
	})

	Context("User-defined Global Whitelist Policy", func() {
		When("create EverouteCluster", func() {
			var cluster *schema.EverouteCluster

			BeforeEach(func() {
				cluster = NewEverouteCluster(everouteCluster, schema.GlobalPolicyActionAllow)
				cluster.ControllerInstances = nil
				cluster.GlobalWhitelist = *NewGlobalWhitelist()
				By(fmt.Sprintf("create random everouteCluster %+v", everouteCluster))
				server.TrackerFactory().EverouteCluster().CreateOrUpdate(cluster)

				anotherCluster := NewEverouteCluster("anotherCluster", schema.GlobalPolicyActionAllow)
				anotherCluster.ControllerInstances = nil
				anotherCluster.GlobalWhitelist = *NewGlobalWhitelist()
				By(fmt.Sprintf("create another random everouteCluster %+v", anotherCluster))
				server.TrackerFactory().EverouteCluster().CreateOrUpdate(anotherCluster)
			})
			It("should create security policy", func() {
				assertPoliciesNum(ctx, 1)
				assertHasPolicy(ctx, constants.Tier2, false, v1alpha1.WorkMode, v1alpha1.DefaultRuleNone,
					[]networkingv1.PolicyType{networkingv1.PolicyTypeIngress, networkingv1.PolicyTypeEgress},
					&v1alpha1.Rule{
						Name: "ingress0",
						From: []v1alpha1.SecurityPolicyPeer{
							{IPBlock: &networkingv1.IPBlock{CIDR: *cluster.GlobalWhitelist.Ingress[0].IPBlock + "/32"}},
						},
					},
					&v1alpha1.Rule{
						Name: "egress0",
						To: []v1alpha1.SecurityPolicyPeer{
							{IPBlock: &networkingv1.IPBlock{CIDR: *cluster.GlobalWhitelist.Egress[0].IPBlock + "/32"}},
						},
					},
				)
			})

			When("update everouteCluster to disable global whitelist", func() {
				BeforeEach(func() {
					cluster.GlobalWhitelist.Enable = false
					By(fmt.Sprintf("update everouteCluster to %+v", cluster))
					server.TrackerFactory().EverouteCluster().CreateOrUpdate(cluster)
				})
				It("should update security policy", func() {
					assertPoliciesNum(ctx, 1)
					assertHasPolicy(ctx, constants.Tier2, false, v1alpha1.MonitorMode, v1alpha1.DefaultRuleNone,
						[]networkingv1.PolicyType{networkingv1.PolicyTypeIngress, networkingv1.PolicyTypeEgress},
						&v1alpha1.Rule{
							Name: "ingress0",
							From: []v1alpha1.SecurityPolicyPeer{
								{IPBlock: &networkingv1.IPBlock{CIDR: *cluster.GlobalWhitelist.Ingress[0].IPBlock + "/32"}},
							},
						},
						&v1alpha1.Rule{
							Name: "egress0",
							To: []v1alpha1.SecurityPolicyPeer{
								{IPBlock: &networkingv1.IPBlock{CIDR: *cluster.GlobalWhitelist.Egress[0].IPBlock + "/32"}},
							},
						},
					)

				})
			})

			When("update everouteCluster to only ingress", func() {
				BeforeEach(func() {
					cluster.GlobalWhitelist.Egress = nil
					By(fmt.Sprintf("update everouteCluster to %+v", cluster))
					server.TrackerFactory().EverouteCluster().CreateOrUpdate(cluster)
				})
				It("should update security policy", func() {
					assertPoliciesNum(ctx, 1)
					assertHasPolicy(ctx, constants.Tier2, false, v1alpha1.WorkMode, v1alpha1.DefaultRuleNone,
						[]networkingv1.PolicyType{networkingv1.PolicyTypeIngress, networkingv1.PolicyTypeEgress},
						&v1alpha1.Rule{
							Name: "ingress0",
							From: []v1alpha1.SecurityPolicyPeer{
								{IPBlock: &networkingv1.IPBlock{CIDR: *cluster.GlobalWhitelist.Ingress[0].IPBlock + "/32"}},
							},
						}, nil,
					)
				})
			})

			When("update everouteCluster to only egress", func() {
				BeforeEach(func() {
					cluster.GlobalWhitelist.Ingress = nil
					By(fmt.Sprintf("update everouteCluster to %+v", cluster))
					server.TrackerFactory().EverouteCluster().CreateOrUpdate(cluster)
				})
				It("should update security policy", func() {
					assertPoliciesNum(ctx, 1)
					assertHasPolicy(ctx, constants.Tier2, false, v1alpha1.WorkMode, v1alpha1.DefaultRuleNone,
						[]networkingv1.PolicyType{networkingv1.PolicyTypeIngress, networkingv1.PolicyTypeEgress},
						nil,
						&v1alpha1.Rule{
							Name: "egress0",
							To: []v1alpha1.SecurityPolicyPeer{
								{IPBlock: &networkingv1.IPBlock{CIDR: *cluster.GlobalWhitelist.Egress[0].IPBlock + "/32"}},
							},
						},
					)
				})
			})

			When("update everouteCluster with alg egress", func() {
				var ipBlock = &networkingv1.IPBlock{CIDR: NewRandomIP().String() + "/32"}
				BeforeEach(func() {
					cluster.GlobalWhitelist.Ingress = nil
					cluster.GlobalWhitelist.Egress = nil
					cluster.GlobalWhitelist.Egress = append(cluster.GlobalWhitelist.Egress, *NewNetworkPolicyRule("TCP", "27", ipBlock))
					By(fmt.Sprintf("update everouteCluster to %+v", cluster))
					server.TrackerFactory().EverouteCluster().CreateOrUpdate(cluster)
				})
				It("should generate security policy with alg rule", func() {
					assertPoliciesNum(ctx, 1)
					assertHasPolicy(ctx, constants.Tier2, false, v1alpha1.WorkMode, v1alpha1.DefaultRuleNone, []networkingv1.PolicyType{networkingv1.PolicyTypeIngress, networkingv1.PolicyTypeEgress},
						nil, NewSecurityPolicyRuleEgress("TCP", "27", ipBlock))
				})
			})

			When("update everouteCluster with service", func() {
				var svc *schema.NetworkPolicyRuleService
				var ipBlock1 *networkingv1.IPBlock
				BeforeEach(func() {
					By("create service")
					svc = NewService(*NewNetworkPolicyRulePort("UDP", "", "12,23"))
					server.TrackerFactory().Service().Create(svc)

					cluster.GlobalWhitelist.Ingress = nil
					cluster.GlobalWhitelist.Egress = nil
					ipBlock1 = NewRandomIPBlock()
					ingress := NewNetworkPolicyRule("ICMP", "", ipBlock1)
					NetworkPolicyRuleAddServices(ingress, svc.ID)
					cluster.GlobalWhitelist.Ingress = append(cluster.GlobalWhitelist.Ingress, *ingress)
					By(fmt.Sprintf("update everouteCluster to %+v", cluster))
					server.TrackerFactory().EverouteCluster().CreateOrUpdate(cluster)
				})

				It("should generate security policy with service ports", func() {
					assertPoliciesNum(ctx, 1)
					expectIngress := NewSecurityPolicyRuleIngress("ICMP", "", ipBlock1)
					RuleAddPorts(expectIngress, "UDP", "12,23")
					assertHasPolicy(ctx, constants.Tier2, false, v1alpha1.WorkMode, v1alpha1.DefaultRuleNone, []networkingv1.PolicyType{networkingv1.PolicyTypeIngress, networkingv1.PolicyTypeEgress},
						expectIngress, nil)
				})

				When("update service", func() {
					BeforeEach(func() {
						svc.Members = append(svc.Members, *NewNetworkPolicyRulePort("TCP", "", "90"), *NewNetworkPolicyRulePort("UDP", "", "3434"))
						server.TrackerFactory().Service().CreateOrUpdate(svc)
					})

					It("should update security policy ports as service", func() {
						expectIngress := NewSecurityPolicyRuleIngress("ICMP", "", ipBlock1)
						RuleAddPorts(expectIngress, "UDP", "12,23", "TCP", "90", "UDP", "3434")
						assertHasPolicy(ctx, constants.Tier2, false, v1alpha1.WorkMode, v1alpha1.DefaultRuleNone, []networkingv1.PolicyType{networkingv1.PolicyTypeIngress, networkingv1.PolicyTypeEgress},
							expectIngress, nil)
					})
				})
			})

			// TODO: assertHasPolicy has problems with multi-rules
			/*
				When("add more items in cluster", func() {
					BeforeEach(func() {
						cluster.GlobalWhitelist.Ingress = append(cluster.GlobalWhitelist.Ingress,
							*NewNetworkPolicyRule("", "", NewRandomIP().String()))
						cluster.GlobalWhitelist.Egress = append(cluster.GlobalWhitelist.Egress,
							*NewNetworkPolicyRule("", "", NewRandomIP().String()))
						By(fmt.Sprintf("update everouteCluster to %+v", cluster))
						server.TrackerFactory().EverouteCluster().CreateOrUpdate(cluster)
					})
					It("should update security policy", func() {
						assertPoliciesNum(ctx, 1)
						assertHasPolicy(ctx, constants.Tier2, false, "",  v1alpha1.DefaultRuleNone,
							[]networkingv1.PolicyType{networkingv1.PolicyTypeIngress, networkingv1.PolicyTypeEgress},
							&v1alpha1.Rule{
								Name: "ingress0",
								From: []v1alpha1.SecurityPolicyPeer{
									{IPBlock: &networkingv1.IPBlock{CIDR: *cluster.GlobalWhitelist.Ingress[0].IPBlock + "/32"}},
									{IPBlock: &networkingv1.IPBlock{CIDR: *cluster.GlobalWhitelist.Ingress[1].IPBlock + "/32"}},
								},
							},
							&v1alpha1.Rule{
								Name: "egress0",
								To: []v1alpha1.SecurityPolicyPeer{
									{IPBlock: &networkingv1.IPBlock{CIDR: *cluster.GlobalWhitelist.Egress[0].IPBlock + "/32"}},
									{IPBlock: &networkingv1.IPBlock{CIDR: *cluster.GlobalWhitelist.Egress[1].IPBlock + "/32"}},
								},
							},
						)
					})
				})
			*/
			When("without ingress and egress in global whitelist", func() {
				BeforeEach(func() {
					cluster.GlobalWhitelist.Ingress = nil
					cluster.GlobalWhitelist.Egress = nil
					By(fmt.Sprintf("remove all security policy from everouteCluster: %+v", cluster))
					server.TrackerFactory().EverouteCluster().CreateOrUpdate(cluster)
				})
				It("should delete security policy", func() {
					assertPoliciesNum(ctx, 0)
				})
			})
		})
	})

	Context("SecurityGroup", func() {
		var normalGroup, emptyGroup, emptyLabelsGroup *schema.SecurityGroup
		var vm *schema.VM
		var vnicA, vnicB *schema.VMNic

		BeforeEach(func() {
			vm = NewRandomVM()
			vnicA = NewRandomVMNicAttachedTo(vm)
			vnicB = NewRandomVMNicAttachedTo(vm)

			normalGroup = NewSecurityGroup(everouteCluster)
			normalGroup.LabelGroups = append(normalGroup.LabelGroups, schema.LabelGroup{
				Labels: LabelAsReference(labelA, labelB, labelC),
			})
			normalGroup.VMs = append(normalGroup.VMs, schema.ObjectReference{ID: vm.ID})
			emptyGroup = NewSecurityGroup(everouteCluster)
			emptyLabelsGroup = NewSecurityGroup(everouteCluster)
			emptyLabelsGroup.LabelGroups = []schema.LabelGroup{{}}

			By(fmt.Sprintf("create vm %+v with vnic %+v and %+v", vm, vnicA, vnicB))
			server.TrackerFactory().VM().CreateOrUpdate(vm)

			By(fmt.Sprintf("create security group %+v %+v %+v", normalGroup, emptyGroup, emptyLabelsGroup))
			server.TrackerFactory().SecurityGroup().CreateOrUpdate(normalGroup)
			server.TrackerFactory().SecurityGroup().CreateOrUpdate(emptyGroup)
			server.TrackerFactory().SecurityGroup().CreateOrUpdate(emptyLabelsGroup)
		})

		When("create SecurityPolicy with empty security group", func() {
			var policy *schema.SecurityPolicy

			BeforeEach(func() {
				policy = NewSecurityPolicy(everouteCluster, false, emptyGroup)
				By(fmt.Sprintf("create security policy %+v", policy))
				server.TrackerFactory().SecurityPolicy().CreateOrUpdate(policy)
			})

			It("should not create security policy with empty group", func() {
				time.Sleep(3 * time.Second) // wait for reconcile
				assertPoliciesNum(ctx, 0)
			})
		})

		When("create SecurityPolicy with normal security group", func() {
			var policy *schema.SecurityPolicy

			BeforeEach(func() {
				policy = NewSecurityPolicy(everouteCluster, false, normalGroup)
				By(fmt.Sprintf("create security policy %+v", policy))
				server.TrackerFactory().SecurityPolicy().CreateOrUpdate(policy)
			})

			It("should create security policy with normal group", func() {
				assertPoliciesNum(ctx, 1)
				assertHasPolicy(ctx, constants.Tier2, true, "", v1alpha1.DefaultRuleDrop, allPolicyTypes(),
					nil,
					nil,
					NewSecurityPolicyApplyPeer(vnicA.ID),
					NewSecurityPolicyApplyPeer(vnicB.ID),
					NewSecurityPolicyApplyPeer("", labelA, labelB, labelC),
				)
			})

			When("update vms in the security group", func() {
				var vnicC *schema.VMNic

				BeforeEach(func() {
					vnicC = NewRandomVMNicAttachedTo(vm)
					server.TrackerFactory().VM().CreateOrUpdate(vm)
				})

				It("should update security policy with normal group", func() {
					assertPoliciesNum(ctx, 1)
					assertHasPolicy(ctx, constants.Tier2, true, "", v1alpha1.DefaultRuleDrop, allPolicyTypes(),
						nil,
						nil,
						NewSecurityPolicyApplyPeer(vnicA.ID),
						NewSecurityPolicyApplyPeer(vnicB.ID),
						NewSecurityPolicyApplyPeer(vnicC.ID),
						NewSecurityPolicyApplyPeer("", labelA, labelB, labelC),
					)
				})
			})

			When("update labels key which in the security group", func() {
				BeforeEach(func() {
					labelA.Key = rand.String(10)
					server.TrackerFactory().Label().CreateOrUpdate(labelA)
				})

				It("should update security policy with normal group", func() {
					assertPoliciesNum(ctx, 1)
					assertHasPolicy(ctx, constants.Tier2, true, "", v1alpha1.DefaultRuleDrop, allPolicyTypes(),
						nil,
						nil,
						NewSecurityPolicyApplyPeer(vnicA.ID),
						NewSecurityPolicyApplyPeer(vnicB.ID),
						NewSecurityPolicyApplyPeer("", labelA, labelB, labelC),
					)
				})
			})

			When("remove vnic from vm which in the security group", func() {
				BeforeEach(func() {
					vm.VMNics = vm.VMNics[:1]
					server.TrackerFactory().VM().CreateOrUpdate(vm)
				})

				It("should update security policy with normal group", func() {
					assertPoliciesNum(ctx, 1)
					assertHasPolicy(ctx, constants.Tier2, true, "", v1alpha1.DefaultRuleDrop, allPolicyTypes(),
						nil,
						nil,
						NewSecurityPolicyApplyPeer(vnicA.ID),
						NewSecurityPolicyApplyPeer("", labelA, labelB, labelC),
					)
				})
			})

			When("update security group to empty", func() {
				BeforeEach(func() {
					normalGroup.VMs = nil
					normalGroup.LabelGroups = nil
					server.TrackerFactory().SecurityGroup().CreateOrUpdate(normalGroup)
				})

				It("should remove the security policy", func() {
					assertPoliciesNum(ctx, 0)
				})
			})
		})

		When("create SecurityPolicy with empty security group and empty labels", func() {
			var policy *schema.SecurityPolicy

			BeforeEach(func() {
				policy = NewSecurityPolicy(everouteCluster, true, emptyGroup)
				policy.ApplyTo = append(policy.ApplyTo, schema.SecurityPolicyApply{
					Type:          schema.SecurityPolicyTypeSecurityGroup,
					Communicable:  true,
					SecurityGroup: &schema.ObjectReference{ID: emptyLabelsGroup.ID},
				})
				By(fmt.Sprintf("create security policy %+v", policy))
				server.TrackerFactory().SecurityPolicy().CreateOrUpdate(policy)
			})

			It("should generate expect policies", func() {
				assertPoliciesNum(ctx, 2)
				assertHasPolicy(ctx, constants.Tier2, true, "", v1alpha1.DefaultRuleDrop, allPolicyTypes(),
					nil,
					nil,
					v1alpha1.ApplyToPeer{EndpointSelector: &labels.Selector{MatchNothing: true}},
				)

				assertHasPolicy(ctx, constants.Tier2, false, "", v1alpha1.DefaultRuleDrop, allPolicyTypes(),
					&v1alpha1.Rule{From: []v1alpha1.SecurityPolicyPeer{{EndpointSelector: &labels.Selector{MatchNothing: true}}}},
					&v1alpha1.Rule{To: []v1alpha1.SecurityPolicyPeer{{EndpointSelector: &labels.Selector{MatchNothing: true}}}},
					v1alpha1.ApplyToPeer{EndpointSelector: &labels.Selector{MatchNothing: true}},
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

func assertBlocklist(ctx context.Context) {
	Eventually(func() bool {
		policyList, err := crdClient.SecurityV1alpha1().SecurityPolicies(namespace).List(ctx, metav1.ListOptions{})
		Expect(err).Should(Succeed())
		for _, item := range policyList.Items {
			if item.Spec.IsBlocklist && item.Spec.Priority == 50 && item.Spec.DefaultRule == v1alpha1.DefaultRuleNone && !item.Spec.SymmetricMode {
				return true
			}
		}
		return false
	}, timeout, interval).Should(BeTrue())
}

func assertAllowlist(ctx context.Context) {
	Eventually(func() bool {
		policyList, err := crdClient.SecurityV1alpha1().SecurityPolicies(namespace).List(ctx, metav1.ListOptions{})
		Expect(err).Should(Succeed())
		for _, item := range policyList.Items {
			if !item.Spec.IsBlocklist && item.Spec.Priority == 0 && item.Spec.DefaultRule == v1alpha1.DefaultRuleDrop && item.Spec.SymmetricMode {
				return true
			}
		}
		return false
	}, timeout, interval).Should(BeTrue())
}

func assertHasPolicy(ctx context.Context, tier string, symmetricMode bool, enforceMode v1alpha1.PolicyMode, defaultRule v1alpha1.DefaultRuleType,
	policyTypes []networkingv1.PolicyType, ingress, egress *v1alpha1.Rule, applyToPeers ...v1alpha1.ApplyToPeer) {
	Eventually(func() bool {
		policyList, err := crdClient.SecurityV1alpha1().SecurityPolicies(namespace).List(ctx, metav1.ListOptions{})
		Expect(err).Should(Succeed())
		for item := range policyList.Items {
			if matchPolicy(&policyList.Items[item], tier, symmetricMode, enforceMode,
				defaultRule, policyTypes, ingress, egress, applyToPeers...) {
				return true
			}
		}
		return false
	}, timeout, interval).Should(BeTrue())
}

func matchPolicy(policy *v1alpha1.SecurityPolicy, tier string, symmetricMode bool, enforceMode v1alpha1.PolicyMode, defaultRule v1alpha1.DefaultRuleType,
	policyTypes []networkingv1.PolicyType, ingress, egress *v1alpha1.Rule, applyToPeers ...v1alpha1.ApplyToPeer) bool {
	matchAllPolicyTypes := func(policyTypes1 []networkingv1.PolicyType, policyTypes2 []networkingv1.PolicyType) bool {
		if len(policyTypes1) != len(policyTypes2) {
			return false
		}
		policyTypeSet := sets.NewString()
		for _, item := range policyTypes1 {
			policyTypeSet.Insert(string(item))
		}

		for _, policyType := range policyTypes2 {
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
		matchPorts := func(ports, expectPorts []v1alpha1.SecurityPolicyPort) bool {
			if len(ports) != len(expectPorts) {
				return false
			}
			for _, ep := range expectPorts {
				find := false
				for _, p := range ports {
					if ep.Protocol == p.Protocol && ep.PortRange == p.PortRange {
						find = true
						break
					}
				}
				if !find {
					return false
				}
			}
			return true
		}
		return (len(rule[0].Ports) == 0 && len(expectRule.Ports) == 0 || matchPorts(rule[0].Ports, expectRule.Ports)) &&
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
		policy.Spec.SecurityPolicyEnforcementMode == enforceMode &&
		policy.Spec.DefaultRule == defaultRule &&
		matchAllPolicyTypes(policy.Spec.PolicyTypes, policyTypes) &&
		matchRules(policy.Spec.IngressRules, ingress) &&
		matchRules(policy.Spec.EgressRules, egress) &&
		matchApplyPeers(policy.Spec.AppliedTo, applyToPeers)
}

func allPolicyTypes() []networkingv1.PolicyType {
	return []networkingv1.PolicyType{networkingv1.PolicyTypeIngress, networkingv1.PolicyTypeEgress}
}

func getEmptyIngress() *v1alpha1.Rule {
	return &v1alpha1.Rule{Name: "ingress"}
}

func getEmptyEgress() *v1alpha1.Rule {
	return &v1alpha1.Rule{Name: "egress"}
}

type ApplyPeers []v1alpha1.ApplyToPeer

func (s ApplyPeers) Len() int      { return len(s) }
func (s ApplyPeers) Swap(i, j int) { s[i], s[j] = s[j], s[i] }
func (s ApplyPeers) Less(i, j int) bool {
	rawI, _ := json.Marshal(s[i])
	rawJ, _ := json.Marshal(s[j])
	return string(rawI) < string(rawJ)
}
