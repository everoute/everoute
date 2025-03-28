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
	"reflect"
	"testing"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/format"
	"golang.org/x/sys/unix"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8stypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/rand"
	"k8s.io/apimachinery/pkg/util/sets"
	storecache "k8s.io/client-go/tools/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/everoute/everoute/pkg/agent/controller/policy/cache"
	groupv1alpha1 "github.com/everoute/everoute/pkg/apis/group/v1alpha1"
	securityv1alpha1 "github.com/everoute/everoute/pkg/apis/security/v1alpha1"
	"github.com/everoute/everoute/pkg/constants"
	ctrlpolicy "github.com/everoute/everoute/pkg/controller/policy"
	"github.com/everoute/everoute/pkg/labels"
	"github.com/everoute/everoute/pkg/types"
	"github.com/everoute/everoute/pkg/utils"
)

const (
	timeout  = time.Second * 10
	interval = time.Millisecond * 250
)

var _ = Describe("PolicyController", func() {
	var ctx context.Context

	BeforeEach(func() {
		format.MaxLength = 0
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
	})

	Context("policy needed endpoints and groups has been create", func() {
		var group1, group2, group3 *testGroup
		var group4 []*testGroup
		var ep1, ep2, ep3 *securityv1alpha1.Endpoint

		BeforeEach(func() {
			ep1NamedPorts := []securityv1alpha1.NamedPort{newTestNamedPort("TCP", "http", 80)}
			ep3NamedPorts := []securityv1alpha1.NamedPort{
				newTestNamedPort("UDP", "dns", 53),
				newTestNamedPort("UDP", "dns", 54),
				newTestNamedPort("UDP", "nfs", 78),
			}
			ep1 = newTestEndpoint([]types.IPAddress{"192.168.1.1", "fe80::11"}, []string{utils.CurrentAgentName()}, ep1NamedPorts)
			ep2 = newTestEndpoint([]types.IPAddress{"192.168.2.1", "fe80::21"}, []string{utils.CurrentAgentName()}, nil)
			ep3 = newTestEndpoint([]types.IPAddress{"192.168.3.1", "fe80::31"}, []string{utils.CurrentAgentName()}, ep3NamedPorts)
			group1 = newTestGroupMembers(0, endpointToMember(ep1))
			group2 = newTestGroupMembers(0, endpointToMember(ep2))
			group3 = newTestGroupMembers(0, endpointToMember(ep3))
			group4 = []*testGroup{
				{
					ipBlock: &networkingv1.IPBlock{
						CIDR:   "10.0.0.0/8",
						Except: []string{"10.0.0.0/10"},
					}},
				{
					ipBlock: &networkingv1.IPBlock{
						CIDR:   "2401::/16",
						Except: []string{"2401::/18"},
					}},
			}

			By(fmt.Sprintf("create endpoints %s and groups %v",
				[]string{ep1.Name, ep2.Name, ep3.Name},
				[]string{group1.Name, group2.Name, group3.Name}))
			Expect(k8sClient.Create(ctx, group1.GroupMembers)).Should(Succeed())
			Expect(k8sClient.Create(ctx, group2.GroupMembers)).Should(Succeed())
			Expect(k8sClient.Create(ctx, group3.GroupMembers)).Should(Succeed())
		})
		When("create a sample policy with port range", func() {
			var policy *securityv1alpha1.SecurityPolicy
			var priority int32

			It("allowlist policy", func() {
				priority = int32(rand.Intn(100) + 1)
				policy = newTestPolicy([]*testGroup{group1}, []*testGroup{group2}, []*testGroup{group3}, newTestPort("TCP", "1000-1999", "number"), newTestPort("UDP", "80", "number"))
				policy.Spec.Priority = priority

				By("create policy " + policy.Name)
				Expect(k8sClient.Create(ctx, policy)).Should(Succeed())

				By("should flatten policy to rules")
				assertPolicyRulesNum(policy, 20)
				assertCompleteRuleNum(4)

				assertHasPolicyRuleWithPortRange(policy, "Ingress", "Allow", "192.168.2.1/32",
					0, 0, "192.168.1.1/32", 0x03e8, 0xfff8, "TCP", unix.AF_INET)
				assertHasPolicyRuleWithPortRange(policy, "Ingress", "Allow", "192.168.2.1/32",
					0, 0, "192.168.1.1/32", 0x03f0, 0xfff0, "TCP", unix.AF_INET)
				assertHasPolicyRuleWithPortRange(policy, "Ingress", "Allow", "192.168.2.1/32",
					0, 0, "192.168.1.1/32", 0x0400, 0xfe00, "TCP", unix.AF_INET)
				assertHasPolicyRuleWithPortRange(policy, "Ingress", "Allow", "192.168.2.1/32",
					0, 0, "192.168.1.1/32", 0x0600, 0xff00, "TCP", unix.AF_INET)
				assertHasPolicyRuleWithPortRange(policy, "Ingress", "Allow", "192.168.2.1/32",
					0, 0, "192.168.1.1/32", 0x0700, 0xff80, "TCP", unix.AF_INET)
				assertHasPolicyRuleWithPortRange(policy, "Ingress", "Allow", "192.168.2.1/32",
					0, 0, "192.168.1.1/32", 0x0780, 0xffc0, "TCP", unix.AF_INET)
				assertHasPolicyRuleWithPortRange(policy, "Ingress", "Allow", "192.168.2.1/32",
					0, 0, "192.168.1.1/32", 0x07c0, 0xfff0, "TCP", unix.AF_INET)

				assertHasPolicyRuleWithPortRange(policy, "Ingress", "Allow", "fe80::21/128",
					0, 0, "fe80::11/128", 0x03e8, 0xfff8, "TCP", unix.AF_INET6)
				assertHasPolicyRuleWithPortRange(policy, "Ingress", "Allow", "fe80::21/128",
					0, 0, "fe80::11/128", 0x03f0, 0xfff0, "TCP", unix.AF_INET6)
				assertHasPolicyRuleWithPortRange(policy, "Ingress", "Allow", "fe80::21/128",
					0, 0, "fe80::11/128", 0x0400, 0xfe00, "TCP", unix.AF_INET6)
				assertHasPolicyRuleWithPortRange(policy, "Ingress", "Allow", "fe80::21/128",
					0, 0, "fe80::11/128", 0x0600, 0xff00, "TCP", unix.AF_INET6)
				assertHasPolicyRuleWithPortRange(policy, "Ingress", "Allow", "fe80::21/128",
					0, 0, "fe80::11/128", 0x0700, 0xff80, "TCP", unix.AF_INET6)
				assertHasPolicyRuleWithPortRange(policy, "Ingress", "Allow", "fe80::21/128",
					0, 0, "fe80::11/128", 0x0780, 0xffc0, "TCP", unix.AF_INET6)
				assertHasPolicyRuleWithPortRange(policy, "Ingress", "Allow", "fe80::21/128",
					0, 0, "fe80::11/128", 0x07c0, 0xfff0, "TCP", unix.AF_INET6)

				// default ingress/egress rule (drop all to/from source)
				assertHasPolicyRule(policy, "Ingress", "Drop", "", 0, "192.168.1.1/32", 0, "", unix.AF_INET)
				assertHasPolicyRule(policy, "Egress", "Drop", "192.168.1.1/32", 0, "", 0, "", unix.AF_INET)
				assertHasPolicyRule(policy, "Ingress", "Drop", "", 0, "fe80::11/128", 0, "", unix.AF_INET6)
				assertHasPolicyRule(policy, "Egress", "Drop", "fe80::11/128", 0, "", 0, "", unix.AF_INET6)
			})

			It("blocklist policy", func() {
				priority = int32(rand.Intn(100) + 1)
				policy = newTestPolicy([]*testGroup{group1}, []*testGroup{group2}, []*testGroup{group3}, newTestPort("TCP", "1000-1999", "number"), newTestPort("UDP", "80", "number"))
				policy.Spec.Priority = priority
				policy.Spec.IsBlocklist = true
				policy.Spec.DefaultRule = securityv1alpha1.DefaultRuleNone

				By("create policy " + policy.Name)
				Expect(k8sClient.Create(ctx, policy)).Should(Succeed())

				By("should flatten policy to rules")
				Eventually(func(g Gomega) {
					g.Expect(len(ruleCacheLister.ListKeys())).Should(Equal(2))
					var policyRuleList = getRuleByPolicy(policy)
					g.Expect(len(policyRuleList)).Should(Equal(16))

					expRule := newTestPolicyRule("Ingress", "Drop", "192.168.2.1/32", "192.168.1.1/32", 0x03e8, 0xfff8, "TCP", constants.Tier2, 4*priority+3, unix.AF_INET)
					g.Expect(policyRuleList).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
					expRule = newTestPolicyRule("Ingress", "Drop", "192.168.2.1/32", "192.168.1.1/32", 0x03f0, 0xfff0, "TCP", constants.Tier2, 4*priority+3, unix.AF_INET)
					g.Expect(policyRuleList).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
					expRule = newTestPolicyRule("Ingress", "Drop", "192.168.2.1/32", "192.168.1.1/32", 0x0400, 0xfe00, "TCP", constants.Tier2, 4*priority+3, unix.AF_INET)
					g.Expect(policyRuleList).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
					expRule = newTestPolicyRule("Ingress", "Drop", "192.168.2.1/32", "192.168.1.1/32", 0x0600, 0xff00, "TCP", constants.Tier2, 4*priority+3, unix.AF_INET)
					g.Expect(policyRuleList).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
					expRule = newTestPolicyRule("Egress", "Drop", "192.168.1.1/32", "192.168.3.1/32", 0x50, 0xffff, "UDP", constants.Tier2, 4*priority+3, unix.AF_INET)
					g.Expect(policyRuleList).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
					expRule = newTestPolicyRule("Ingress", "Drop", "192.168.2.1/32", "192.168.1.1/32", 0x0700, 0xff80, "TCP", constants.Tier2, 4*priority+3, unix.AF_INET)
					g.Expect(policyRuleList).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
					expRule = newTestPolicyRule("Ingress", "Drop", "192.168.2.1/32", "192.168.1.1/32", 0x0780, 0xffc0, "TCP", constants.Tier2, 4*priority+3, unix.AF_INET)
					g.Expect(policyRuleList).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
					expRule = newTestPolicyRule("Ingress", "Drop", "192.168.2.1/32", "192.168.1.1/32", 0x07c0, 0xfff0, "TCP", constants.Tier2, 4*priority+3, unix.AF_INET)
					g.Expect(policyRuleList).Should(ContainElement(NewPolicyRuleMatcher(expRule)))

					expRule = newTestPolicyRule("Ingress", "Drop", "fe80::21/128", "fe80::11/128", 0x03e8, 0xfff8, "TCP", constants.Tier2, 4*priority+3, unix.AF_INET6)
					g.Expect(policyRuleList).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
					expRule = newTestPolicyRule("Ingress", "Drop", "fe80::21/128", "fe80::11/128", 0x03f0, 0xfff0, "TCP", constants.Tier2, 4*priority+3, unix.AF_INET6)
					g.Expect(policyRuleList).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
					expRule = newTestPolicyRule("Ingress", "Drop", "fe80::21/128", "fe80::11/128", 0x0400, 0xfe00, "TCP", constants.Tier2, 4*priority+3, unix.AF_INET6)
					g.Expect(policyRuleList).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
					expRule = newTestPolicyRule("Ingress", "Drop", "fe80::21/128", "fe80::11/128", 0x0600, 0xff00, "TCP", constants.Tier2, 4*priority+3, unix.AF_INET6)
					g.Expect(policyRuleList).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
					expRule = newTestPolicyRule("Egress", "Drop", "fe80::11/128", "fe80::31/128", 0x50, 0xffff, "UDP", constants.Tier2, 4*priority+3, unix.AF_INET6)
					g.Expect(policyRuleList).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
					expRule = newTestPolicyRule("Ingress", "Drop", "fe80::21/128", "fe80::11/128", 0x0700, 0xff80, "TCP", constants.Tier2, 4*priority+3, unix.AF_INET6)
					g.Expect(policyRuleList).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
					expRule = newTestPolicyRule("Ingress", "Drop", "fe80::21/128", "fe80::11/128", 0x0780, 0xffc0, "TCP", constants.Tier2, 4*priority+3, unix.AF_INET6)
					g.Expect(policyRuleList).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
					expRule = newTestPolicyRule("Ingress", "Drop", "fe80::21/128", "fe80::11/128", 0x07c0, 0xfff0, "TCP", constants.Tier2, 4*priority+3, unix.AF_INET6)
					g.Expect(policyRuleList).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
				}, timeout, interval).Should(Succeed())
			})
		})

		When("create a sample policy with port range 2", func() {
			var policy *securityv1alpha1.SecurityPolicy

			BeforeEach(func() {
				policy = newTestPolicy([]*testGroup{group1}, []*testGroup{group2}, []*testGroup{group3}, newTestPort("TCP", "65532-65535", "number"), newTestPort("UDP", "80", "number"))

				By("create policy " + policy.Name)
				Expect(k8sClient.Create(ctx, policy)).Should(Succeed())
			})

			It("should flatten policy to rules", func() {
				assertPolicyRulesNum(policy, 8)
				assertCompleteRuleNum(4)

				assertHasPolicyRuleWithPortRange(policy, "Ingress", "Allow", "192.168.2.1/32",
					0, 0, "192.168.1.1/32", 0xfffc, 0xfffc, "TCP", unix.AF_INET)
				assertHasPolicyRuleWithPortRange(policy, "Ingress", "Allow", "fe80::21/128",
					0, 0, "fe80::11/128", 0xfffc, 0xfffc, "TCP", unix.AF_INET6)
			})
		})

		When("create a sample policy with named port", func() {
			var policy *securityv1alpha1.SecurityPolicy
			BeforeEach(func() {
				policy = newTestPolicy([]*testGroup{group1}, []*testGroup{group2}, []*testGroup{group3}, newTestPort("TCP", "http", "name"), newTestPort("UDP", "dns,nfs", "name"))
				By("create policy " + policy.Name)
				Expect(k8sClient.Create(ctx, policy)).Should(Succeed())
			})

			It("should flatten policy to rules", func() {
				assertPolicyRulesNum(policy, 12)
				assertCompleteRuleNum(4)

				assertHasPolicyRuleWithPortRange(policy, "Ingress", "Allow", "192.168.2.1/32",
					0, 0, "192.168.1.1/32", 0x50, 0xffff, "TCP", unix.AF_INET)
				assertHasPolicyRuleWithPortRange(policy, "Egress", "Allow", "192.168.1.1/32",
					0, 0, "192.168.3.1/32", 0x35, 0xffff, "UDP", unix.AF_INET)
				assertHasPolicyRuleWithPortRange(policy, "Egress", "Allow", "192.168.1.1/32",
					0, 0, "192.168.3.1/32", 0x36, 0xffff, "UDP", unix.AF_INET)
				assertHasPolicyRuleWithPortRange(policy, "Egress", "Allow", "192.168.1.1/32",
					0, 0, "192.168.3.1/32", 0x4e, 0xffff, "UDP", unix.AF_INET)

				assertHasPolicyRuleWithPortRange(policy, "Ingress", "Allow", "fe80::21/128",
					0, 0, "fe80::11/128", 0x50, 0xffff, "TCP", unix.AF_INET6)
				assertHasPolicyRuleWithPortRange(policy, "Egress", "Allow", "fe80::11/128",
					0, 0, "fe80::31/128", 0x35, 0xffff, "UDP", unix.AF_INET6)
				assertHasPolicyRuleWithPortRange(policy, "Egress", "Allow", "fe80::11/128",
					0, 0, "fe80::31/128", 0x36, 0xffff, "UDP", unix.AF_INET6)
				assertHasPolicyRuleWithPortRange(policy, "Egress", "Allow", "fe80::11/128",
					0, 0, "fe80::31/128", 0x4e, 0xffff, "UDP", unix.AF_INET6)
			})
		})

		When("create a sample policy apply to ip block", func() {
			var policy *securityv1alpha1.SecurityPolicy
			BeforeEach(func() {
				policy = newTestPolicy(group4, []*testGroup{group1}, []*testGroup{group2}, newTestPort("UDP", "80", "number"), newTestPort("UDP", "80", "number"))
				By("create policy " + policy.Name)
				Expect(k8sClient.Create(ctx, policy)).Should(Succeed())
			})

			It("should flatten policy to rules", func() {
				assertCompleteRuleNum(4)
				assertPolicyRulesNum(policy, 16)

				assertHasPolicyRuleWithPortRange(policy, "Ingress", "Allow", "192.168.1.1/32",
					0, 0, "10.128.0.0/9", 0x50, 0xffff, "UDP", unix.AF_INET)
				assertHasPolicyRuleWithPortRange(policy, "Ingress", "Allow", "192.168.1.1/32",
					0, 0, "10.64.0.0/10", 0x50, 0xffff, "UDP", unix.AF_INET)
				assertHasPolicyRuleWithPortRange(policy, "Egress", "Allow", "10.128.0.0/9",
					0, 0, "192.168.2.1/32", 0x50, 0xffff, "UDP", unix.AF_INET)
				assertHasPolicyRuleWithPortRange(policy, "Egress", "Allow", "10.64.0.0/10",
					0, 0, "192.168.2.1/32", 0x50, 0xffff, "UDP", unix.AF_INET)

				assertHasPolicyRuleWithPortRange(policy, "Ingress", "Allow", "fe80::11/128",
					0, 0, "2401:8000::/17", 0x50, 0xffff, "UDP", unix.AF_INET6)
				assertHasPolicyRuleWithPortRange(policy, "Ingress", "Allow", "fe80::11/128",
					0, 0, "2401:4000::/18", 0x50, 0xffff, "UDP", unix.AF_INET6)
				assertHasPolicyRuleWithPortRange(policy, "Egress", "Allow", "2401:8000::/17",
					0, 0, "fe80::21/128", 0x50, 0xffff, "UDP", unix.AF_INET6)
				assertHasPolicyRuleWithPortRange(policy, "Egress", "Allow", "2401:4000::/18",
					0, 0, "fe80::21/128", 0x50, 0xffff, "UDP", unix.AF_INET6)
			})
			When("update apply ip blocks", func() {
				BeforeEach(func() {
					policy.Spec.AppliedTo[0].IPBlock.Except = []string{"10.192.0.0/10"}
					mustUpdatePolicy(ctx, policy)
				})
				It("should flatten policy to rules", func() {
					assertCompleteRuleNum(4)
					assertPolicyRulesNum(policy, 16)

					assertHasPolicyRuleWithPortRange(policy, "Ingress", "Allow", "192.168.1.1/32",
						0, 0, "10.0.0.0/9", 0x50, 0xffff, "UDP", unix.AF_INET)
					assertHasPolicyRuleWithPortRange(policy, "Ingress", "Allow", "192.168.1.1/32",
						0, 0, "10.128.0.0/10", 0x50, 0xffff, "UDP", unix.AF_INET)
					assertHasPolicyRuleWithPortRange(policy, "Egress", "Allow", "10.0.0.0/9",
						0, 0, "192.168.2.1/32", 0x50, 0xffff, "UDP", unix.AF_INET)
					assertHasPolicyRuleWithPortRange(policy, "Egress", "Allow", "10.128.0.0/10",
						0, 0, "192.168.2.1/32", 0x50, 0xffff, "UDP", unix.AF_INET)
				})
			})
		})
		When("create a sample policy with same ipblock in src and dst", func() {
			var policy *securityv1alpha1.SecurityPolicy
			BeforeEach(func() {
				group4[0].ipBlock.Except = []string{}
				group4[1].ipBlock.Except = []string{}
				policy = newTestPolicy(group4, group4, group4, newTestPort("UDP", "80", "number"), newTestPort("UDP", "80", "number"))
				Expect(k8sClient.Create(ctx, policy)).Should(Succeed())
			})
			It("should flatten policy to rules", func() {
				assertCompleteRuleNum(4)
				assertPolicyRulesNum(policy, 8)

				assertHasPolicyRuleWithPortRange(policy, "Ingress", "Allow", "10.0.0.0/8",
					0, 0, "10.0.0.0/8", 0x50, 0xffff, "UDP", unix.AF_INET)
				assertHasPolicyRuleWithPortRange(policy, "Egress", "Allow", "10.0.0.0/8",
					0, 0, "10.0.0.0/8", 0x50, 0xffff, "UDP", unix.AF_INET)

				assertHasPolicyRuleWithPortRange(policy, "Ingress", "Allow", "2401::/16",
					0, 0, "2401::/16", 0x50, 0xffff, "UDP", unix.AF_INET6)
				assertHasPolicyRuleWithPortRange(policy, "Egress", "Allow", "2401::/16",
					0, 0, "2401::/16", 0x50, 0xffff, "UDP", unix.AF_INET6)
			})
			When("update ipblock to /32 ip", func() {
				BeforeEach(func() {
					policy.Spec.AppliedTo[0].IPBlock.CIDR = "10.0.0.1/32"
					policy.Spec.IngressRules[0].From[0].IPBlock.CIDR = "10.0.0.1/32"
					mustUpdatePolicy(ctx, policy)
				})
				It("should not generate rules", func() {
					assertCompleteRuleNum(4)
					assertPolicyRulesNum(policy, 7)

					assertHasPolicyRuleWithPortRange(policy, "Egress", "Allow", "10.0.0.1/32",
						0, 0, "10.0.0.0/8", 0x50, 0xffff, "UDP", unix.AF_INET)
				})
			})
		})

		When("create blocklist policy with named and number port", func() {
			var priority int32
			var policy *securityv1alpha1.SecurityPolicy
			BeforeEach(func() {
				priority = int32(rand.Intn(100) + 1)
				policy = newTestPolicy([]*testGroup{group1}, []*testGroup{group2}, []*testGroup{group3}, newTestPort("TCP", "http", "name"), newTestPort("UDP", "dns,nfs", "name"))
				policy.Spec.EgressRules[0].Ports = append(policy.Spec.EgressRules[0].Ports, *newTestPort("TCP", "3322", "number"))
				policy.Spec.IsBlocklist = true
				policy.Spec.Priority = priority
				policy.Spec.SymmetricMode = false
				policy.Spec.DefaultRule = securityv1alpha1.DefaultRuleNone
				By("create policy " + policy.Name)
				Expect(k8sClient.Create(ctx, policy)).Should(Succeed())
			})
			It("should flatten policy to rules", func() {
				Eventually(func(g Gomega) {
					g.Expect(len(ruleCacheLister.ListKeys())).Should(Equal(2))
					var policyRuleList = getRuleByPolicy(policy)
					g.Expect(len(policyRuleList)).Should(Equal(10))

					expRule := newTestPolicyRule("Ingress", "Drop", "192.168.2.1/32", "192.168.1.1/32", 0x50, 0xffff, "TCP", constants.Tier2, 4*priority+3, unix.AF_INET)
					g.Expect(policyRuleList).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
					expRule = newTestPolicyRule("Egress", "Drop", "192.168.1.1/32", "192.168.3.1/32", 3322, 0xffff, "TCP", constants.Tier2, 4*priority+3, unix.AF_INET)
					g.Expect(policyRuleList).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
					expRule = newTestPolicyRule("Egress", "Drop", "192.168.1.1/32", "192.168.3.1/32", 53, 0xffff, "UDP", constants.Tier2, 4*priority+3, unix.AF_INET)
					g.Expect(policyRuleList).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
					expRule = newTestPolicyRule("Egress", "Drop", "192.168.1.1/32", "192.168.3.1/32", 54, 0xffff, "UDP", constants.Tier2, 4*priority+3, unix.AF_INET)
					g.Expect(policyRuleList).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
					expRule = newTestPolicyRule("Egress", "Drop", "192.168.1.1/32", "192.168.3.1/32", 78, 0xffff, "UDP", constants.Tier2, 4*priority+3, unix.AF_INET)
					g.Expect(policyRuleList).Should(ContainElement(NewPolicyRuleMatcher(expRule)))

					expRule = newTestPolicyRule("Ingress", "Drop", "fe80::21/128", "fe80::11/128", 0x50, 0xffff, "TCP", constants.Tier2, 4*priority+3, unix.AF_INET6)
					g.Expect(policyRuleList).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
					expRule = newTestPolicyRule("Egress", "Drop", "fe80::11/128", "fe80::31/128", 3322, 0xffff, "TCP", constants.Tier2, 4*priority+3, unix.AF_INET6)
					g.Expect(policyRuleList).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
					expRule = newTestPolicyRule("Egress", "Drop", "fe80::11/128", "fe80::31/128", 53, 0xffff, "UDP", constants.Tier2, 4*priority+3, unix.AF_INET6)
					g.Expect(policyRuleList).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
					expRule = newTestPolicyRule("Egress", "Drop", "fe80::11/128", "fe80::31/128", 54, 0xffff, "UDP", constants.Tier2, 4*priority+3, unix.AF_INET6)
					g.Expect(policyRuleList).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
					expRule = newTestPolicyRule("Egress", "Drop", "fe80::11/128", "fe80::31/128", 78, 0xffff, "UDP", constants.Tier2, 4*priority+3, unix.AF_INET6)
					g.Expect(policyRuleList).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
				}, timeout, interval).Should(Succeed())
			})

			When("update egress to no peer", func() {
				var testPolicy *securityv1alpha1.SecurityPolicy
				BeforeEach(func() {
					gm := groupv1alpha1.GroupMembers{
						ObjectMeta: metav1.ObjectMeta{
							Name: constants.AllEpWithNamedPort,
						},
						GroupMembers: []groupv1alpha1.GroupMember{*endpointToMember(ep3)},
					}
					Expect(k8sClient.Create(ctx, &gm)).Should(Succeed())
					testPolicy = policy.DeepCopy()
					testPolicy.Spec.EgressRules[0].To = nil
					mustUpdatePolicy(ctx, testPolicy)
				})
				It("should flatten policy to rules", func() {
					Eventually(func(g Gomega) {
						g.Expect(len(ruleCacheLister.ListKeys())).Should(Equal(3))
						var policyRuleList = getRuleByPolicy(testPolicy)
						g.Expect(len(policyRuleList)).Should(Equal(10))

						expRule := newTestPolicyRule("Ingress", "Drop", "192.168.2.1/32", "192.168.1.1/32", 0x50, 0xffff, "TCP", constants.Tier2, 4*priority+3, unix.AF_INET)
						g.Expect(policyRuleList).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
						expRule = newTestPolicyRule("Egress", "Drop", "192.168.1.1/32", "", 3322, 0xffff, "TCP", constants.Tier2, 4*priority+3, unix.AF_INET)
						g.Expect(policyRuleList).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
						expRule = newTestPolicyRule("Egress", "Drop", "192.168.1.1/32", "192.168.3.1/32", 53, 0xffff, "UDP", constants.Tier2, 4*priority+3, unix.AF_INET)
						g.Expect(policyRuleList).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
						expRule = newTestPolicyRule("Egress", "Drop", "192.168.1.1/32", "192.168.3.1/32", 54, 0xffff, "UDP", constants.Tier2, 4*priority+3, unix.AF_INET)
						g.Expect(policyRuleList).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
						expRule = newTestPolicyRule("Egress", "Drop", "192.168.1.1/32", "192.168.3.1/32", 78, 0xffff, "UDP", constants.Tier2, 4*priority+3, unix.AF_INET)
						g.Expect(policyRuleList).Should(ContainElement(NewPolicyRuleMatcher(expRule)))

						expRule = newTestPolicyRule("Ingress", "Drop", "fe80::21/128", "fe80::11/128", 0x50, 0xffff, "TCP", constants.Tier2, 4*priority+3, unix.AF_INET6)
						g.Expect(policyRuleList).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
						expRule = newTestPolicyRule("Egress", "Drop", "fe80::11/128", "", 3322, 0xffff, "TCP", constants.Tier2, 4*priority+3, unix.AF_INET6)
						g.Expect(policyRuleList).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
						expRule = newTestPolicyRule("Egress", "Drop", "fe80::11/128", "fe80::31/128", 53, 0xffff, "UDP", constants.Tier2, 4*priority+3, unix.AF_INET6)
						g.Expect(policyRuleList).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
						expRule = newTestPolicyRule("Egress", "Drop", "fe80::11/128", "fe80::31/128", 54, 0xffff, "UDP", constants.Tier2, 4*priority+3, unix.AF_INET6)
						g.Expect(policyRuleList).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
						expRule = newTestPolicyRule("Egress", "Drop", "fe80::11/128", "fe80::31/128", 78, 0xffff, "UDP", constants.Tier2, 4*priority+3, unix.AF_INET6)
						g.Expect(policyRuleList).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
					}, timeout, interval).Should(Succeed())
				})
			})
		})

		When("create a sample policy no port limit", func() {
			var policy *securityv1alpha1.SecurityPolicy

			BeforeEach(func() {
				policy = newTestPolicy([]*testGroup{group1}, []*testGroup{group2}, []*testGroup{group3}, newTestPort("TCP", "0", "number"), newTestPort("UDP", "80", "number"))

				By("create policy " + policy.Name)
				Expect(k8sClient.Create(ctx, policy)).Should(Succeed())
			})

			It("should flatten policy to rules", func() {
				assertPolicyRulesNum(policy, 8)
				assertCompleteRuleNum(4)

				assertHasPolicyRuleWithPortRange(policy, "Ingress", "Allow", "192.168.2.1/32",
					0, 0, "192.168.1.1/32", 0, 0, "TCP", unix.AF_INET)
				assertHasPolicyRuleWithPortRange(policy, "Ingress", "Allow", "fe80::21/128",
					0, 0, "fe80::11/128", 0, 0, "TCP", unix.AF_INET6)
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
					assertCompleteRuleNum(4)
					assertPolicyRulesNum(testPolicy, 8)

					assertHasPolicyRuleWithPortRange(testPolicy, "Ingress", "Allow", "192.168.2.1/32",
						0, 0, "", 0, 0, "TCP", unix.AF_INET)
					assertHasPolicyRuleWithPortRange(testPolicy, "Ingress", "Drop", "",
						0, 0, "", 0, 0, "", unix.AF_INET)

					assertHasPolicyRuleWithPortRange(testPolicy, "Egress", "Allow", "",
						0, 0, "192.168.3.1/32", 80, 0xffff, "UDP", unix.AF_INET)
					assertHasPolicyRuleWithPortRange(testPolicy, "Egress", "Drop", "",
						0, 0, "", 0, 0, "", unix.AF_INET)

					assertHasPolicyRuleWithPortRange(testPolicy, "Ingress", "Allow", "fe80::21/128",
						0, 0, "", 0, 0, "TCP", unix.AF_INET6)
					assertHasPolicyRuleWithPortRange(testPolicy, "Ingress", "Drop", "",
						0, 0, "", 0, 0, "", unix.AF_INET6)

					assertHasPolicyRuleWithPortRange(testPolicy, "Egress", "Allow", "",
						0, 0, "fe80::31/128", 80, 0xffff, "UDP", unix.AF_INET6)
					assertHasPolicyRuleWithPortRange(testPolicy, "Egress", "Drop", "",
						0, 0, "", 0, 0, "", unix.AF_INET6)
				})
			})

			When("update to blocklist", func() {
				var testPolicy *securityv1alpha1.SecurityPolicy
				var priority int32
				BeforeEach(func() {
					priority = int32(rand.Intn(100) + 1)
					testPolicy = policy.DeepCopy()
					testPolicy.Spec.IsBlocklist = true
					testPolicy.Spec.Priority = priority
					testPolicy.Spec.DefaultRule = securityv1alpha1.DefaultRuleNone

					By(fmt.Sprintf("update allowlist policy %s to blocklist", testPolicy.Name))
					mustUpdatePolicy(ctx, testPolicy)
				})

				It("check rules", func() {
					Eventually(func(g Gomega) {
						g.Expect(len(ruleCacheLister.ListKeys())).Should(Equal(2))
						var policyRuleList = getRuleByPolicy(testPolicy)
						g.Expect(len(policyRuleList)).Should(Equal(4))

						expRule := newTestPolicyRule("Ingress", "Drop", "192.168.2.1/32", "192.168.1.1/32", 0, 0, "TCP", constants.Tier2, 4*priority+3, unix.AF_INET)
						g.Expect(policyRuleList).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
						expRule = newTestPolicyRule("Egress", "Drop", "192.168.1.1/32", "192.168.3.1/32", 80, 0xffff, "UDP", constants.Tier2, 4*priority+3, unix.AF_INET)
						g.Expect(policyRuleList).Should(ContainElement(NewPolicyRuleMatcher(expRule)))

						expRule = newTestPolicyRule("Ingress", "Drop", "fe80::21/128", "fe80::11/128", 0, 0, "TCP", constants.Tier2, 4*priority+3, unix.AF_INET6)
						g.Expect(policyRuleList).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
						expRule = newTestPolicyRule("Egress", "Drop", "fe80::11/128", "fe80::31/128", 80, 0xffff, "UDP", constants.Tier2, 4*priority+3, unix.AF_INET6)
						g.Expect(policyRuleList).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
					}, timeout, interval).Should(Succeed())
				})
			})

			When("update to no egress", func() {

			})
		})

		When("create a sample policy with ingress and egress", func() {
			var policy *securityv1alpha1.SecurityPolicy

			BeforeEach(func() {
				policy = newTestPolicy([]*testGroup{group1}, []*testGroup{group2}, []*testGroup{group3}, newTestPort("TCP", "22", "number"), newTestPort("UDP", "80", "number"))

				By("create policy " + policy.Name)
				Expect(k8sClient.Create(ctx, policy)).Should(Succeed())
			})

			It("should flatten policy to rules", func() {
				assertPolicyRulesNum(policy, 8)
				assertCompleteRuleNum(4)

				assertHasPolicyRule(policy, "Ingress", "Allow", "192.168.2.1/32", 0, "192.168.1.1/32", 22, "TCP", unix.AF_INET)
				assertHasPolicyRule(policy, "Egress", "Allow", "192.168.1.1/32", 0, "192.168.3.1/32", 80, "UDP", unix.AF_INET)

				// default ingress/egress rule (drop all to/from source)
				assertHasPolicyRule(policy, "Ingress", "Drop", "", 0, "192.168.1.1/32", 0, "", unix.AF_INET)
				assertHasPolicyRule(policy, "Egress", "Drop", "192.168.1.1/32", 0, "", 0, "", unix.AF_INET)

				assertHasPolicyRule(policy, "Ingress", "Allow", "fe80::21/128", 0, "fe80::11/128", 22, "TCP", unix.AF_INET6)
				assertHasPolicyRule(policy, "Egress", "Allow", "fe80::11/128", 0, "fe80::31/128", 80, "UDP", unix.AF_INET6)

				assertHasPolicyRule(policy, "Ingress", "Drop", "", 0, "fe80::11/128", 0, "", unix.AF_INET6)
				assertHasPolicyRule(policy, "Egress", "Drop", "fe80::11/128", 0, "", 0, "", unix.AF_INET6)
			})

			When("add a group into applied groups", func() {
				var newGroup *testGroup
				var updPolicy *securityv1alpha1.SecurityPolicy

				BeforeEach(func() {
					newEp := newTestEndpoint([]types.IPAddress{"192.168.1.2", "fe80::12"}, []string{utils.CurrentAgentName()}, nil)
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
					assertHasPolicyRule(policy, "Ingress", "Allow", "192.168.2.1/32", 0, "192.168.1.2/32", 22, "TCP", unix.AF_INET)
					assertHasPolicyRule(policy, "Egress", "Allow", "192.168.1.2/32", 0, "192.168.3.1/32", 80, "UDP", unix.AF_INET)

					// add endpoint into default rule
					assertHasPolicyRule(policy, "Ingress", "Drop", "", 0, "192.168.1.2/32", 0, "", unix.AF_INET)
					assertHasPolicyRule(policy, "Egress", "Drop", "192.168.1.2/32", 0, "", 0, "", unix.AF_INET)

					assertHasPolicyRule(policy, "Ingress", "Allow", "fe80::21/128", 0, "fe80::12/128", 22, "TCP", unix.AF_INET6)
					assertHasPolicyRule(policy, "Egress", "Allow", "fe80::12/128", 0, "fe80::31/128", 80, "UDP", unix.AF_INET6)

					assertHasPolicyRule(policy, "Ingress", "Drop", "", 0, "fe80::12/128", 0, "", unix.AF_INET6)
					assertHasPolicyRule(policy, "Egress", "Drop", "fe80::12/128", 0, "", 0, "", unix.AF_INET6)
				})
			})
			When("add a group into ingress groups", func() {
				var newGroup *testGroup
				var updPolicy *securityv1alpha1.SecurityPolicy

				BeforeEach(func() {
					newEp := newTestEndpoint([]types.IPAddress{"192.168.2.2", "fe80::22"}, []string{utils.CurrentAgentName()}, nil)
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
					assertHasPolicyRule(policy, "Ingress", "Allow", "192.168.2.2/32", 0, "192.168.1.1/32", 22, "TCP", unix.AF_INET)
					assertHasPolicyRule(policy, "Ingress", "Allow", "fe80::22/128", 0, "fe80::11/128", 22, "TCP", unix.AF_INET6)
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
					assertNoPolicyRule(policy, "Egress", "Allow", "192.168.1.1/32", 0, "192.168.3.1/32", 80, "UDP", unix.AF_INET)
					assertNoPolicyRule(policy, "Egress", "Allow", "fe80::11/128", 0, "fe80::31/128", 80, "UDP", unix.AF_INET6)
				})
				It("should add an egress policy rule allow all destinations", func() {
					// empty to securityPeer match all destinations
					assertHasPolicyRule(policy, "Egress", "Allow", "192.168.1.1/32", 0, "", 80, "UDP", unix.AF_INET)
					assertHasPolicyRule(policy, "Egress", "Allow", "fe80::11/128", 0, "", 80, "UDP", unix.AF_INET6)
				})
			})

			When("add an new empty from peer ingress rule", func() {
				var newRule *securityv1alpha1.Rule
				var updPolicy *securityv1alpha1.SecurityPolicy

				BeforeEach(func() {
					newRule = &securityv1alpha1.Rule{
						Name:  rand.String(6),
						Ports: []securityv1alpha1.SecurityPolicyPort{*newTestPort("ICMP", "", "number")},
					}
					updPolicy = policy.DeepCopy()
					updPolicy.Spec.IngressRules = append(updPolicy.Spec.IngressRules, *newRule)

					By(fmt.Sprintf("update policy %s an new empty from peer ingress rule %s", policy.Name, newRule.Name))
					mustUpdatePolicy(ctx, updPolicy)
				})
				It("should add an ingress policy rule allow all sources", func() {
					assertCompleteRuleNum(5)

					// empty from securityPeer match all sources
					assertHasPolicyRule(policy, "Ingress", "Allow", "", 0, "192.168.1.1/32", 0, "ICMP", unix.AF_INET)
					assertHasPolicyRule(policy, "Ingress", "Allow", "", 0, "fe80::11/128", 0, "ICMP", unix.AF_INET6)
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

					assertNoPolicyRule(policy, "Egress", "Allow", "192.168.1.1/32", 0, "192.168.3.1/32", 80, "UDP", unix.AF_INET)
					assertNoPolicyRule(policy, "Egress", "Allow", "fe80::11/128", 0, "fe80::31/128", 80, "UDP", unix.AF_INET6)
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

					assertNoPolicyRule(policy, "Ingress", "Allow", "192.168.2.1/32", 0, "192.168.1.1/32", 22, "TCP", unix.AF_INET)
					assertNoPolicyRule(policy, "Egress", "Allow", "192.168.1.1/32", 0, "192.168.3.1/32", 80, "UDP", unix.AF_INET)
					assertNoPolicyRule(policy, "Ingress", "Drop", "", 0, "192.168.1.1/32", 0, "", unix.AF_INET)
					assertNoPolicyRule(policy, "Egress", "Drop", "192.168.1.1/32", 0, "", 0, "", unix.AF_INET)

					assertHasPolicyRule(updPolicy, "Ingress", "Allow", "192.168.2.1/32", 0, "192.168.1.1/32", 22, "TCP", unix.AF_INET)
					assertHasPolicyRule(updPolicy, "Egress", "Allow", "192.168.1.1/32", 0, "192.168.3.1/32", 80, "UDP", unix.AF_INET)
					assertHasPolicyRule(updPolicy, "Ingress", "Drop", "", 0, "192.168.1.1/32", 0, "", unix.AF_INET)
					assertHasPolicyRule(updPolicy, "Egress", "Drop", "192.168.1.1/32", 0, "", 0, "", unix.AF_INET)

					assertNoPolicyRule(policy, "Ingress", "Allow", "fe80::21/128", 0, "fe80::11/128", 22, "TCP", unix.AF_INET6)
					assertNoPolicyRule(policy, "Egress", "Allow", "fe80::11/128", 0, "fe80::31/128", 80, "UDP", unix.AF_INET6)
					assertNoPolicyRule(policy, "Ingress", "Drop", "", 0, "fe80::11/128", 0, "", unix.AF_INET6)
					assertNoPolicyRule(policy, "Egress", "Drop", "fe80::11/128", 0, "", 0, "", unix.AF_INET6)

					assertHasPolicyRule(updPolicy, "Ingress", "Allow", "fe80::21/128", 0, "fe80::11/128", 22, "TCP", unix.AF_INET6)
					assertHasPolicyRule(updPolicy, "Egress", "Allow", "fe80::11/128", 0, "fe80::31/128", 80, "UDP", unix.AF_INET6)
					assertHasPolicyRule(updPolicy, "Ingress", "Drop", "", 0, "fe80::11/128", 0, "", unix.AF_INET6)
					assertHasPolicyRule(updPolicy, "Egress", "Drop", "fe80::11/128", 0, "", 0, "", unix.AF_INET6)
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
					assertNoPolicyRule(policy, "Ingress", "Allow", "192.168.2.1/32", 0, "192.168.1.1/32", 22, "TCP", unix.AF_INET)
					assertHasPolicyRule(policy, "Ingress", "Allow", "192.168.2.1/32", 0, "192.168.1.1/32", 0, "", unix.AF_INET)

					assertNoPolicyRule(policy, "Ingress", "Allow", "fe80::21/128", 0, "fe80::11/128", 22, "TCP", unix.AF_INET6)
					assertHasPolicyRule(policy, "Ingress", "Allow", "fe80::21/128", 0, "fe80::11/128", 0, "", unix.AF_INET6)
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

					assertNoPolicyRule(policy, "Ingress", "Allow", "192.168.2.1/32", 0, "192.168.1.1/32", 22, "TCP", unix.AF_INET)
					assertHasPolicyRule(policy, "Ingress", "Allow", "192.168.2.1/32", 0, "192.168.1.1/32", 22, "UDP", unix.AF_INET)

					assertNoPolicyRule(policy, "Ingress", "Allow", "fe80::21/128", 0, "fe80::11/128", 22, "TCP", unix.AF_INET6)
					assertHasPolicyRule(policy, "Ingress", "Allow", "fe80::21/128", 0, "fe80::11/128", 22, "UDP", unix.AF_INET6)
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
					assertNoPolicyRule(policy, "Egress", "Allow", "192.168.1.1/32", 0, "192.168.3.1/32", 80, "UDP", unix.AF_INET)
					assertHasPolicyRuleWithPortRange(policy, "Egress", "Allow", "192.168.1.1/32",
						0, 0, "192.168.3.1/32", 8080, 0xfffe, "UDP", unix.AF_INET)
					assertHasPolicyRule(policy, "Egress", "Allow", "192.168.1.1/32",
						0, "192.168.3.1/32", 8082, "UDP", unix.AF_INET)

					assertNoPolicyRule(policy, "Egress", "Allow", "fe80::11/128", 0, "fe80::31/128", 80, "UDP", unix.AF_INET6)
					assertHasPolicyRuleWithPortRange(policy, "Egress", "Allow", "fe80::11/128",
						0, 0, "fe80::31/128", 8080, 0xfffe, "UDP", unix.AF_INET6)
					assertHasPolicyRule(policy, "Egress", "Allow", "fe80::11/128",
						0, "fe80::31/128", 8082, "UDP", unix.AF_INET6)
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
					assertPolicyRulesNum(policy, 12)
					assertCompleteRuleNum(4)

					// ingress symmetry egress rule
					assertHasPolicyRule(policy, "Egress", "Allow", "192.168.2.1/32", 0, "192.168.1.1/32", 22, "TCP", unix.AF_INET)
					assertHasPolicyRule(policy, "Egress", "Allow", "fe80::21/128", 0, "fe80::11/128", 22, "TCP", unix.AF_INET6)
					// egress symmetry ingress rule
					assertHasPolicyRule(policy, "Ingress", "Allow", "192.168.1.1/32", 0, "192.168.3.1/32", 80, "UDP", unix.AF_INET)
					assertHasPolicyRule(policy, "Ingress", "Allow", "fe80::11/128", 0, "fe80::31/128", 80, "UDP", unix.AF_INET6)
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
					assertPolicyRulesNum(policy, 4)
					assertCompleteRuleNum(2)

					assertNoPolicyRule(policy, "Egress", "Allow", "192.168.1.1/32", 0, "192.168.3.1/32", 80, "UDP", unix.AF_INET)
					assertNoPolicyRule(policy, "Egress", "Drop", "192.168.1.1/32", 0, "", 0, "", unix.AF_INET)

					assertNoPolicyRule(policy, "Egress", "Allow", "fe80::11/128", 0, "fe80::31/128", 80, "UDP", unix.AF_INET6)
					assertNoPolicyRule(policy, "Egress", "Drop", "fe80::11/128", 0, "", 0, "", unix.AF_INET6)
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
					assertPolicyRulesNum(policy, 4)
					assertCompleteRuleNum(2)

					assertNoPolicyRule(policy, "Ingress", "Allow", "192.168.2.1/32", 0, "192.168.1.1/32", 22, "TCP", unix.AF_INET)
					assertNoPolicyRule(policy, "Ingress", "Drop", "", 0, "192.168.1.1/32", 0, "", unix.AF_INET)

					assertNoPolicyRule(policy, "Ingress", "Allow", "fe80::21/128", 0, "fe80::11/128", 22, "TCP", unix.AF_INET6)
					assertNoPolicyRule(policy, "Ingress", "Drop", "", 0, "fe80::11/128", 0, "", unix.AF_INET6)
				})
			})
		})

		When("create a sample policy with SymmetricMode enable", func() {
			var policy *securityv1alpha1.SecurityPolicy

			BeforeEach(func() {
				policy = newTestPolicy([]*testGroup{group1}, []*testGroup{group2}, []*testGroup{group3}, newTestPort("TCP", "443", "number"), newTestPort("UDP", "123", "number"))
				policy.Spec.SymmetricMode = true

				By(fmt.Sprintf("create policy %s with SymmetricMode enable", policy.Name))
				Expect(k8sClient.Create(ctx, policy)).Should(Succeed())
			})

			It("should flatten policy to rules", func() {
				assertPolicyRulesNum(policy, 12)
				assertCompleteRuleNum(4)

				assertHasPolicyRule(policy, "Ingress", "Allow", "192.168.2.1/32", 0, "192.168.1.1/32", 443, "TCP", unix.AF_INET)
				assertHasPolicyRule(policy, "Egress", "Allow", "192.168.1.1/32", 0, "192.168.3.1/32", 123, "UDP", unix.AF_INET)

				// symmetry rules
				assertHasPolicyRule(policy, "Egress", "Allow", "192.168.2.1/32", 0, "192.168.1.1/32", 443, "TCP", unix.AF_INET)
				assertHasPolicyRule(policy, "Ingress", "Allow", "192.168.1.1/32", 0, "192.168.3.1/32", 123, "UDP", unix.AF_INET)

				assertHasPolicyRule(policy, "Ingress", "Drop", "", 0, "192.168.1.1/32", 0, "", unix.AF_INET)
				assertHasPolicyRule(policy, "Egress", "Drop", "192.168.1.1/32", 0, "", 0, "", unix.AF_INET)

				assertHasPolicyRule(policy, "Ingress", "Allow", "fe80::21/128", 0, "fe80::11/128", 443, "TCP", unix.AF_INET6)
				assertHasPolicyRule(policy, "Egress", "Allow", "fe80::11/128", 0, "fe80::31/128", 123, "UDP", unix.AF_INET6)
				assertHasPolicyRule(policy, "Egress", "Allow", "fe80::21/128", 0, "fe80::11/128", 443, "TCP", unix.AF_INET6)
				assertHasPolicyRule(policy, "Ingress", "Allow", "fe80::11/128", 0, "fe80::31/128", 123, "UDP", unix.AF_INET6)
				assertHasPolicyRule(policy, "Ingress", "Drop", "", 0, "fe80::11/128", 0, "", unix.AF_INET6)
				assertHasPolicyRule(policy, "Egress", "Drop", "fe80::11/128", 0, "", 0, "", unix.AF_INET6)
			})

			When("add policy ingress rule with DisableSymmetric peer", func() {
				var ipCIDR1, ipCIDR2 = "10.12.13.0/24", "13.13.23.0/24"
				BeforeEach(func() {
					ingressRule := securityv1alpha1.Rule{
						Name: "ingress-2",
						Ports: []securityv1alpha1.SecurityPolicyPort{
							*newTestPort("TCP", "2245", "number"),
						},
						From: []securityv1alpha1.SecurityPolicyPeer{
							{
								DisableSymmetric: true,
								IPBlock:          &networkingv1.IPBlock{CIDR: ipCIDR1},
							},
							{
								DisableSymmetric: false,
								IPBlock:          &networkingv1.IPBlock{CIDR: ipCIDR2},
							},
						},
					}
					policy.Spec.IngressRules = append(policy.Spec.IngressRules, ingressRule)
					mustUpdatePolicy(ctx, policy)
				})

				It("should flatten policy to rules", func() {
					assertPolicyRulesNum(policy, 15)
					assertCompleteRuleNum(6)

					assertHasPolicyRule(policy, "Ingress", "Allow", ipCIDR1, 0, "192.168.1.1/32", 2245, "TCP", unix.AF_INET)
					assertHasPolicyRule(policy, "Ingress", "Allow", ipCIDR2, 0, "192.168.1.1/32", 2245, "TCP", unix.AF_INET)

					// no symmetric rule for ipCIDR1
					assertNoPolicyRule(policy, "Egress", "Allow", ipCIDR1, 0, "192.168.1.1/32", 2245, "TCP", unix.AF_INET)

					// symmetric rule for ipCIDR2
					assertHasPolicyRule(policy, "Egress", "Allow", ipCIDR2, 0, "192.168.1.1/32", 2245, "TCP", unix.AF_INET)
				})

				When("update peer DisableSymmetric from true to false", func() {
					BeforeEach(func() {
						policy.Spec.IngressRules[1].From[0].DisableSymmetric = false
						policy.Spec.IngressRules[1].From[1].DisableSymmetric = false
						mustUpdatePolicy(ctx, policy)
					})

					It("should generate symmetric rule", func() {
						assertPolicyRulesNum(policy, 16)
						assertCompleteRuleNum(5)

						assertHasPolicyRule(policy, "Egress", "Allow", ipCIDR1, 0, "192.168.1.1/32", 2245, "TCP", unix.AF_INET)
						assertHasPolicyRule(policy, "Egress", "Allow", ipCIDR2, 0, "192.168.1.1/32", 2245, "TCP", unix.AF_INET)
					})
				})

				When("disable policy SymmetricMode", func() {
					BeforeEach(func() {
						policy.Spec.SymmetricMode = false
						mustUpdatePolicy(ctx, policy)
					})

					It("should remove symmetric policy rules", func() {
						assertPolicyRulesNum(policy, 10)
						assertCompleteRuleNum(5)

						assertNoPolicyRule(policy, "Egress", "Allow", ipCIDR1, 0, "192.168.1.1/32", 2245, "TCP", unix.AF_INET)
						assertNoPolicyRule(policy, "Egress", "Allow", ipCIDR2, 0, "192.168.1.1/32", 2245, "TCP", unix.AF_INET)
					})
				})
			})

			When("update policy egress rule peer DisableSymmetric from false to true", func() {
				BeforeEach(func() {
					policy.Spec.EgressRules[0].To[0].DisableSymmetric = true
					mustUpdatePolicy(ctx, policy)
				})

				It("should remove egress rule symmetric rules", func() {
					assertPolicyRulesNum(policy, 10)
					assertCompleteRuleNum(4)

					// ingress rule has symmetry rule
					assertHasPolicyRule(policy, "Egress", "Allow", "192.168.2.1/32", 0, "192.168.1.1/32", 443, "TCP", unix.AF_INET)
					assertHasPolicyRule(policy, "Egress", "Allow", "fe80::21/128", 0, "fe80::11/128", 443, "TCP", unix.AF_INET6)
					// egress rule has no symmetric rule
					assertNoPolicyRule(policy, "Ingress", "Allow", "192.168.1.1/32", 0, "192.168.3.1/32", 123, "UDP", unix.AF_INET)
					assertNoPolicyRule(policy, "Ingress", "Allow", "fe80::11/128", 0, "fe80::31/128", 123, "UDP", unix.AF_INET6)
				})

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
					assertPolicyRulesNum(policy, 8)
					assertCompleteRuleNum(4)

					assertNoPolicyRule(policy, "Egress", "Allow", "192.168.2.1/32", 0, "192.168.1.1/32", 443, "TCP", unix.AF_INET)
					assertNoPolicyRule(policy, "Ingress", "Allow", "192.168.1.1/32", 0, "192.168.3.1/32", 123, "UDP", unix.AF_INET)

					assertNoPolicyRule(policy, "Egress", "Allow", "fe80::21/128", 0, "fe80::11/128", 443, "TCP", unix.AF_INET6)
					assertNoPolicyRule(policy, "Ingress", "Allow", "fe80::11/128", 0, "fe80::31/128", 123, "UDP", unix.AF_INET6)
				})
			})
		})

		When("create a sample policy with enable ingress only", func() {
			var policy *securityv1alpha1.SecurityPolicy

			BeforeEach(func() {
				policy = newTestPolicy([]*testGroup{group1}, []*testGroup{group2}, []*testGroup{group3}, newTestPort("TCP", "443", "number"), newTestPort("UDP", "123", "number"))
				policy.Spec.PolicyTypes = []networkingv1.PolicyType{networkingv1.PolicyTypeIngress}

				By(fmt.Sprintf("create policy %s with enable ingress only", policy.Name))
				Expect(k8sClient.Create(ctx, policy)).Should(Succeed())
			})

			It("should flatten policy to rules", func() {
				assertPolicyRulesNum(policy, 4)
				assertCompleteRuleNum(2)

				assertHasPolicyRule(policy, "Ingress", "Allow", "192.168.2.1/32", 0, "192.168.1.1/32", 443, "TCP", unix.AF_INET)
				assertHasPolicyRule(policy, "Ingress", "Drop", "", 0, "192.168.1.1/32", 0, "", unix.AF_INET)
				assertHasPolicyRule(policy, "Ingress", "Allow", "fe80::21/128", 0, "fe80::11/128", 443, "TCP", unix.AF_INET6)
				assertHasPolicyRule(policy, "Ingress", "Drop", "", 0, "fe80::11/128", 0, "", unix.AF_INET6)

				// Only ingress specified, egress rule should not generate
				assertNoPolicyRule(policy, "Egress", "Allow", "192.168.1.1/32", 0, "192.168.3.1/32", 123, "UDP", unix.AF_INET)
				assertNoPolicyRule(policy, "Egress", "Drop", "192.168.1.1/32", 0, "", 0, "", unix.AF_INET)
				assertNoPolicyRule(policy, "Egress", "Allow", "fe80::11/128", 0, "fe80::31/128", 123, "UDP", unix.AF_INET6)
				assertNoPolicyRule(policy, "Egress", "Drop", "fe80::11/128", 0, "", 0, "", unix.AF_INET6)
			})
		})

		When("create a sample policy with enable egress only", func() {
			var policy *securityv1alpha1.SecurityPolicy

			BeforeEach(func() {
				policy = newTestPolicy([]*testGroup{group1}, []*testGroup{group2}, []*testGroup{group3}, newTestPort("TCP", "443", "number"), newTestPort("UDP", "123", "number"))
				policy.Spec.PolicyTypes = []networkingv1.PolicyType{networkingv1.PolicyTypeEgress}

				By(fmt.Sprintf("create policy %s with enable ingress only", policy.Name))
				Expect(k8sClient.Create(ctx, policy)).Should(Succeed())
			})

			It("should flatten policy to rules", func() {
				assertPolicyRulesNum(policy, 4)
				assertCompleteRuleNum(2)

				assertHasPolicyRule(policy, "Egress", "Allow", "192.168.1.1/32", 0, "192.168.3.1/32", 123, "UDP", unix.AF_INET)
				assertHasPolicyRule(policy, "Egress", "Drop", "192.168.1.1/32", 0, "", 0, "", unix.AF_INET)

				assertHasPolicyRule(policy, "Egress", "Allow", "fe80::11/128", 0, "fe80::31/128", 123, "UDP", unix.AF_INET6)
				assertHasPolicyRule(policy, "Egress", "Drop", "fe80::11/128", 0, "", 0, "", unix.AF_INET6)

				// Only egress specified, ingress rule should not generate
				assertNoPolicyRule(policy, "Ingress", "Allow", "192.168.2.1/32", 0, "192.168.1.1/32", 443, "TCP", unix.AF_INET)
				assertNoPolicyRule(policy, "Ingress", "Drop", "", 0, "192.168.1.1/32", 0, "", unix.AF_INET)

				assertNoPolicyRule(policy, "Ingress", "Allow", "fe80::21/128", 0, "fe80::11/128", 443, "TCP", unix.AF_INET6)
				assertNoPolicyRule(policy, "Ingress", "Drop", "", 0, "fe80::11/128", 0, "", unix.AF_INET6)

			})
		})
		When("create a simple policy without drop", func() {
			var policy *securityv1alpha1.SecurityPolicy

			BeforeEach(func() {
				policy = newTestPolicy([]*testGroup{group1}, []*testGroup{group2}, []*testGroup{group3}, newTestPort("TCP", "443", "number"), newTestPort("UDP", "123", "number"))
				policy.Spec.PolicyTypes = []networkingv1.PolicyType{networkingv1.PolicyTypeEgress}
				policy.Spec.DefaultRule = securityv1alpha1.DefaultRuleNone
				By(fmt.Sprintf("create policy %s without drop", policy.Name))
				Expect(k8sClient.Create(ctx, policy)).Should(Succeed())
			})

			It("should not have default rules", func() {
				assertPolicyRulesNum(policy, 2)

				assertHasPolicyRule(policy, "Egress", "Allow", "192.168.1.1/32", 0, "192.168.3.1/32", 123, "UDP", unix.AF_INET)
				assertNoPolicyRule(policy, "Egress", "Drop", "192.168.1.1/32", 0, "", 0, "", unix.AF_INET)

				assertHasPolicyRule(policy, "Egress", "Allow", "fe80::11/128", 0, "fe80::31/128", 123, "UDP", unix.AF_INET6)
				assertNoPolicyRule(policy, "Egress", "Drop", "fe80::11/128", 0, "", 0, "", unix.AF_INET6)

				// Only egress specified, ingress rule should not generate
				assertNoPolicyRule(policy, "Ingress", "Allow", "192.168.2.1/32", 0, "192.168.1.1/32", 443, "TCP", unix.AF_INET)
				assertNoPolicyRule(policy, "Ingress", "Drop", "", 0, "192.168.1.1/32", 0, "", unix.AF_INET)

				assertNoPolicyRule(policy, "Ingress", "Allow", "fe80::21/128", 0, "fe80::11/128", 443, "TCP", unix.AF_INET6)
				assertNoPolicyRule(policy, "Ingress", "Drop", "", 0, "fe80::11/128", 0, "", unix.AF_INET6)
			})
		})

		When("create a sample policy with no PolicyTypes specified", func() {
			var policy *securityv1alpha1.SecurityPolicy

			BeforeEach(func() {
				policy = newTestPolicy([]*testGroup{group1}, []*testGroup{group2}, []*testGroup{group3}, newTestPort("TCP", "443", "number"), newTestPort("UDP", "123", "number"))
				policy.Spec.PolicyTypes = []networkingv1.PolicyType{}

				By(fmt.Sprintf("create policy %s with enable ingress only", policy.Name))
				Expect(k8sClient.Create(ctx, policy)).Should(Succeed())
			})

			It("should flatten policy to rules", func() {
				// Ingress and Egress exists on SecurityPolicy, should generate both ingress rule and egress rule
				assertPolicyRulesNum(policy, 8)
				assertCompleteRuleNum(4)

				assertHasPolicyRule(policy, "Egress", "Allow", "192.168.1.1/32", 0, "192.168.3.1/32", 123, "UDP", unix.AF_INET)
				assertHasPolicyRule(policy, "Egress", "Drop", "192.168.1.1/32", 0, "", 0, "", unix.AF_INET)

				assertHasPolicyRule(policy, "Ingress", "Allow", "192.168.2.1/32", 0, "192.168.1.1/32", 443, "TCP", unix.AF_INET)
				assertHasPolicyRule(policy, "Ingress", "Drop", "", 0, "192.168.1.1/32", 0, "", unix.AF_INET)

				assertHasPolicyRule(policy, "Egress", "Allow", "fe80::11/128", 0, "fe80::31/128", 123, "UDP", unix.AF_INET6)
				assertHasPolicyRule(policy, "Egress", "Drop", "fe80::11/128", 0, "", 0, "", unix.AF_INET6)

				assertHasPolicyRule(policy, "Ingress", "Allow", "fe80::21/128", 0, "fe80::11/128", 443, "TCP", unix.AF_INET6)
				assertHasPolicyRule(policy, "Ingress", "Drop", "", 0, "fe80::11/128", 0, "", unix.AF_INET6)
			})
		})

		When("create two same sample policy", func() {
			var policy01, policy02 *securityv1alpha1.SecurityPolicy

			BeforeEach(func() {
				policy01 = newTestPolicy([]*testGroup{group1}, []*testGroup{group2}, []*testGroup{group3}, newTestPort("TCP", "443", "number"), newTestPort("UDP", "123", "number"))
				By(fmt.Sprintf("create policy %s without drop", policy01.Name))
				Expect(k8sClient.Create(ctx, policy01)).Should(Succeed())

				policy02 = newTestPolicy([]*testGroup{group1}, []*testGroup{group2}, []*testGroup{group3}, newTestPort("TCP", "443", "number"), newTestPort("UDP", "123", "number"))
				By(fmt.Sprintf("create policy %s without drop", policy02.Name))
				Expect(k8sClient.Create(ctx, policy02)).Should(Succeed())
			})

			It("should flatten policy to rules", func() {
				assertPolicyRulesNum(policy01, 8)
				assertPolicyRulesNum(policy02, 8)
				assertCompleteRuleNum(8)

				assertHasPolicyRule(policy01, "Egress", "Allow", "192.168.1.1/32", 0, "192.168.3.1/32", 123, "UDP", unix.AF_INET)
				assertHasPolicyRule(policy01, "Egress", "Drop", "192.168.1.1/32", 0, "", 0, "", unix.AF_INET)
				assertHasPolicyRule(policy01, "Ingress", "Allow", "192.168.2.1/32", 0, "192.168.1.1/32", 443, "TCP", unix.AF_INET)
				assertHasPolicyRule(policy01, "Ingress", "Drop", "", 0, "192.168.1.1/32", 0, "", unix.AF_INET)
				assertHasPolicyRule(policy02, "Egress", "Allow", "192.168.1.1/32", 0, "192.168.3.1/32", 123, "UDP", unix.AF_INET)
				assertHasPolicyRule(policy02, "Egress", "Drop", "192.168.1.1/32", 0, "", 0, "", unix.AF_INET)
				assertHasPolicyRule(policy02, "Ingress", "Allow", "192.168.2.1/32", 0, "192.168.1.1/32", 443, "TCP", unix.AF_INET)
				assertHasPolicyRule(policy02, "Ingress", "Drop", "", 0, "192.168.1.1/32", 0, "", unix.AF_INET)

				assertHasPolicyRule(policy01, "Egress", "Allow", "fe80::11/128", 0, "fe80::31/128", 123, "UDP", unix.AF_INET6)
				assertHasPolicyRule(policy01, "Egress", "Drop", "fe80::11/128", 0, "", 0, "", unix.AF_INET6)
				assertHasPolicyRule(policy01, "Ingress", "Allow", "fe80::21/128", 0, "fe80::11/128", 443, "TCP", unix.AF_INET6)
				assertHasPolicyRule(policy01, "Ingress", "Drop", "", 0, "fe80::11/128", 0, "", unix.AF_INET6)
				assertHasPolicyRule(policy02, "Egress", "Allow", "fe80::11/128", 0, "fe80::31/128", 123, "UDP", unix.AF_INET6)
				assertHasPolicyRule(policy02, "Egress", "Drop", "fe80::11/128", 0, "", 0, "", unix.AF_INET6)
				assertHasPolicyRule(policy02, "Ingress", "Allow", "fe80::21/128", 0, "fe80::11/128", 443, "TCP", unix.AF_INET6)
				assertHasPolicyRule(policy02, "Ingress", "Drop", "", 0, "fe80::11/128", 0, "", unix.AF_INET6)
			})

			When("remove one of security policy", func() {
				BeforeEach(func() {
					Expect(k8sClient.Delete(ctx, policy01)).Should(Succeed())
				})

				It("should not hang on policy rule remove", func() {
					assertPolicyRulesNum(policy01, 0)
					assertPolicyRulesNum(policy02, 8)
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

	Context("partial endpoints do not on current agent", func() {
		var group1, group2, group3, group4, group5, group6, groupAll *testGroup
		var ep1, ep2, ep3, ep4, ep5, ep6, epAll *securityv1alpha1.Endpoint

		BeforeEach(func() {
			ep1 = newTestEndpoint([]types.IPAddress{"192.168.1.1", "fe80::11"}, []string{utils.CurrentAgentName()}, nil)
			ep2 = newTestEndpoint([]types.IPAddress{"192.168.2.1", "fe80::21"}, []string{utils.CurrentAgentName()}, nil)
			ep3 = newTestEndpoint([]types.IPAddress{"192.168.3.1", "fe80::31"}, []string{utils.CurrentAgentName()}, nil)
			ep4 = newTestEndpoint([]types.IPAddress{"192.168.4.1", "fe80::41"}, []string{"agent2"}, nil)
			ep5 = newTestEndpoint([]types.IPAddress{"192.168.5.1", "fe80::51"}, []string{"agent2"}, nil)
			ep6 = newTestEndpoint([]types.IPAddress{"192.168.6.1", "fe80::61"}, []string{"agent2"}, nil)
			epAll = newTestEndpoint([]types.IPAddress{"192.168.100.1", "fe80::1001"}, nil, nil)

			group1 = newTestGroupMembers(0, endpointToMember(ep1))
			group2 = newTestGroupMembers(0, endpointToMember(ep2))
			group3 = newTestGroupMembers(0, endpointToMember(ep3))
			group4 = newTestGroupMembers(0, endpointToMember(ep4))
			group5 = newTestGroupMembers(0, endpointToMember(ep5))
			group6 = newTestGroupMembers(0, endpointToMember(ep6))
			groupAll = newTestGroupMembers(0, endpointToMember(epAll))

			By(fmt.Sprintf("create endpoints %s and groups %v",
				[]string{ep1.Name, ep2.Name, ep3.Name, ep4.Name, ep5.Name, ep6.Name, epAll.Name},
				[]string{group1.Name, group2.Name, group3.Name, group4.Name, group5.Name, group6.Name, groupAll.Name}))
			Expect(k8sClient.Create(ctx, group1.GroupMembers)).Should(Succeed())
			Expect(k8sClient.Create(ctx, group2.GroupMembers)).Should(Succeed())
			Expect(k8sClient.Create(ctx, group3.GroupMembers)).Should(Succeed())
			Expect(k8sClient.Create(ctx, group4.GroupMembers)).Should(Succeed())
			Expect(k8sClient.Create(ctx, group5.GroupMembers)).Should(Succeed())
			Expect(k8sClient.Create(ctx, group6.GroupMembers)).Should(Succeed())
			Expect(k8sClient.Create(ctx, groupAll.GroupMembers)).Should(Succeed())
		})

		When("create a sample policy not in current agent", func() {
			var policy *securityv1alpha1.SecurityPolicy

			BeforeEach(func() {
				policy = newTestPolicy([]*testGroup{group4}, []*testGroup{group5}, []*testGroup{group6}, newTestPort("TCP", "80", "number"), newTestPort("UDP", "80", "number"))
				policy.Spec.SymmetricMode = true
				By("create policy " + policy.Name)
				Expect(k8sClient.Create(ctx, policy)).Should(Succeed())
			})

			It("should not appear in current agent", func() {
				assertCompleteRuleNum(4)
				assertPolicyRulesNum(policy, 0)
			})
		})
		When("create a sample policy apply to current agent with egress & ingress not", func() {
			var policy *securityv1alpha1.SecurityPolicy

			BeforeEach(func() {
				policy = newTestPolicy([]*testGroup{group1}, []*testGroup{group4}, []*testGroup{group5}, newTestPort("TCP", "80", "number"), newTestPort("UDP", "80", "number"))

				By("create policy " + policy.Name)
				Expect(k8sClient.Create(ctx, policy)).Should(Succeed())
			})
			It("should create rules", func() {
				assertCompleteRuleNum(4)
				assertPolicyRulesNum(policy, 8)

				assertHasPolicyRule(policy, "Ingress", "Allow", "192.168.4.1/32", 0, "192.168.1.1/32", 80, "TCP", unix.AF_INET)
				assertHasPolicyRule(policy, "Ingress", "Drop", "", 0, "192.168.1.1/32", 0, "", unix.AF_INET)
				assertHasPolicyRule(policy, "Egress", "Allow", "192.168.1.1/32", 0, "192.168.5.1/32", 80, "UDP", unix.AF_INET)
				assertHasPolicyRule(policy, "Egress", "Drop", "192.168.1.1/32", 0, "", 0, "", unix.AF_INET)

				assertHasPolicyRule(policy, "Ingress", "Allow", "fe80::41/128", 0, "fe80::11/128", 80, "TCP", unix.AF_INET6)
				assertHasPolicyRule(policy, "Ingress", "Drop", "", 0, "fe80::11/128", 0, "", unix.AF_INET6)
				assertHasPolicyRule(policy, "Egress", "Allow", "fe80::11/128", 0, "fe80::51/128", 80, "UDP", unix.AF_INET6)
				assertHasPolicyRule(policy, "Egress", "Drop", "fe80::11/128", 0, "", 0, "", unix.AF_INET6)
			})
		})
		When("create a sample policy applyTo & ingress(current agent), egress(another agent)", func() {
			var policy *securityv1alpha1.SecurityPolicy

			BeforeEach(func() {
				policy = newTestPolicy([]*testGroup{group1}, []*testGroup{group2}, []*testGroup{group5}, newTestPort("TCP", "80", "number"), newTestPort("UDP", "80", "number"))

				By("create policy " + policy.Name)
				Expect(k8sClient.Create(ctx, policy)).Should(Succeed())
			})
			It("should create rules", func() {
				assertCompleteRuleNum(4)
				assertPolicyRulesNum(policy, 8)

				assertHasPolicyRule(policy, "Ingress", "Allow", "192.168.2.1/32", 0, "192.168.1.1/32", 80, "TCP", unix.AF_INET)
				assertHasPolicyRule(policy, "Ingress", "Drop", "", 0, "192.168.1.1/32", 0, "", unix.AF_INET)
				assertHasPolicyRule(policy, "Egress", "Allow", "192.168.1.1/32", 0, "192.168.5.1/32", 80, "UDP", unix.AF_INET)
				assertHasPolicyRule(policy, "Egress", "Drop", "192.168.1.1/32", 0, "", 0, "", unix.AF_INET)

				assertHasPolicyRule(policy, "Ingress", "Allow", "fe80::21/128", 0, "fe80::11/128", 80, "TCP", unix.AF_INET6)
				assertHasPolicyRule(policy, "Ingress", "Drop", "", 0, "fe80::11/128", 0, "", unix.AF_INET6)
				assertHasPolicyRule(policy, "Egress", "Allow", "fe80::11/128", 0, "fe80::51/128", 80, "UDP", unix.AF_INET6)
				assertHasPolicyRule(policy, "Egress", "Drop", "fe80::11/128", 0, "", 0, "", unix.AF_INET6)
			})

			When("update policy with ipBlock", func() {
				var testPolicy *securityv1alpha1.SecurityPolicy
				BeforeEach(func() {
					testPolicy = policy.DeepCopy()
					testPolicy.Spec.EgressRules[0].To = append(testPolicy.Spec.EgressRules[0].To, securityv1alpha1.SecurityPolicyPeer{
						IPBlock: &networkingv1.IPBlock{CIDR: "192.168.7.0/25", Except: []string{"192.168.7.32/29", "192.168.7.41/32"}},
					})
					mustUpdatePolicy(ctx, testPolicy)
				})
				It("should update rules", func() {
					pri := testPolicy.Spec.Priority
					Eventually(func(g Gomega) {
						g.Expect(len(ruleCacheLister.ListKeys())).Should(Equal(4))
						rules := getRuleByPolicy(testPolicy)
						g.Expect(len(rules)).Should(Equal(14))
						expRule := newTestPolicyRule("Ingress", "Allow", "192.168.2.1/32", "192.168.1.1/32", 80, 0xffff, "TCP", constants.Tier2, 4*pri+1, unix.AF_INET)
						g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
						expRule = newTestPolicyRule("Ingress", "Drop", "", "192.168.1.1/32", 0, 0, "", constants.Tier2, 4*pri, unix.AF_INET)
						g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
						expRule = newTestPolicyRule("Egress", "Allow", "192.168.1.1/32", "192.168.5.1/32", 80, 0xffff, "UDP", constants.Tier2, 4*pri+1, unix.AF_INET)
						g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
						expRule = newTestPolicyRule("Egress", "Allow", "192.168.1.1/32", "192.168.7.64/26", 80, 0xffff, "UDP", constants.Tier2, 4*pri+1, unix.AF_INET)
						g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
						expRule = newTestPolicyRule("Egress", "Allow", "192.168.1.1/32", "192.168.7.0/27", 80, 0xffff, "UDP", constants.Tier2, 4*pri+1, unix.AF_INET)
						g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
						expRule = newTestPolicyRule("Egress", "Allow", "192.168.1.1/32", "192.168.7.40/32", 80, 0xffff, "UDP", constants.Tier2, 4*pri+1, unix.AF_INET)
						g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
						expRule = newTestPolicyRule("Egress", "Allow", "192.168.1.1/32", "192.168.7.42/31", 80, 0xffff, "UDP", constants.Tier2, 4*pri+1, unix.AF_INET)
						g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
						expRule = newTestPolicyRule("Egress", "Allow", "192.168.1.1/32", "192.168.7.44/30", 80, 0xffff, "UDP", constants.Tier2, 4*pri+1, unix.AF_INET)
						g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
						expRule = newTestPolicyRule("Egress", "Allow", "192.168.1.1/32", "192.168.7.48/28", 80, 0xffff, "UDP", constants.Tier2, 4*pri+1, unix.AF_INET)
						g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
						expRule = newTestPolicyRule("Egress", "Drop", "192.168.1.1/32", "", 0, 0, "", constants.Tier2, 4*pri, unix.AF_INET)
						g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
					}, timeout, interval).Should(Succeed())
				})
			})
		})
		When("create a sample policy ingress(current agent), applyTo,egress(another agent)", func() {
			var policy *securityv1alpha1.SecurityPolicy

			BeforeEach(func() {
				policy = newTestPolicy([]*testGroup{group4}, []*testGroup{group1}, []*testGroup{group5}, newTestPort("TCP", "80", "number"), newTestPort("UDP", "80", "number"))
				policy.Spec.SymmetricMode = true
				By("create policy " + policy.Name)
				Expect(k8sClient.Create(ctx, policy)).Should(Succeed())
			})
			It("should only create one Symmetric rule", func() {
				assertCompleteRuleNum(4)
				assertPolicyRulesNum(policy, 2)

				assertHasPolicyRule(policy, "Egress", "Allow", "192.168.1.1/32", 0, "192.168.4.1/32", 80, "TCP", unix.AF_INET)
			})
		})
		When("create a sample policy egress(current agent), applyTo,ingress(another agent)", func() {
			var policy *securityv1alpha1.SecurityPolicy

			BeforeEach(func() {
				policy = newTestPolicy([]*testGroup{group4}, []*testGroup{group5}, []*testGroup{group1}, newTestPort("TCP", "80", "number"), newTestPort("UDP", "80", "number"))
				policy.Spec.SymmetricMode = true
				By("create policy " + policy.Name)
				Expect(k8sClient.Create(ctx, policy)).Should(Succeed())
			})
			It("should only create one Symmetric rule", func() {
				assertCompleteRuleNum(4)
				assertPolicyRulesNum(policy, 2)

				assertHasPolicyRule(policy, "Ingress", "Allow", "192.168.4.1/32", 0, "192.168.1.1/32", 80, "UDP", unix.AF_INET)
			})
		})
		When("create a sample policy with apply all endpoints", func() {
			var policy *securityv1alpha1.SecurityPolicy

			BeforeEach(func() {
				policy = newTestPolicy([]*testGroup{groupAll}, []*testGroup{group4}, []*testGroup{group5}, newTestPort("TCP", "80", "number"), newTestPort("UDP", "80", "number"))
				policy.Spec.SymmetricMode = true
				By("create policy " + policy.Name)
				Expect(k8sClient.Create(ctx, policy)).Should(Succeed())
			})
			It("should only create one Symmetric rule", func() {
				assertCompleteRuleNum(4)
				assertPolicyRulesNum(policy, 8)

				assertHasPolicyRule(policy, "Ingress", "Allow", "192.168.4.1/32", 0, "192.168.100.1/32", 80, "TCP", unix.AF_INET)
				assertHasPolicyRule(policy, "Ingress", "Drop", "", 0, "192.168.100.1/32", 0, "", unix.AF_INET)
				assertHasPolicyRule(policy, "Egress", "Allow", "192.168.100.1/32", 0, "192.168.5.1/32", 80, "UDP", unix.AF_INET)
				assertHasPolicyRule(policy, "Egress", "Drop", "192.168.100.1/32", 0, "", 0, "", unix.AF_INET)

				assertHasPolicyRule(policy, "Ingress", "Allow", "fe80::41/128", 0, "fe80::1001/128", 80, "TCP", unix.AF_INET6)
				assertHasPolicyRule(policy, "Ingress", "Drop", "", 0, "fe80::1001/128", 0, "", unix.AF_INET6)
				assertHasPolicyRule(policy, "Egress", "Allow", "fe80::1001/128", 0, "fe80::51/128", 80, "UDP", unix.AF_INET6)
				assertHasPolicyRule(policy, "Egress", "Drop", "fe80::1001/128", 0, "", 0, "", unix.AF_INET6)
			})
		})
	})

	Context("groupmembers", func() {
		var group1, group2, group3 *testGroup
		var ep1, ep2, ep3, ep4, ep5, ep6 *securityv1alpha1.Endpoint
		var policy *securityv1alpha1.SecurityPolicy
		var policyPri, pri int32
		var isBlocklist, symmetricMode bool
		var lenCompleteRule, lenRules int
		var ruleAction string
		var defaultRule securityv1alpha1.DefaultRuleType

		BeforeEach(func() {
			symmetricMode = (rand.Intn(2) == 1)
			policyPri = int32(rand.Intn(100) + 1)
			isBlocklist = (rand.Intn(2) == 1)
			defaultRule = []securityv1alpha1.DefaultRuleType{securityv1alpha1.DefaultRuleDrop, securityv1alpha1.DefaultRuleNone}[rand.Intn(2)]
			ruleAction = "Allow"
			pri = 4*policyPri + 1
			if isBlocklist {
				symmetricMode = false
				ruleAction = "Drop"
				defaultRule = securityv1alpha1.DefaultRuleNone
				pri = 4*policyPri + 3
			}

			ep1NamedPorts := []securityv1alpha1.NamedPort{newTestNamedPort("TCP", "http", 80)}
			ep3NamedPorts := []securityv1alpha1.NamedPort{
				newTestNamedPort("UDP", "dns", 53),
				newTestNamedPort("UDP", "dns", 54),
				newTestNamedPort("UDP", "nfs", 78),
			}
			ep5NamedPorts := []securityv1alpha1.NamedPort{
				newTestNamedPort("UDP", "nfs", 90),
			}
			ep1 = newTestEndpoint([]types.IPAddress{"192.168.1.1", "fe80::11"}, []string{utils.CurrentAgentName()}, ep1NamedPorts)
			ep2 = newTestEndpoint([]types.IPAddress{"192.168.2.1", "fe80::21"}, []string{utils.CurrentAgentName()}, nil)
			ep3 = newTestEndpoint([]types.IPAddress{"192.168.3.1", "fe80::31"}, []string{utils.CurrentAgentName()}, ep3NamedPorts)
			ep4 = newTestEndpoint([]types.IPAddress{"192.168.4.1", "fe80::41"}, []string{"agent2"}, nil)
			ep5 = newTestEndpoint([]types.IPAddress{"192.168.5.1", "fe80::51"}, []string{utils.CurrentAgentName()}, ep5NamedPorts)
			ep6 = newTestEndpoint([]types.IPAddress{"192.168.6.1", "fe80::61"}, []string{}, nil)

			group1 = newTestGroupMembers(0, endpointToMember(ep1))
			group2 = newTestGroupMembers(0, endpointToMember(ep2))
			group3 = newTestGroupMembers(0, endpointToMember(ep3))

			By(fmt.Sprintf("create endpoints %s and groups %v",
				[]string{ep1.Name, ep2.Name, ep3.Name, ep4.Name, ep5.Name, ep6.Name},
				[]string{group1.Name, group2.Name, group3.Name}))
			Expect(k8sClient.Create(ctx, group1.GroupMembers)).Should(Succeed())
			Expect(k8sClient.Create(ctx, group2.GroupMembers)).Should(Succeed())

			By(fmt.Sprintf("create policy, priority=%d, isBlocklist=%v, symmetricMode=%v, defaultRule=%s", pri, isBlocklist, symmetricMode, defaultRule))
			policy = newTestPolicy([]*testGroup{group1}, []*testGroup{group2}, []*testGroup{group3}, newTestPort("TCP", "54", "number"), newTestPort("UDP", "nfs", "name"))
			policy.Spec.IngressRules[0].From = append(policy.Spec.IngressRules[0].From,
				securityv1alpha1.SecurityPolicyPeer{
					IPBlock: &networkingv1.IPBlock{CIDR: "10.10.1.0/31"},
				},
				securityv1alpha1.SecurityPolicyPeer{
					IPBlock: &networkingv1.IPBlock{CIDR: "2401::1010:10/127"},
				})
			policy.Spec.IngressRules[0].From = append(policy.Spec.IngressRules[0].From,
				securityv1alpha1.SecurityPolicyPeer{
					DisableSymmetric: true,
					IPBlock: &networkingv1.IPBlock{
						CIDR: "10.10.2.1/32"},
				}, securityv1alpha1.SecurityPolicyPeer{
					DisableSymmetric: true,
					IPBlock: &networkingv1.IPBlock{
						CIDR: "2401::1010:21/128"},
				})
			policy.Spec.Priority = policyPri
			policy.Spec.IsBlocklist = isBlocklist
			policy.Spec.SymmetricMode = symmetricMode
			policy.Spec.DefaultRule = defaultRule
			Expect(k8sClient.Create(ctx, policy)).Should(Succeed())

			lenCompleteRule = 2
			if symmetricMode {
				lenCompleteRule = 3
			}
			if policy.Spec.DefaultRule == securityv1alpha1.DefaultRuleDrop {
				lenCompleteRule += 2
			}
		})

		It("can't flatten rules", func() {
			time.Sleep(2)
			_, exists := pCtrl.GetGroupCache().ListGroupIPBlocks(ctx, group3.Name)
			Expect(exists).Should(BeFalse())
			Expect(len(ruleCacheLister.ListKeys())).Should(Equal(0))
		})

		When("add groupmembers", func() {
			BeforeEach(func() {
				Expect(k8sClient.Create(ctx, group3.GroupMembers)).Should(Succeed())
			})

			It("should flatten rules", func() {
				lenRules = 8
				if symmetricMode {
					lenRules = 14
				}
				if policy.Spec.DefaultRule == securityv1alpha1.DefaultRuleDrop {
					lenRules += 4
				}
				Eventually(func(g Gomega) {
					g.Expect(len(ruleCacheLister.ListKeys())).Should(Equal(lenCompleteRule))
					rules := getRuleByPolicy(policy)
					g.Expect(len(rules)).Should(Equal(lenRules))
					By("check rules")
					expRule := newTestPolicyRule("Ingress", ruleAction, "192.168.2.1/32", "192.168.1.1/32", 54, 0xffff, "TCP", constants.Tier2, pri, unix.AF_INET)
					g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
					expRule = newTestPolicyRule("Ingress", ruleAction, "10.10.1.0/31", "192.168.1.1/32", 54, 0xffff, "TCP", constants.Tier2, pri, unix.AF_INET)
					g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
					expRule = newTestPolicyRule("Ingress", ruleAction, "10.10.2.1/32", "192.168.1.1/32", 54, 0xffff, "TCP", constants.Tier2, pri, unix.AF_INET)
					g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
					expRule = newTestPolicyRule("Egress", ruleAction, "192.168.1.1/32", "192.168.3.1/32", 78, 0xffff, "UDP", constants.Tier2, pri, unix.AF_INET)
					g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))

					expRule = newTestPolicyRule("Ingress", ruleAction, "fe80::21/128", "fe80::11/128", 54, 0xffff, "TCP", constants.Tier2, pri, unix.AF_INET6)
					g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
					expRule = newTestPolicyRule("Ingress", ruleAction, "2401::1010:10/127", "fe80::11/128", 54, 0xffff, "TCP", constants.Tier2, pri, unix.AF_INET6)
					g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
					expRule = newTestPolicyRule("Ingress", ruleAction, "2401::1010:21/128", "fe80::11/128", 54, 0xffff, "TCP", constants.Tier2, pri, unix.AF_INET6)
					g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
					expRule = newTestPolicyRule("Egress", ruleAction, "fe80::11/128", "fe80::31/128", 78, 0xffff, "UDP", constants.Tier2, pri, unix.AF_INET6)
					g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))

					if symmetricMode {
						By("check symmetric rules")
						expRule = newTestPolicyRule("Egress", ruleAction, "192.168.2.1/32", "192.168.1.1/32", 54, 0xffff, "TCP", constants.Tier2, pri, unix.AF_INET)
						g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
						expRule = newTestPolicyRule("Egress", ruleAction, "10.10.1.0/31", "192.168.1.1/32", 54, 0xffff, "TCP", constants.Tier2, pri, unix.AF_INET)
						g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
						expRule = newTestPolicyRule("Ingress", ruleAction, "192.168.1.1/32", "192.168.3.1/32", 78, 0xffff, "UDP", constants.Tier2, pri, unix.AF_INET)
						g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))

						expRule = newTestPolicyRule("Egress", ruleAction, "fe80::21/128", "fe80::11/128", 54, 0xffff, "TCP", constants.Tier2, pri, unix.AF_INET6)
						g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
						expRule = newTestPolicyRule("Egress", ruleAction, "2401::1010:10/127", "fe80::11/128", 54, 0xffff, "TCP", constants.Tier2, pri, unix.AF_INET6)
						g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
						expRule = newTestPolicyRule("Ingress", ruleAction, "fe80::11/128", "fe80::31/128", 78, 0xffff, "UDP", constants.Tier2, pri, unix.AF_INET6)
						g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
					}

					if policy.Spec.DefaultRule == securityv1alpha1.DefaultRuleDrop {
						By("check default rules")
						expRule = newTestPolicyRule("Ingress", "Drop", "", "192.168.1.1/32", 0, 0, "", constants.Tier2, policyPri*4, unix.AF_INET)
						g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
						expRule = newTestPolicyRule("Egress", "Drop", "192.168.1.1/32", "", 0, 0, "", constants.Tier2, policyPri*4, unix.AF_INET)
						g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))

						expRule = newTestPolicyRule("Ingress", "Drop", "", "fe80::11/128", 0, 0, "", constants.Tier2, policyPri*4, unix.AF_INET6)
						g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
						expRule = newTestPolicyRule("Egress", "Drop", "fe80::11/128", "", 0, 0, "", constants.Tier2, policyPri*4, unix.AF_INET6)
						g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
					}
				}, timeout, interval).Should(Succeed())
			})
		})

		When("update groupmembers", func() {
			BeforeEach(func() {
				Expect(k8sClient.Create(ctx, group3.GroupMembers)).Should(Succeed())

				lenRules = 8
				if symmetricMode {
					lenRules = 14
				}
				if policy.Spec.DefaultRule == securityv1alpha1.DefaultRuleDrop {
					lenRules += 4
				}
				Eventually(func(g Gomega) {
					g.Expect(len(ruleCacheLister.ListKeys())).Should(Equal(lenCompleteRule))
					rules := getRuleByPolicy(policy)
					g.Expect(len(rules)).Should(Equal(lenRules))

					By("check rules")
					expRule := newTestPolicyRule("Ingress", ruleAction, "192.168.2.1/32", "192.168.1.1/32", 54, 0xffff, "TCP", constants.Tier2, pri, unix.AF_INET)
					g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
					expRule = newTestPolicyRule("Ingress", ruleAction, "10.10.1.0/31", "192.168.1.1/32", 54, 0xffff, "TCP", constants.Tier2, pri, unix.AF_INET)
					g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
					expRule = newTestPolicyRule("Ingress", ruleAction, "10.10.2.1/32", "192.168.1.1/32", 54, 0xffff, "TCP", constants.Tier2, pri, unix.AF_INET)
					g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
					expRule = newTestPolicyRule("Egress", ruleAction, "192.168.1.1/32", "192.168.3.1/32", 78, 0xffff, "UDP", constants.Tier2, pri, unix.AF_INET)
					g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))

					expRule = newTestPolicyRule("Ingress", ruleAction, "fe80::21/128", "fe80::11/128", 54, 0xffff, "TCP", constants.Tier2, pri, unix.AF_INET6)
					g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
					expRule = newTestPolicyRule("Ingress", ruleAction, "2401::1010:10/127", "fe80::11/128", 54, 0xffff, "TCP", constants.Tier2, pri, unix.AF_INET6)
					g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
					expRule = newTestPolicyRule("Ingress", ruleAction, "2401::1010:21/128", "fe80::11/128", 54, 0xffff, "TCP", constants.Tier2, pri, unix.AF_INET6)
					g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
					expRule = newTestPolicyRule("Egress", ruleAction, "fe80::11/128", "fe80::31/128", 78, 0xffff, "UDP", constants.Tier2, pri, unix.AF_INET6)
					g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))

					if symmetricMode {
						By("check symmetric rules")
						expRule = newTestPolicyRule("Egress", ruleAction, "192.168.2.1/32", "192.168.1.1/32", 54, 0xffff, "TCP", constants.Tier2, pri, unix.AF_INET)
						g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
						expRule = newTestPolicyRule("Egress", ruleAction, "10.10.1.0/31", "192.168.1.1/32", 54, 0xffff, "TCP", constants.Tier2, pri, unix.AF_INET)
						g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
						expRule = newTestPolicyRule("Ingress", ruleAction, "192.168.1.1/32", "192.168.3.1/32", 78, 0xffff, "UDP", constants.Tier2, pri, unix.AF_INET)
						g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))

						expRule = newTestPolicyRule("Egress", ruleAction, "fe80::21/128", "fe80::11/128", 54, 0xffff, "TCP", constants.Tier2, pri, unix.AF_INET6)
						g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
						expRule = newTestPolicyRule("Egress", ruleAction, "2401::1010:10/127", "fe80::11/128", 54, 0xffff, "TCP", constants.Tier2, pri, unix.AF_INET6)
						g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
						expRule = newTestPolicyRule("Ingress", ruleAction, "fe80::11/128", "fe80::31/128", 78, 0xffff, "UDP", constants.Tier2, pri, unix.AF_INET6)
						g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
					}

					if policy.Spec.DefaultRule == securityv1alpha1.DefaultRuleDrop {
						By("check default rules")
						expRule = newTestPolicyRule("Ingress", "Drop", "", "192.168.1.1/32", 0, 0, "", constants.Tier2, 4*policyPri, unix.AF_INET)
						g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
						expRule = newTestPolicyRule("Egress", "Drop", "192.168.1.1/32", "", 0, 0, "", constants.Tier2, 4*policyPri, unix.AF_INET)
						g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))

						expRule = newTestPolicyRule("Ingress", "Drop", "", "fe80::11/128", 0, 0, "", constants.Tier2, 4*policyPri, unix.AF_INET6)
						g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
						expRule = newTestPolicyRule("Egress", "Drop", "fe80::11/128", "", 0, 0, "", constants.Tier2, 4*policyPri, unix.AF_INET6)
						g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
					}
				}, timeout, interval).Should(Succeed())
			})

			When("add endpoint to groupmembers", func() {
				When("add local endpoint", func() {
					BeforeEach(func() {
						gm := &groupv1alpha1.GroupMembers{}
						Expect(k8sClient.Get(ctx, k8stypes.NamespacedName{Name: group3.GetName()}, gm)).Should(Succeed())
						gm.GroupMembers = append(gm.GroupMembers, *endpointToMember(ep5))
						Expect(k8sClient.Update(ctx, gm)).Should(Succeed())
					})

					It("check rules", func() {
						lenRules += 2
						if symmetricMode {
							lenRules += 2
						}

						Eventually(func(g Gomega) {
							g.Expect(len(ruleCacheLister.ListKeys())).Should(Equal(lenCompleteRule))
							rules := getRuleByPolicy(policy)
							g.Expect(len(rules)).Should(Equal(lenRules))

							By("check rules")
							expRule := newTestPolicyRule("Ingress", ruleAction, "192.168.2.1/32", "192.168.1.1/32", 54, 0xffff, "TCP", constants.Tier2, pri, unix.AF_INET)
							g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
							expRule = newTestPolicyRule("Ingress", ruleAction, "10.10.1.0/31", "192.168.1.1/32", 54, 0xffff, "TCP", constants.Tier2, pri, unix.AF_INET)
							g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
							expRule = newTestPolicyRule("Ingress", ruleAction, "10.10.2.1/32", "192.168.1.1/32", 54, 0xffff, "TCP", constants.Tier2, pri, unix.AF_INET)
							g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
							expRule = newTestPolicyRule("Egress", ruleAction, "192.168.1.1/32", "192.168.3.1/32", 78, 0xffff, "UDP", constants.Tier2, pri, unix.AF_INET)
							g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
							expRule = newTestPolicyRule("Egress", ruleAction, "192.168.1.1/32", "192.168.5.1/32", 90, 0xffff, "UDP", constants.Tier2, pri, unix.AF_INET)
							g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))

							expRule = newTestPolicyRule("Ingress", ruleAction, "fe80::21/128", "fe80::11/128", 54, 0xffff, "TCP", constants.Tier2, pri, unix.AF_INET6)
							g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
							expRule = newTestPolicyRule("Ingress", ruleAction, "2401::1010:10/127", "fe80::11/128", 54, 0xffff, "TCP", constants.Tier2, pri, unix.AF_INET6)
							g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
							expRule = newTestPolicyRule("Ingress", ruleAction, "2401::1010:21/128", "fe80::11/128", 54, 0xffff, "TCP", constants.Tier2, pri, unix.AF_INET6)
							g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
							expRule = newTestPolicyRule("Egress", ruleAction, "fe80::11/128", "fe80::31/128", 78, 0xffff, "UDP", constants.Tier2, pri, unix.AF_INET6)
							g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
							expRule = newTestPolicyRule("Egress", ruleAction, "fe80::11/128", "fe80::51/128", 90, 0xffff, "UDP", constants.Tier2, pri, unix.AF_INET6)
							g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
							if symmetricMode {
								By("check symmetric rules")
								expRule = newTestPolicyRule("Egress", ruleAction, "192.168.2.1/32", "192.168.1.1/32", 54, 0xffff, "TCP", constants.Tier2, pri, unix.AF_INET)
								g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
								expRule = newTestPolicyRule("Egress", ruleAction, "10.10.1.0/31", "192.168.1.1/32", 54, 0xffff, "TCP", constants.Tier2, pri, unix.AF_INET)
								g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
								expRule = newTestPolicyRule("Ingress", ruleAction, "192.168.1.1/32", "192.168.3.1/32", 78, 0xffff, "UDP", constants.Tier2, pri, unix.AF_INET)
								g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
								expRule = newTestPolicyRule("Ingress", ruleAction, "192.168.1.1/32", "192.168.5.1/32", 90, 0xffff, "UDP", constants.Tier2, pri, unix.AF_INET)
								g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))

								expRule = newTestPolicyRule("Egress", ruleAction, "fe80::21/128", "fe80::11/128", 54, 0xffff, "TCP", constants.Tier2, pri, unix.AF_INET6)
								g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
								expRule = newTestPolicyRule("Egress", ruleAction, "2401::1010:10/127", "fe80::11/128", 54, 0xffff, "TCP", constants.Tier2, pri, unix.AF_INET6)
								g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
								expRule = newTestPolicyRule("Ingress", ruleAction, "fe80::11/128", "fe80::31/128", 78, 0xffff, "UDP", constants.Tier2, pri, unix.AF_INET6)
								g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
								expRule = newTestPolicyRule("Ingress", ruleAction, "fe80::11/128", "fe80::51/128", 90, 0xffff, "UDP", constants.Tier2, pri, unix.AF_INET6)
								g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
							}

							if policy.Spec.DefaultRule == securityv1alpha1.DefaultRuleDrop {
								By("check default rules")
								expRule = newTestPolicyRule("Ingress", "Drop", "", "192.168.1.1/32", 0, 0, "", constants.Tier2, 4*policyPri, unix.AF_INET)
								g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
								expRule = newTestPolicyRule("Egress", "Drop", "192.168.1.1/32", "", 0, 0, "", constants.Tier2, 4*policyPri, unix.AF_INET)
								g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))

								expRule = newTestPolicyRule("Ingress", "Drop", "", "fe80::11/128", 0, 0, "", constants.Tier2, 4*policyPri, unix.AF_INET6)
								g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
								expRule = newTestPolicyRule("Egress", "Drop", "fe80::11/128", "", 0, 0, "", constants.Tier2, 4*policyPri, unix.AF_INET6)
								g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
							}
						}, timeout, interval).Should(Succeed())
					})
				})

				When("add endpoint in other agent", func() {
					BeforeEach(func() {
						gm := &groupv1alpha1.GroupMembers{}
						Expect(k8sClient.Get(ctx, k8stypes.NamespacedName{Name: group2.GetName()}, gm)).Should(Succeed())
						gm.GroupMembers = append(gm.GroupMembers, *endpointToMember(ep4))
						Expect(k8sClient.Update(ctx, gm)).Should(Succeed())
					})

					It("check rules", func() {
						lenRules += 2

						Eventually(func(g Gomega) {
							g.Expect(len(ruleCacheLister.ListKeys())).Should(Equal(lenCompleteRule))
							rules := getRuleByPolicy(policy)
							g.Expect(len(rules)).Should(Equal(lenRules))

							By("check rules")
							expRule := newTestPolicyRule("Ingress", ruleAction, "192.168.2.1/32", "192.168.1.1/32", 54, 0xffff, "TCP", constants.Tier2, pri, unix.AF_INET)
							g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
							expRule = newTestPolicyRule("Ingress", ruleAction, "10.10.1.0/31", "192.168.1.1/32", 54, 0xffff, "TCP", constants.Tier2, pri, unix.AF_INET)
							g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
							expRule = newTestPolicyRule("Ingress", ruleAction, "10.10.2.1/32", "192.168.1.1/32", 54, 0xffff, "TCP", constants.Tier2, pri, unix.AF_INET)
							g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
							expRule = newTestPolicyRule("Egress", ruleAction, "192.168.1.1/32", "192.168.3.1/32", 78, 0xffff, "UDP", constants.Tier2, pri, unix.AF_INET)
							g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
							expRule = newTestPolicyRule("Ingress", ruleAction, "192.168.4.1/32", "192.168.1.1/32", 54, 0xffff, "TCP", constants.Tier2, pri, unix.AF_INET)
							g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))

							expRule = newTestPolicyRule("Ingress", ruleAction, "fe80::21/128", "fe80::11/128", 54, 0xffff, "TCP", constants.Tier2, pri, unix.AF_INET6)
							g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
							expRule = newTestPolicyRule("Ingress", ruleAction, "2401::1010:10/127", "fe80::11/128", 54, 0xffff, "TCP", constants.Tier2, pri, unix.AF_INET6)
							g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
							expRule = newTestPolicyRule("Ingress", ruleAction, "2401::1010:21/128", "fe80::11/128", 54, 0xffff, "TCP", constants.Tier2, pri, unix.AF_INET6)
							g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
							expRule = newTestPolicyRule("Egress", ruleAction, "fe80::11/128", "fe80::31/128", 78, 0xffff, "UDP", constants.Tier2, pri, unix.AF_INET6)
							g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
							expRule = newTestPolicyRule("Ingress", ruleAction, "fe80::41/128", "fe80::11/128", 54, 0xffff, "TCP", constants.Tier2, pri, unix.AF_INET6)
							g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))

							if symmetricMode {
								By("check symmetric rules")
								expRule = newTestPolicyRule("Egress", ruleAction, "192.168.2.1/32", "192.168.1.1/32", 54, 0xffff, "TCP", constants.Tier2, pri, unix.AF_INET)
								g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
								expRule = newTestPolicyRule("Egress", ruleAction, "10.10.1.0/31", "192.168.1.1/32", 54, 0xffff, "TCP", constants.Tier2, pri, unix.AF_INET)
								g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
								expRule = newTestPolicyRule("Ingress", ruleAction, "192.168.1.1/32", "192.168.3.1/32", 78, 0xffff, "UDP", constants.Tier2, pri, unix.AF_INET)
								g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))

								expRule = newTestPolicyRule("Egress", ruleAction, "fe80::21/128", "fe80::11/128", 54, 0xffff, "TCP", constants.Tier2, pri, unix.AF_INET6)
								g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
								expRule = newTestPolicyRule("Egress", ruleAction, "2401::1010:10/127", "fe80::11/128", 54, 0xffff, "TCP", constants.Tier2, pri, unix.AF_INET6)
								g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
								expRule = newTestPolicyRule("Ingress", ruleAction, "fe80::11/128", "fe80::31/128", 78, 0xffff, "UDP", constants.Tier2, pri, unix.AF_INET6)
								g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
							}

							if policy.Spec.DefaultRule == securityv1alpha1.DefaultRuleDrop {
								By("check default rules")
								expRule = newTestPolicyRule("Ingress", "Drop", "", "192.168.1.1/32", 0, 0, "", constants.Tier2, 4*policyPri, unix.AF_INET)
								g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
								expRule = newTestPolicyRule("Egress", "Drop", "192.168.1.1/32", "", 0, 0, "", constants.Tier2, 4*policyPri, unix.AF_INET)
								g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))

								expRule = newTestPolicyRule("Ingress", "Drop", "", "fe80::11/128", 0, 0, "", constants.Tier2, 4*policyPri, unix.AF_INET6)
								g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
								expRule = newTestPolicyRule("Egress", "Drop", "fe80::11/128", "", 0, 0, "", constants.Tier2, 4*policyPri, unix.AF_INET6)
								g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
							}
						}, timeout, interval).Should(Succeed())
					})
				})

				When("add endpoint in all agent", func() {
					BeforeEach(func() {
						gm := &groupv1alpha1.GroupMembers{}
						Expect(k8sClient.Get(ctx, k8stypes.NamespacedName{Name: group1.GetName()}, gm)).Should(Succeed())
						gm.GroupMembers = append(gm.GroupMembers, *endpointToMember(ep6))
						Expect(k8sClient.Update(ctx, gm)).Should(Succeed())
					})

					It("check rules", func() {
						lenRules = lenRules * 2

						Eventually(func(g Gomega) {
							g.Expect(len(ruleCacheLister.ListKeys())).Should(Equal(lenCompleteRule))
							rules := getRuleByPolicy(policy)
							g.Expect(len(rules)).Should(Equal(lenRules))

							By("check rules")
							expRule := newTestPolicyRule("Ingress", ruleAction, "192.168.2.1/32", "192.168.1.1/32", 54, 0xffff, "TCP", constants.Tier2, pri, unix.AF_INET)
							g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
							expRule = newTestPolicyRule("Ingress", ruleAction, "10.10.1.0/31", "192.168.1.1/32", 54, 0xffff, "TCP", constants.Tier2, pri, unix.AF_INET)
							g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
							expRule = newTestPolicyRule("Ingress", ruleAction, "10.10.2.1/32", "192.168.1.1/32", 54, 0xffff, "TCP", constants.Tier2, pri, unix.AF_INET)
							g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
							expRule = newTestPolicyRule("Egress", ruleAction, "192.168.1.1/32", "192.168.3.1/32", 78, 0xffff, "UDP", constants.Tier2, pri, unix.AF_INET)
							g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
							expRule = newTestPolicyRule("Ingress", ruleAction, "192.168.2.1/32", "192.168.6.1/32", 54, 0xffff, "TCP", constants.Tier2, pri, unix.AF_INET)
							g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
							expRule = newTestPolicyRule("Ingress", ruleAction, "10.10.1.0/31", "192.168.6.1/32", 54, 0xffff, "TCP", constants.Tier2, pri, unix.AF_INET)
							g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
							expRule = newTestPolicyRule("Ingress", ruleAction, "10.10.2.1/32", "192.168.6.1/32", 54, 0xffff, "TCP", constants.Tier2, pri, unix.AF_INET)
							g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
							expRule = newTestPolicyRule("Egress", ruleAction, "192.168.6.1/32", "192.168.3.1/32", 78, 0xffff, "UDP", constants.Tier2, pri, unix.AF_INET)
							g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))

							expRule = newTestPolicyRule("Ingress", ruleAction, "fe80::21/128", "fe80::11/128", 54, 0xffff, "TCP", constants.Tier2, pri, unix.AF_INET6)
							g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
							expRule = newTestPolicyRule("Ingress", ruleAction, "2401::1010:10/127", "fe80::11/128", 54, 0xffff, "TCP", constants.Tier2, pri, unix.AF_INET6)
							g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
							expRule = newTestPolicyRule("Ingress", ruleAction, "2401::1010:21/128", "fe80::11/128", 54, 0xffff, "TCP", constants.Tier2, pri, unix.AF_INET6)
							g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
							expRule = newTestPolicyRule("Egress", ruleAction, "fe80::11/128", "fe80::31/128", 78, 0xffff, "UDP", constants.Tier2, pri, unix.AF_INET6)
							g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
							expRule = newTestPolicyRule("Ingress", ruleAction, "fe80::21/128", "fe80::61/128", 54, 0xffff, "TCP", constants.Tier2, pri, unix.AF_INET6)
							g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
							expRule = newTestPolicyRule("Ingress", ruleAction, "2401::1010:10/127", "fe80::61/128", 54, 0xffff, "TCP", constants.Tier2, pri, unix.AF_INET6)
							g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
							expRule = newTestPolicyRule("Ingress", ruleAction, "2401::1010:21/128", "fe80::61/128", 54, 0xffff, "TCP", constants.Tier2, pri, unix.AF_INET6)
							g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
							expRule = newTestPolicyRule("Egress", ruleAction, "fe80::61/128", "fe80::31/128", 78, 0xffff, "UDP", constants.Tier2, pri, unix.AF_INET6)
							g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))

							if symmetricMode {
								By("check symmetric rules")
								expRule = newTestPolicyRule("Egress", ruleAction, "192.168.2.1/32", "192.168.1.1/32", 54, 0xffff, "TCP", constants.Tier2, pri, unix.AF_INET)
								g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
								expRule = newTestPolicyRule("Egress", ruleAction, "10.10.1.0/31", "192.168.1.1/32", 54, 0xffff, "TCP", constants.Tier2, pri, unix.AF_INET)
								g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
								expRule = newTestPolicyRule("Ingress", ruleAction, "192.168.1.1/32", "192.168.3.1/32", 78, 0xffff, "UDP", constants.Tier2, pri, unix.AF_INET)
								g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
								expRule = newTestPolicyRule("Egress", ruleAction, "192.168.2.1/32", "192.168.6.1/32", 54, 0xffff, "TCP", constants.Tier2, pri, unix.AF_INET)
								g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
								expRule = newTestPolicyRule("Egress", ruleAction, "10.10.1.0/31", "192.168.6.1/32", 54, 0xffff, "TCP", constants.Tier2, pri, unix.AF_INET)
								g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
								expRule = newTestPolicyRule("Ingress", ruleAction, "192.168.6.1/32", "192.168.3.1/32", 78, 0xffff, "UDP", constants.Tier2, pri, unix.AF_INET)
								g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))

								expRule = newTestPolicyRule("Egress", ruleAction, "fe80::21/128", "fe80::11/128", 54, 0xffff, "TCP", constants.Tier2, pri, unix.AF_INET6)
								g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
								expRule = newTestPolicyRule("Egress", ruleAction, "2401::1010:10/127", "fe80::11/128", 54, 0xffff, "TCP", constants.Tier2, pri, unix.AF_INET6)
								g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
								expRule = newTestPolicyRule("Ingress", ruleAction, "fe80::11/128", "fe80::31/128", 78, 0xffff, "UDP", constants.Tier2, pri, unix.AF_INET6)
								g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
								expRule = newTestPolicyRule("Egress", ruleAction, "fe80::21/128", "fe80::61/128", 54, 0xffff, "TCP", constants.Tier2, pri, unix.AF_INET6)
								g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
								expRule = newTestPolicyRule("Egress", ruleAction, "2401::1010:10/127", "fe80::61/128", 54, 0xffff, "TCP", constants.Tier2, pri, unix.AF_INET6)
								g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
								expRule = newTestPolicyRule("Ingress", ruleAction, "fe80::61/128", "fe80::31/128", 78, 0xffff, "UDP", constants.Tier2, pri, unix.AF_INET6)
								g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
							}

							if policy.Spec.DefaultRule == securityv1alpha1.DefaultRuleDrop {
								By("check default rules")
								expRule = newTestPolicyRule("Ingress", "Drop", "", "192.168.1.1/32", 0, 0, "", constants.Tier2, 4*policyPri, unix.AF_INET)
								g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
								expRule = newTestPolicyRule("Egress", "Drop", "192.168.1.1/32", "", 0, 0, "", constants.Tier2, 4*policyPri, unix.AF_INET)
								g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
								expRule = newTestPolicyRule("Ingress", "Drop", "", "192.168.6.1/32", 0, 0, "", constants.Tier2, 4*policyPri, unix.AF_INET)
								g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
								expRule = newTestPolicyRule("Egress", "Drop", "192.168.6.1/32", "", 0, 0, "", constants.Tier2, 4*policyPri, unix.AF_INET)
								g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))

								expRule = newTestPolicyRule("Ingress", "Drop", "", "fe80::11/128", 0, 0, "", constants.Tier2, 4*policyPri, unix.AF_INET6)
								g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
								expRule = newTestPolicyRule("Egress", "Drop", "fe80::11/128", "", 0, 0, "", constants.Tier2, 4*policyPri, unix.AF_INET6)
								g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
								expRule = newTestPolicyRule("Ingress", "Drop", "", "fe80::61/128", 0, 0, "", constants.Tier2, 4*policyPri, unix.AF_INET6)
								g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
								expRule = newTestPolicyRule("Egress", "Drop", "fe80::61/128", "", 0, 0, "", constants.Tier2, 4*policyPri, unix.AF_INET6)
								g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
							}
						}, timeout, interval).Should(Succeed())
					})
				})
			})

			When("update endpoint IP", func() {
				BeforeEach(func() {
					gm := &groupv1alpha1.GroupMembers{}
					Expect(k8sClient.Get(ctx, k8stypes.NamespacedName{Name: group2.GetName()}, gm)).Should(Succeed())
					gm.GroupMembers[0].IPs = []types.IPAddress{"10.10.3.1", "2401::1010:31"}
					Expect(k8sClient.Update(ctx, gm)).Should(Succeed())
				})

				It("check rules", func() {
					Eventually(func(g Gomega) {
						g.Expect(len(ruleCacheLister.ListKeys())).Should(Equal(lenCompleteRule))
						rules := getRuleByPolicy(policy)
						g.Expect(len(rules)).Should(Equal(lenRules))

						By("check rules")
						expRule := newTestPolicyRule("Ingress", ruleAction, "10.10.3.1/32", "192.168.1.1/32", 54, 0xffff, "TCP", constants.Tier2, pri, unix.AF_INET)
						g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
						expRule = newTestPolicyRule("Ingress", ruleAction, "10.10.1.0/31", "192.168.1.1/32", 54, 0xffff, "TCP", constants.Tier2, pri, unix.AF_INET)
						g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
						expRule = newTestPolicyRule("Ingress", ruleAction, "10.10.2.1/32", "192.168.1.1/32", 54, 0xffff, "TCP", constants.Tier2, pri, unix.AF_INET)
						g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
						expRule = newTestPolicyRule("Egress", ruleAction, "192.168.1.1/32", "192.168.3.1/32", 78, 0xffff, "UDP", constants.Tier2, pri, unix.AF_INET)
						g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))

						expRule = newTestPolicyRule("Ingress", ruleAction, "2401::1010:31/128", "fe80::11/128", 54, 0xffff, "TCP", constants.Tier2, pri, unix.AF_INET6)
						g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
						expRule = newTestPolicyRule("Ingress", ruleAction, "2401::1010:10/127", "fe80::11/128", 54, 0xffff, "TCP", constants.Tier2, pri, unix.AF_INET6)
						g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
						expRule = newTestPolicyRule("Ingress", ruleAction, "2401::1010:21/128", "fe80::11/128", 54, 0xffff, "TCP", constants.Tier2, pri, unix.AF_INET6)
						g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
						expRule = newTestPolicyRule("Egress", ruleAction, "fe80::11/128", "fe80::31/128", 78, 0xffff, "UDP", constants.Tier2, pri, unix.AF_INET6)
						g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))

						if symmetricMode {
							By("check symmetric rules")
							expRule = newTestPolicyRule("Egress", ruleAction, "10.10.3.1/32", "192.168.1.1/32", 54, 0xffff, "TCP", constants.Tier2, pri, unix.AF_INET)
							g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
							expRule = newTestPolicyRule("Egress", ruleAction, "10.10.1.0/31", "192.168.1.1/32", 54, 0xffff, "TCP", constants.Tier2, pri, unix.AF_INET)
							g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
							expRule = newTestPolicyRule("Ingress", ruleAction, "192.168.1.1/32", "192.168.3.1/32", 78, 0xffff, "UDP", constants.Tier2, pri, unix.AF_INET)
							g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))

							expRule = newTestPolicyRule("Egress", ruleAction, "2401::1010:31/128", "fe80::11/128", 54, 0xffff, "TCP", constants.Tier2, pri, unix.AF_INET6)
							g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
							expRule = newTestPolicyRule("Egress", ruleAction, "2401::1010:10/127", "fe80::11/128", 54, 0xffff, "TCP", constants.Tier2, pri, unix.AF_INET6)
							g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
							expRule = newTestPolicyRule("Ingress", ruleAction, "fe80::11/128", "fe80::31/128", 78, 0xffff, "UDP", constants.Tier2, pri, unix.AF_INET6)
							g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
						}

						if policy.Spec.DefaultRule == securityv1alpha1.DefaultRuleDrop {
							By("check default rules")
							expRule = newTestPolicyRule("Ingress", "Drop", "", "192.168.1.1/32", 0, 0, "", constants.Tier2, 4*policyPri, unix.AF_INET)
							g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
							expRule = newTestPolicyRule("Egress", "Drop", "192.168.1.1/32", "", 0, 0, "", constants.Tier2, 4*policyPri, unix.AF_INET)
							g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))

							expRule = newTestPolicyRule("Ingress", "Drop", "", "fe80::11/128", 0, 0, "", constants.Tier2, 4*policyPri, unix.AF_INET6)
							g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
							expRule = newTestPolicyRule("Egress", "Drop", "fe80::11/128", "", 0, 0, "", constants.Tier2, 4*policyPri, unix.AF_INET6)
							g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
						}
					}, timeout, interval).Should(Succeed())
				})

			})

			When("update endpoint agents", func() {
				BeforeEach(func() {
					gm := &groupv1alpha1.GroupMembers{}
					Expect(k8sClient.Get(ctx, k8stypes.NamespacedName{Name: group1.GetName()}, gm)).Should(Succeed())
					gm.GroupMembers[0].EndpointAgent = []string{"agent-unexists"}
					Expect(k8sClient.Update(ctx, gm)).Should(Succeed())
				})

				It("check rules", func() {
					lenRules -= 8
					if policy.Spec.DefaultRule == securityv1alpha1.DefaultRuleDrop {
						lenRules -= 4
					}
					Eventually(func(g Gomega) {
						g.Expect(len(ruleCacheLister.ListKeys())).Should(Equal(lenCompleteRule))
						rules := getRuleByPolicy(policy)
						g.Expect(len(rules)).Should(Equal(lenRules))

						By("check rules")
						var expRule cache.PolicyRule

						if symmetricMode {
							By("check symmetric rules")
							expRule = newTestPolicyRule("Egress", ruleAction, "10.10.1.0/31", "192.168.1.1/32", 54, 0xffff, "TCP", constants.Tier2, pri, unix.AF_INET)
							g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
							expRule = newTestPolicyRule("Egress", ruleAction, "192.168.2.1/32", "192.168.1.1/32", 54, 0xffff, "TCP", constants.Tier2, pri, unix.AF_INET)
							g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
							expRule = newTestPolicyRule("Ingress", ruleAction, "192.168.1.1/32", "192.168.3.1/32", 78, 0xffff, "UDP", constants.Tier2, pri, unix.AF_INET)
							g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))

							expRule = newTestPolicyRule("Egress", ruleAction, "2401::1010:10/127", "fe80::11/128", 54, 0xffff, "TCP", constants.Tier2, pri, unix.AF_INET6)
							g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
							expRule = newTestPolicyRule("Egress", ruleAction, "fe80::21/128", "fe80::11/128", 54, 0xffff, "TCP", constants.Tier2, pri, unix.AF_INET6)
							g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
							expRule = newTestPolicyRule("Ingress", ruleAction, "fe80::11/128", "fe80::31/128", 78, 0xffff, "UDP", constants.Tier2, pri, unix.AF_INET6)
							g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
						}
					}, timeout, interval).Should(Succeed())
				})
			})
			When("del endpoint from groupmembers", func() {
				BeforeEach(func() {
					gm := &groupv1alpha1.GroupMembers{}
					Expect(k8sClient.Get(ctx, k8stypes.NamespacedName{Name: group2.GetName()}, gm)).Should(Succeed())
					gm.GroupMembers = nil
					Expect(k8sClient.Update(ctx, gm)).Should(Succeed())
				})

				It("check rules", func() {
					lenRules -= 2
					if symmetricMode {
						lenRules -= 2
					}
					Eventually(func(g Gomega) {
						g.Expect(len(ruleCacheLister.ListKeys())).Should(Equal(lenCompleteRule))
						rules := getRuleByPolicy(policy)
						g.Expect(len(rules)).Should(Equal(lenRules))

						By("check rules")
						expRule := newTestPolicyRule("Ingress", ruleAction, "10.10.1.0/31", "192.168.1.1/32", 54, 0xffff, "TCP", constants.Tier2, pri, unix.AF_INET)
						g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
						expRule = newTestPolicyRule("Ingress", ruleAction, "10.10.2.1/32", "192.168.1.1/32", 54, 0xffff, "TCP", constants.Tier2, pri, unix.AF_INET)
						g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
						expRule = newTestPolicyRule("Egress", ruleAction, "192.168.1.1/32", "192.168.3.1/32", 78, 0xffff, "UDP", constants.Tier2, pri, unix.AF_INET)
						g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))

						expRule = newTestPolicyRule("Ingress", ruleAction, "2401::1010:10/127", "fe80::11/128", 54, 0xffff, "TCP", constants.Tier2, pri, unix.AF_INET6)
						g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
						expRule = newTestPolicyRule("Ingress", ruleAction, "2401::1010:21/128", "fe80::11/128", 54, 0xffff, "TCP", constants.Tier2, pri, unix.AF_INET6)
						g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
						expRule = newTestPolicyRule("Egress", ruleAction, "fe80::11/128", "fe80::31/128", 78, 0xffff, "UDP", constants.Tier2, pri, unix.AF_INET6)
						g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))

						if symmetricMode {
							By("check symmetric rules")
							expRule = newTestPolicyRule("Egress", ruleAction, "10.10.1.0/31", "192.168.1.1/32", 54, 0xffff, "TCP", constants.Tier2, pri, unix.AF_INET)
							g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
							expRule = newTestPolicyRule("Ingress", ruleAction, "192.168.1.1/32", "192.168.3.1/32", 78, 0xffff, "UDP", constants.Tier2, pri, unix.AF_INET)
							g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))

							expRule = newTestPolicyRule("Egress", ruleAction, "2401::1010:10/127", "fe80::11/128", 54, 0xffff, "TCP", constants.Tier2, pri, unix.AF_INET6)
							g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
							expRule = newTestPolicyRule("Ingress", ruleAction, "fe80::11/128", "fe80::31/128", 78, 0xffff, "UDP", constants.Tier2, pri, unix.AF_INET6)
							g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
						}

						if policy.Spec.DefaultRule == securityv1alpha1.DefaultRuleDrop {
							By("check default rules")
							expRule = newTestPolicyRule("Ingress", "Drop", "", "192.168.1.1/32", 0, 0, "", constants.Tier2, 4*policyPri, unix.AF_INET)
							g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
							expRule = newTestPolicyRule("Egress", "Drop", "192.168.1.1/32", "", 0, 0, "", constants.Tier2, 4*policyPri, unix.AF_INET)
							g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))

							expRule = newTestPolicyRule("Ingress", "Drop", "", "fe80::11/128", 0, 0, "", constants.Tier2, 4*policyPri, unix.AF_INET6)
							g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
							expRule = newTestPolicyRule("Egress", "Drop", "fe80::11/128", "", 0, 0, "", constants.Tier2, 4*policyPri, unix.AF_INET6)
							g.Expect(rules).Should(ContainElement(NewPolicyRuleMatcher(expRule)))
						}
					}, timeout, interval).Should(Succeed())
				})
			})
		})

		When("del groupmembers", func() {

			BeforeEach(func() {
				Expect(k8sClient.Create(ctx, group3.GroupMembers)).Should(Succeed())
				Eventually(func(g Gomega) {
					g.Expect(len(ruleCacheLister.ListKeys())).ShouldNot(Equal(0))
				}, timeout, interval).Should(Succeed())

				By(fmt.Sprintf("delete group2 %s", group2.GetName()))
				gm := &groupv1alpha1.GroupMembers{}
				Expect(k8sClient.Get(ctx, k8stypes.NamespacedName{Name: group2.GetName()}, gm)).Should(Succeed())
				Expect(k8sClient.Delete(ctx, gm)).Should(Succeed())
			})

			When("policy referenced the group", func() {
				It("can't del groupmembers succeed", func() {
					time.Sleep(2)
					_, exists := pCtrl.GetGroupCache().ListGroupIPBlocks(ctx, group2.Name)
					Expect(exists).Should(BeTrue())
				})
			})

			When("no policy referenced the group", func() {
				BeforeEach(func() {
					p := &securityv1alpha1.SecurityPolicy{}
					Expect(k8sClient.Get(ctx, k8stypes.NamespacedName{Namespace: policy.GetNamespace(), Name: policy.GetName()}, p)).Should(Succeed())
					Expect((k8sClient.Delete(ctx, p))).Should(Succeed())
				})

				It("should delete groupmembers from cache", func() {
					Eventually(func(g Gomega) {
						_, exists := pCtrl.GetGroupCache().ListGroupIPBlocks(ctx, group2.Name)
						g.Expect(exists).Should(BeFalse())
					}, timeout, interval).Should(Succeed())
				})
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

			Expect(completeRuleCache.Add(newTestCompleteRule(ruleID, srcGroup, dstGroup, policyNamespacedName))).Should(Succeed())
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
			portRange: newTestPort("TCP", "80", "number"),
			expectRulePort: []cache.RulePort{
				{DstPort: 80, DstPortMask: 0xffff, Protocol: "TCP"},
			},
		},
		"should unmarshal portRange": {
			portRange: newTestPort("TCP", "20-25", "number"),
			expectRulePort: []cache.RulePort{
				{DstPort: 20, DstPortMask: 0xfffc, Protocol: "TCP"},
				{DstPort: 24, DstPortMask: 0xfffe, Protocol: "TCP"},
			},
		},
		"should unmarshal multiple portRange": {
			portRange: newTestPort("TCP", "20-25,80", "number"),
			expectRulePort: []cache.RulePort{
				{DstPort: 20, DstPortMask: 0xfffc, Protocol: "TCP"},
				{DstPort: 24, DstPortMask: 0xfffe, Protocol: "TCP"},
				{DstPort: 80, DstPortMask: 0xffff, Protocol: "TCP"},
			},
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			ports, err := FlattenPorts([]securityv1alpha1.SecurityPolicyPort{*tc.portRange})
			if tc.expectError && err == nil || !tc.expectError && err != nil {
				t.Fatalf("expect error: %t, but get error: %s", tc.expectError, err)
			}
			if !reflect.DeepEqual(ports, tc.expectRulePort) {
				t.Fatalf("expect rule ports: %+v, get rule ports: %+v", tc.expectRulePort, ports)
			}
		})
	}
}

func newTestPort(protocol, portRange, portType string) *securityv1alpha1.SecurityPolicyPort {
	return &securityv1alpha1.SecurityPolicyPort{
		Protocol:  securityv1alpha1.Protocol(protocol),
		PortRange: portRange,
		Type:      securityv1alpha1.PortType(portType),
	}
}

func newTestNamedPort(protocol, name string, port int32) securityv1alpha1.NamedPort {
	return securityv1alpha1.NamedPort{
		Protocol: securityv1alpha1.Protocol(protocol),
		Port:     port,
		Name:     name,
	}
}

func newTestPolicy(appliedTo, ingress, egress []*testGroup, ingressPort, egressPort *securityv1alpha1.SecurityPolicyPort) *securityv1alpha1.SecurityPolicy {
	var name = "policy-test-" + rand.String(6)

	p := &securityv1alpha1.SecurityPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: metav1.NamespaceDefault,
		},
		Spec: securityv1alpha1.SecurityPolicySpec{
			AppliedTo: []securityv1alpha1.ApplyToPeer{},
			IngressRules: []securityv1alpha1.Rule{
				{
					Name: "ingress",
					Ports: []securityv1alpha1.SecurityPolicyPort{
						*ingressPort,
					},
					From: []securityv1alpha1.SecurityPolicyPeer{},
				},
			},
			EgressRules: []securityv1alpha1.Rule{
				{
					Name: "egress",
					Ports: []securityv1alpha1.SecurityPolicyPort{
						*egressPort,
					},
					To: []securityv1alpha1.SecurityPolicyPeer{},
				},
			},
			PolicyTypes: []networkingv1.PolicyType{
				networkingv1.PolicyTypeIngress,
				networkingv1.PolicyTypeEgress,
			},
			Tier:                          constants.Tier2,
			SecurityPolicyEnforcementMode: securityv1alpha1.WorkMode,
		},
	}

	for _, item := range appliedTo {
		p.Spec.AppliedTo = append(p.Spec.AppliedTo,
			securityv1alpha1.ApplyToPeer{
				EndpointSelector: item.endpointSelector,
				IPBlock:          item.ipBlock,
			})
	}
	for _, item := range ingress {
		p.Spec.IngressRules[0].From = append(p.Spec.IngressRules[0].From,
			securityv1alpha1.SecurityPolicyPeer{
				EndpointSelector: item.endpointSelector,
				IPBlock:          item.ipBlock,
			})
	}
	for _, item := range egress {
		p.Spec.EgressRules[0].To = append(p.Spec.EgressRules[0].To,
			securityv1alpha1.SecurityPolicyPeer{
				EndpointSelector: item.endpointSelector,
				IPBlock:          item.ipBlock,
			})
	}

	return p
}

func newTestEndpoint(ip []types.IPAddress, agent []string, namedPorts []securityv1alpha1.NamedPort) *securityv1alpha1.Endpoint {
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
			Ports: namedPorts,
		},
		Status: securityv1alpha1.EndpointStatus{
			IPs:    ip,
			Agents: agent,
		},
	}
}

type testGroup struct {
	*groupv1alpha1.GroupMembers
	endpointSelector *labels.Selector
	ipBlock          *networkingv1.IPBlock
}

func newTestGroupMembers(revision int32, members ...*groupv1alpha1.GroupMember) *testGroup {
	var testGroup = new(testGroup)
	var groupMembers []groupv1alpha1.GroupMember
	var namespaceDefault = metav1.NamespaceDefault

	for _, member := range members {
		groupMembers = append(groupMembers, *member)
	}

	testGroup.endpointSelector = &labels.Selector{
		ExtendMatchLabels: map[string][]string{
			rand.String(10): {rand.String(10)},
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

func newTestCompleteRule(ruleId string, srcGroup, dstGroup string, policy string) *cache.CompleteRule {
	return &cache.CompleteRule{
		RuleID:    ruleId,
		Policy:    policy,
		SrcGroups: sets.New[string](srcGroup),
		DstGroups: sets.New[string](dstGroup),
	}
}

func endpointToMember(ep *securityv1alpha1.Endpoint) *groupv1alpha1.GroupMember {
	return &groupv1alpha1.GroupMember{
		EndpointReference: groupv1alpha1.EndpointReference{
			ExternalIDName:  ep.Spec.Reference.ExternalIDName,
			ExternalIDValue: ep.Spec.Reference.ExternalIDValue,
		},
		IPs:           ep.Status.IPs,
		EndpointAgent: ep.Status.Agents,
		Ports:         ep.Spec.Ports,
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
	direction, action, srcCidr string, srcPort uint16, dstCidr string, dstPort uint16, protocol string, family uint8) {
	Eventually(func() string {
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
				family == rule.IPFamily &&
				protocol == rule.IPProtocol {
				return ""
			}
		}
		return fmt.Sprintf("%s,%s,%s,%d,%s,%d,%s,%d\n", direction, action, srcCidr, srcPort, dstCidr, dstPort, protocol, family) +
			fmt.Sprintf("%+v\n%+v\n", policy, policyRuleList)
	}, timeout, interval).Should(Equal(""))
}

func newTestPolicyRule(direction, action, srcCidr string, dstCidr string, dstPort uint16, dstPortMask uint16,
	protocol string, tier string, priority int32, family uint8) cache.PolicyRule {
	return cache.PolicyRule{
		Direction:      cache.RuleDirection(direction),
		Action:         cache.RuleAction(action),
		SrcIPAddr:      srcCidr,
		DstIPAddr:      dstCidr,
		DstPort:        dstPort,
		DstPortMask:    dstPortMask,
		IPProtocol:     protocol,
		IPFamily:       family,
		Tier:           tier,
		PriorityOffset: priority,
	}
}

func assertHasPolicyRuleWithPortRange(policy *securityv1alpha1.SecurityPolicy,
	direction, action, srcCidr string, srcPort uint16, srcPortMask uint16, dstCidr string, dstPort uint16, dstPortMask uint16, protocol string, family uint8) {
	Eventually(func() string {
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
				family == rule.IPFamily &&
				protocol == rule.IPProtocol {
				return ""
			}
		}
		return fmt.Sprintf("%s,%s,%s,%d,%d,%s,%d,%d,%s,%d\n", direction, action, srcCidr, srcPort, srcPortMask, dstCidr, dstPort, dstPortMask, protocol, family) +
			fmt.Sprintf("%+v\n%+v\n", policy, policyRuleList)
	}, timeout, interval).Should(Equal(""))
}

func assertNoPolicyRule(policy *securityv1alpha1.SecurityPolicy,
	direction, action, srcCidr string, srcPort uint16, dstCidr string, dstPort uint16, protocol string, family uint8) {

	Eventually(func() string {
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
				family == rule.IPFamily &&
				protocol == rule.IPProtocol {
				return fmt.Sprintf("%s,%s,%s,%d,%s,%d,%s,%d\n", direction, action, srcCidr, srcPort, dstCidr, dstPort, protocol, family) +
					fmt.Sprintf("%+v\n%+v\n", policy, policyRuleList)
			}
		}
		return ""
	}, timeout, interval).Should(Equal(""))
}

func getRuleByPolicy(policy *securityv1alpha1.SecurityPolicy) []cache.PolicyRule {
	var policyRuleList []cache.PolicyRule
	completeRules, _ := ruleCacheLister.ByIndex(cache.PolicyIndex, policy.Namespace+"/"+policy.Name)
	for _, completeRule := range completeRules {
		rule := completeRule.(*cache.CompleteRule)
		srcIPs, err := cache.AssembleStaticIPAndGroup(ctx, rule.SrcIPs, rule.SrcGroups, pCtrl.GetGroupCache())
		if err != nil {
			return nil
		}
		dstIPs, err := cache.AssembleStaticIPAndGroup(ctx, rule.DstIPs, rule.DstGroups, pCtrl.GetGroupCache())
		if err != nil {
			return nil
		}
		policyRuleList = append(policyRuleList, rule.GenerateRuleList(ctx, srcIPs, dstIPs, rule.Ports)...)
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
