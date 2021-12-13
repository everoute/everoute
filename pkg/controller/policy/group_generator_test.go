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
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/rand"
	"sigs.k8s.io/controller-runtime/pkg/client"

	groupv1alpha1 "github.com/everoute/everoute/pkg/apis/group/v1alpha1"
	securityv1alpha1 "github.com/everoute/everoute/pkg/apis/security/v1alpha1"
)

const (
	timeout  = time.Second * 10
	interval = time.Millisecond * 250
)

var _ = Describe("GroupGenerator", func() {
	var ctx context.Context
	var namespace string

	BeforeEach(func() {
		ctx = context.Background()
		namespaceList := corev1.NamespaceList{}
		Expect(k8sClient.List(ctx, &namespaceList)).Should(Succeed())
		// run test in rand namespace
		namespace = namespaceList.Items[rand.IntnRange(0, len(namespaceList.Items))].GetName()
	})
	AfterEach(func() {
		By("delete all SecurityPolicies")
		Expect(k8sClient.DeleteAllOf(ctx, &securityv1alpha1.SecurityPolicy{}, client.InNamespace(namespace))).Should(Succeed())
		Eventually(func() int {
			policyList := securityv1alpha1.SecurityPolicyList{}
			Expect(k8sClient.List(ctx, &policyList)).Should(Succeed())
			return len(policyList.Items)
		}, timeout, interval).Should(BeZero())

		By("delete all EndpointGroups")
		Expect(k8sClient.DeleteAllOf(ctx, &groupv1alpha1.EndpointGroup{})).Should(Succeed())
	})

	Context("create SecurityPolicy with applied to EndpointSelector", func() {
		var policy *securityv1alpha1.SecurityPolicy
		var endpointSelector *metav1.LabelSelector

		BeforeEach(func() {
			endpointSelector = newRandomSelector()
			policy = newTestPolicyWithoutRule(namespace, endpointSelector, nil)

			By(fmt.Sprintf("create SecurityPolicy %+v", policy))
			Expect(k8sClient.Create(ctx, policy)).Should(Succeed())

			By(fmt.Sprintf("wait for generated EndpointGroup for SecurityPolicy %+v", policy))
			assertEndpointGroupNum(ctx, 1)
		})
		It("should create EndpointGroup used by SecurityPolicy", func() {
			assertEndpointGroupNum(ctx, 1)
			assertHasEndpointGroup(ctx, endpointSelector, nil, &namespace, nil)
		})

		When("update SecurityPolicy applied to another EndpointSelector", func() {
			var newEndpointSelector *metav1.LabelSelector

			BeforeEach(func() {
				newEndpointSelector = newRandomSelector()
				updatePolicy := policy.DeepCopy()
				updatePolicy.Spec.AppliedTo[0] = securityv1alpha1.ApplyToPeer{
					EndpointSelector: newEndpointSelector,
				}

				By(fmt.Sprintf("update SecurityPolicy to %+v", updatePolicy))
				Expect(k8sClient.Patch(ctx, updatePolicy, client.MergeFrom(policy))).Should(Succeed())
			})
			It("should reconcile EndpointGroup used by SecurityPolicy", func() {
				assertEndpointGroupNum(ctx, 1)
				assertHasEndpointGroup(ctx, newEndpointSelector, nil, &namespace, nil)
				assertNoEndpointGroup(ctx, endpointSelector, nil, &namespace)
			})
		})

		When("update SecurityPolicy applied to an Endpoint", func() {
			var appliedEndpoint string

			BeforeEach(func() {
				appliedEndpoint = rand.String(10)
				updatePolicy := policy.DeepCopy()
				updatePolicy.Spec.AppliedTo[0] = securityv1alpha1.ApplyToPeer{
					Endpoint: &appliedEndpoint,
				}

				By(fmt.Sprintf("update SecurityPolicy to %+v", updatePolicy))
				Expect(k8sClient.Patch(ctx, updatePolicy, client.MergeFrom(policy))).Should(Succeed())
			})
			It("should update EndpointGroup", func() {
				assertEndpointGroupNum(ctx, 1)
				assertHasEndpointGroup(ctx, nil, nil, &namespace,
					&securityv1alpha1.NamespacedName{
						Namespace: namespace,
						Name:      appliedEndpoint,
					})
			})
		})

		When("add ingress with NamespaceSelector and EndpointSelector peer", func() {
			var ingress *securityv1alpha1.Rule
			var namespaceSelector, peerEndpointSelector *metav1.LabelSelector

			BeforeEach(func() {
				namespaceSelector = newRandomSelector()
				peerEndpointSelector = newRandomSelector()
				ingress = &securityv1alpha1.Rule{From: []securityv1alpha1.SecurityPolicyPeer{{
					EndpointSelector:  peerEndpointSelector,
					NamespaceSelector: namespaceSelector,
				}}}

				updatePolicy := policy.DeepCopy()
				updatePolicy.Spec.IngressRules = append(updatePolicy.Spec.IngressRules, *ingress)
				By(fmt.Sprintf("update SecurityPolicy to %+v", updatePolicy))
				Expect(k8sClient.Patch(ctx, updatePolicy, client.MergeFrom(policy))).Should(Succeed())
			})
			It("should reconcile EndpointGroup used by SecurityPolicy", func() {
				assertEndpointGroupNum(ctx, 2)
				assertHasEndpointGroup(ctx, endpointSelector, nil, &namespace, nil)
				assertHasEndpointGroup(ctx, peerEndpointSelector, namespaceSelector, nil, nil)
			})
		})

		When("add ingress with NamespaceSelector only peer", func() {
			var ingress *securityv1alpha1.Rule
			var namespaceSelector *metav1.LabelSelector

			BeforeEach(func() {
				namespaceSelector = newRandomSelector()
				ingress = &securityv1alpha1.Rule{From: []securityv1alpha1.SecurityPolicyPeer{{
					NamespaceSelector: namespaceSelector,
				}}}

				updatePolicy := policy.DeepCopy()
				updatePolicy.Spec.IngressRules = append(updatePolicy.Spec.IngressRules, *ingress)
				By(fmt.Sprintf("update SecurityPolicy to %+v", updatePolicy))
				Expect(k8sClient.Patch(ctx, updatePolicy, client.MergeFrom(policy))).Should(Succeed())
			})
			It("should reconcile EndpointGroup used by SecurityPolicy", func() {
				assertEndpointGroupNum(ctx, 2)
				assertHasEndpointGroup(ctx, endpointSelector, nil, &namespace, nil)
				assertHasEndpointGroup(ctx, new(metav1.LabelSelector), namespaceSelector, nil, nil)
			})
		})

		When("add ingress with EndpointSelector only peer", func() {
			var ingress *securityv1alpha1.Rule
			var peerEndpointSelector *metav1.LabelSelector

			BeforeEach(func() {
				peerEndpointSelector = newRandomSelector()
				ingress = &securityv1alpha1.Rule{From: []securityv1alpha1.SecurityPolicyPeer{{
					EndpointSelector: peerEndpointSelector,
				}}}

				updatePolicy := policy.DeepCopy()
				updatePolicy.Spec.IngressRules = append(updatePolicy.Spec.IngressRules, *ingress)
				By(fmt.Sprintf("update SecurityPolicy to %+v", updatePolicy))
				Expect(k8sClient.Patch(ctx, updatePolicy, client.MergeFrom(policy))).Should(Succeed())
			})
			It("should reconcile EndpointGroup used by SecurityPolicy", func() {
				assertEndpointGroupNum(ctx, 2)
				assertHasEndpointGroup(ctx, endpointSelector, nil, &namespace, nil)
				assertHasEndpointGroup(ctx, peerEndpointSelector, nil, &namespace, nil)
			})
		})

		When("delete the SecurityPolicy", func() {
			BeforeEach(func() {
				By(fmt.Sprintf("delete the SecurityPolicy %+v", policy))
				Expect(k8sClient.Delete(ctx, policy)).Should(Succeed())
			})

			It("should delete all EndpointGroups", func() {
				assertEndpointGroupNum(ctx, 0)
			})
		})
	})

	When("create SecurityPolicy with applied to endpoint", func() {
		var policy *securityv1alpha1.SecurityPolicy
		var endpoint string

		BeforeEach(func() {
			endpoint = rand.String(10)
			policy = newTestPolicyWithoutRule(namespace, nil, &endpoint)

			By(fmt.Sprintf("create SecurityPolicy %+v", policy))
			Expect(k8sClient.Create(ctx, policy)).Should(Succeed())
		})
		It("should not create any EndpointGroup", func() {
			assertEndpointGroupNum(ctx, 1)
			assertHasEndpointGroup(ctx, nil, nil, &namespace,
				&securityv1alpha1.NamespacedName{
					Namespace: namespace,
					Name:      endpoint,
				})
		})

		When("update SecurityPolicy applied to an EndpointSelector", func() {
			var endpointSelector *metav1.LabelSelector

			BeforeEach(func() {
				endpointSelector = newRandomSelector()
				updatePolicy := policy.DeepCopy()
				updatePolicy.Spec.AppliedTo[0] = securityv1alpha1.ApplyToPeer{
					EndpointSelector: endpointSelector,
				}

				By(fmt.Sprintf("update SecurityPolicy to %+v", updatePolicy))
				Expect(k8sClient.Patch(ctx, updatePolicy, client.MergeFrom(policy))).Should(Succeed())
			})
			It("should reconcile EndpointGroup used by SecurityPolicy", func() {
				assertEndpointGroupNum(ctx, 1)
				assertHasEndpointGroup(ctx, endpointSelector, nil, &namespace, nil)
			})
		})
	})

	When("create multiple SecurityPolicy with same selector", func() {
		var policy01, policy02 *securityv1alpha1.SecurityPolicy
		var endpointSelector *metav1.LabelSelector

		BeforeEach(func() {
			endpointSelector = newRandomSelector()
			policy01 = newTestPolicyWithoutRule(namespace, endpointSelector, nil)
			policy02 = newTestPolicyWithoutRule(namespace, endpointSelector, nil)

			By(fmt.Sprintf("create SecurityPolicy %+v and %+v", policy01, policy02))
			Expect(k8sClient.Create(ctx, policy01)).Should(Succeed())
			Expect(k8sClient.Create(ctx, policy02)).Should(Succeed())
		})
		It("should create EndpointGroup used by SecurityPolicy", func() {
			assertEndpointGroupNum(ctx, 1)
			assertHasEndpointGroup(ctx, endpointSelector, nil, &namespace, nil)
		})

		When("delete one of the SecurityPolicy", func() {
			BeforeEach(func() {
				By(fmt.Sprintf("delete SecurityPolicy %+v", policy01))
				Expect(k8sClient.Delete(ctx, policy01)).Should(Succeed())
			})
			It("EndpointGroup used by SecurityPolicy should not delete", func() {
				assertEndpointGroupNum(ctx, 1)
				assertHasEndpointGroup(ctx, endpointSelector, nil, &namespace, nil)
			})
		})

		When("delete all of SecurityPolicies", func() {
			BeforeEach(func() {
				By(fmt.Sprintf("delete SecurityPolicy %+vand %+v", policy01, policy02))
				Expect(k8sClient.Delete(ctx, policy01)).Should(Succeed())
				Expect(k8sClient.Delete(ctx, policy02)).Should(Succeed())
			})
			It("EndpointGroup not used should delete", func() {
				assertEndpointGroupNum(ctx, 0)
			})
		})
	})
})

func newTestPolicyWithoutRule(namespace string, endpointSelector *metav1.LabelSelector, endpoint *string) *securityv1alpha1.SecurityPolicy {
	policy := new(securityv1alpha1.SecurityPolicy)
	policy.Name = rand.String(10)
	policy.Namespace = namespace

	if endpointSelector != nil {
		policy.Spec.AppliedTo = append(policy.Spec.AppliedTo, securityv1alpha1.ApplyToPeer{
			EndpointSelector: endpointSelector,
		})
	}

	if endpoint != nil {
		policy.Spec.AppliedTo = append(policy.Spec.AppliedTo, securityv1alpha1.ApplyToPeer{
			Endpoint: endpoint,
		})
	}

	return policy
}

func newRandomSelector() *metav1.LabelSelector {
	return &metav1.LabelSelector{
		MatchLabels: map[string]string{rand.String(10): rand.String(10)},
	}
}

func assertHasEndpointGroup(ctx context.Context, endpointSelector, namespaceSelector *metav1.LabelSelector,
	namespace *string, endpoint *securityv1alpha1.NamespacedName) {
	Eventually(func() bool {
		groupList := groupv1alpha1.EndpointGroupList{}
		Expect(k8sClient.List(ctx, &groupList)).Should(Succeed())

		for _, group := range groupList.Items {
			if reflect.DeepEqual(group.Spec, groupv1alpha1.EndpointGroupSpec{
				EndpointSelector:  endpointSelector,
				NamespaceSelector: namespaceSelector,
				Namespace:         namespace,
				Endpoint:          endpoint,
			}) {
				return true
			}
		}
		return false
	}, timeout, interval).Should(BeTrue())
}

func assertNoEndpointGroup(ctx context.Context, endpointSelector, namespaceSelector *metav1.LabelSelector, namespace *string) {
	Eventually(func() bool {
		groupList := groupv1alpha1.EndpointGroupList{}
		Expect(k8sClient.List(ctx, &groupList)).Should(Succeed())

		for _, group := range groupList.Items {
			if reflect.DeepEqual(group.Spec, groupv1alpha1.EndpointGroupSpec{
				EndpointSelector:  endpointSelector,
				NamespaceSelector: namespaceSelector,
				Namespace:         namespace,
			}) {
				return true
			}
		}
		return false
	}, timeout, interval).Should(BeFalse())
}

func assertEndpointGroupNum(ctx context.Context, numOfEndpointGroups int) {
	Eventually(func() int {
		groupList := groupv1alpha1.EndpointGroupList{}
		Expect(k8sClient.List(ctx, &groupList)).Should(Succeed())
		return len(groupList.Items)
	}, timeout, interval).Should(Equal(numOfEndpointGroups))
}
