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

package k8s

import (
	"context"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	securityv1alpha1 "github.com/everoute/everoute/pkg/apis/security/v1alpha1"
)

var _ = Describe("pod controller", func() {
	var ctx context.Context

	BeforeEach(func() {
		ctx = context.Background()
	})

	Context("Test network policy sync to security policy", func() {
		protoTCP := corev1.ProtocolTCP
		port80 := intstr.FromInt(80)
		// port8000 := intstr.FromInt(80)
		networkPolicy := &networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "network-policy",
				Namespace: "default",
			},
			Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{
					MatchLabels: map[string]string{"label": "value"},
				},
				Ingress: []networkingv1.NetworkPolicyIngressRule{
					{
						Ports: []networkingv1.NetworkPolicyPort{
							{
								Protocol: &protoTCP,
								Port:     &port80,
								// EndPort:  &port8000.IntVal,
							},
						},
						From: []networkingv1.NetworkPolicyPeer{
							{
								PodSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"key": "value"}},
							},
						},
					},
				},
				Egress: []networkingv1.NetworkPolicyEgressRule{
					{
						Ports: []networkingv1.NetworkPolicyPort{
							{
								Protocol: &protoTCP,
								Port:     &port80,
							},
						},
						To: []networkingv1.NetworkPolicyPeer{
							{
								PodSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"key": "value"}},
							},
						},
					},
				},
				PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
			},
		}
		networkPolicyReq := types.NamespacedName{
			Name:      "network-policy",
			Namespace: "default",
		}
		securityPolicyReq := types.NamespacedName{
			Name:      "np-network-policy",
			Namespace: "default",
		}
		securityPolicy := securityv1alpha1.SecurityPolicy{}
		BeforeEach(func() {
			Expect(k8sClient.Create(ctx, networkPolicy.DeepCopy())).Should(Succeed())
		})

		AfterEach(func() {
			// delete test network policy
			Eventually(func() int {
				networkPolicyList := networkingv1.NetworkPolicyList{}
				Expect(k8sClient.List(ctx, &networkPolicyList, client.MatchingLabels{TestLabelKey: TestLabelValue})).Should(Succeed())
				for index := range networkPolicyList.Items {
					Expect(k8sClient.Delete(ctx, &networkPolicyList.Items[index])).Should(Succeed())
				}
				Expect(k8sClient.List(ctx, &networkPolicyList, client.MatchingLabels{TestLabelKey: TestLabelValue})).Should(Succeed())
				return len(networkPolicyList.Items)
			}, time.Minute, interval).Should(BeZero())
		})

		It("should create and delete an endpoint", func() {
			Eventually(func() int {
				securityPolicyList := securityv1alpha1.SecurityPolicyList{}
				Expect(k8sClient.List(ctx, &securityPolicyList)).Should(Succeed())
				return len(securityPolicyList.Items)
			}, time.Minute, interval).Should(Equal(1))

			Expect(k8sClient.Get(ctx, securityPolicyReq, &securityPolicy)).Should(Succeed())

			Expect(len(securityPolicy.Spec.PolicyTypes)).Should(Equal(1))
			Expect(securityPolicy.Spec.Tier).Should(Equal("tier1"))
			Expect(securityPolicy.Spec.SymmetricMode).Should(BeFalse())
			Expect(len(securityPolicy.Spec.IngressRules)).Should(Equal(1))

			Expect(k8sClient.Delete(ctx, networkPolicy)).Should(Succeed())
			Eventually(func() int {
				securityPolicyList := securityv1alpha1.SecurityPolicyList{}
				Expect(k8sClient.List(ctx, &securityPolicyList)).Should(Succeed())
				return len(securityPolicyList.Items)
			}, timeout, interval).Should(BeZero())
		})

		It("should update an endpoint", func() {
			Eventually(func() int {
				securityPolicyList := securityv1alpha1.SecurityPolicyList{}
				Expect(k8sClient.List(ctx, &securityPolicyList)).Should(Succeed())
				return len(securityPolicyList.Items)
			}, time.Minute, interval).Should(Equal(1))
			Expect(k8sClient.Get(ctx, networkPolicyReq, networkPolicy)).Should(Succeed())

			networkPolicy.Spec.PolicyTypes = append(networkPolicy.Spec.PolicyTypes, networkingv1.PolicyTypeEgress)
			Expect(k8sClient.Update(ctx, networkPolicy)).Should(Succeed())

			Eventually(func() int {
				Expect(k8sClient.Get(ctx, securityPolicyReq, &securityPolicy)).Should(Succeed())
				return len(securityPolicy.Spec.PolicyTypes)
			}, timeout, interval).Should(Equal(2))

			Expect(k8sClient.Delete(ctx, &securityPolicy)).Should(Succeed())
		})
	})
})
