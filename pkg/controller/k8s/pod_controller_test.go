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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	securityv1alpha1 "github.com/everoute/everoute/pkg/apis/security/v1alpha1"
	"github.com/everoute/everoute/pkg/utils"
)

const (
	timeout  = time.Second * 10
	interval = time.Millisecond * 250

	// TestLabelKey is the label key test objects contains. All objects generated
	// in the unit test must contain this label, all objects contains test labels
	// should be cleaned up after the test.
	TestLabelKey = "everoute.unit.test.object"
	// TestLabelValue is the label TestLabelValue test objects contains.
	TestLabelValue = "must.clean.after.test"
)

var _ = Describe("pod controller", func() {
	var ctx context.Context

	BeforeEach(func() {
		ctx = context.Background()
	})

	Context("Test add pod", func() {
		pod := &corev1.Pod{
			TypeMeta: metav1.TypeMeta{
				Kind:       "Pod",
				APIVersion: "v1",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:      "pod1",
				Namespace: "default",
				Labels: map[string]string{
					TestLabelKey: TestLabelValue,
					"label1":     "value1",
				},
			},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{
					{
						Name:  "write-pod",
						Image: "alpine",
					},
				},
			},
		}
		podReq := types.NamespacedName{
			Name:      "pod1",
			Namespace: "default",
		}
		endpointName := "pod-" + pod.Name
		endpoint := securityv1alpha1.Endpoint{}
		endpointReq := types.NamespacedName{
			Name:      endpointName,
			Namespace: pod.Namespace,
		}
		externalIDValue := utils.EncodeNamespacedName(types.NamespacedName{
			Name:      endpointName,
			Namespace: pod.Namespace,
		})

		BeforeEach(func() {
			Expect(k8sClient.Create(ctx, pod.DeepCopy())).Should(Succeed())
		})
		AfterEach(func() {
			// delete test pod
			Eventually(func() int {
				podList := corev1.PodList{}
				Expect(k8sClient.List(ctx, &podList, client.MatchingLabels{TestLabelKey: TestLabelValue})).Should(Succeed())
				for index := range podList.Items {
					Expect(k8sClient.Delete(ctx, &podList.Items[index])).Should(Succeed())
				}
				Expect(k8sClient.List(ctx, &podList, client.MatchingLabels{TestLabelKey: TestLabelValue})).Should(Succeed())
				return len(podList.Items)
			}, time.Minute, interval).Should(BeZero())

			Eventually(func() int {
				endpointList := securityv1alpha1.EndpointList{}
				Expect(k8sClient.List(ctx, &endpointList)).Should(Succeed())
				return len(endpointList.Items)
			}, time.Minute, interval).Should(BeZero())
		})

		It("should create and delete an endpoint", func() {
			Eventually(func() int {
				endpointList := securityv1alpha1.EndpointList{}
				Expect(k8sClient.List(ctx, &endpointList)).Should(Succeed())
				return len(endpointList.Items)
			}, time.Minute, interval).Should(Equal(1))

			endpointGet := securityv1alpha1.Endpoint{}
			Expect(k8sClient.Get(ctx, endpointReq, &endpointGet)).Should(Succeed())
			Expect(endpointGet.Spec.Reference.ExternalIDName).Should(Equal("pod-uuid"))
			Expect(endpointGet.Spec.Reference.ExternalIDValue).Should(Equal(externalIDValue))
			Expect(len(endpointGet.ObjectMeta.Labels)).Should(Equal(2))
			Expect(endpointGet.ObjectMeta.Labels["label1"]).Should(Equal("value1"))

			Expect(k8sClient.Delete(ctx, pod)).Should(Succeed())

			Eventually(func() int {
				endpointList := securityv1alpha1.EndpointList{}
				Expect(k8sClient.List(ctx, &endpointList)).Should(Succeed())
				return len(endpointList.Items)
			}, timeout, interval).Should(BeZero())
		})

		It("should update an endpoint - add a new label", func() {
			Eventually(func() int {
				endpointList := securityv1alpha1.EndpointList{}
				Expect(k8sClient.List(ctx, &endpointList)).Should(Succeed())
				return len(endpointList.Items)
			}, time.Minute, interval).Should(Equal(1))

			podGet := &corev1.Pod{}
			Expect(k8sClient.Get(ctx, podReq, podGet)).Should(Succeed())
			podGet.ObjectMeta.Labels["label2"] = "value2"
			Expect(k8sClient.Update(ctx, podGet)).Should(Succeed())

			Eventually(func() int {
				Expect(k8sClient.Get(ctx, endpointReq, &endpoint)).Should(Succeed())
				return len(endpoint.ObjectMeta.Labels)
			}, timeout, interval).Should(Equal(3))

		})

		It("should update an endpoint - remove a label", func() {
			Eventually(func() int {
				endpointList := securityv1alpha1.EndpointList{}
				Expect(k8sClient.List(ctx, &endpointList)).Should(Succeed())
				return len(endpointList.Items)
			}, time.Minute, interval).Should(Equal(1))

			podGet := &corev1.Pod{}
			Expect(k8sClient.Get(ctx, podReq, podGet)).Should(Succeed())
			delete(podGet.ObjectMeta.Labels, "label1")
			Expect(k8sClient.Update(ctx, podGet)).Should(Succeed())

			Eventually(func() int {
				Expect(k8sClient.Get(ctx, endpointReq, &endpoint)).Should(Succeed())
				return len(endpoint.ObjectMeta.Labels)
			}, timeout, interval).Should(Equal(1))

		})
	})
})
