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

	securityv1alpha1 "github.com/smartxworks/lynx/pkg/apis/security/v1alpha1"
	"github.com/smartxworks/lynx/pkg/utils"
)

const (
	timeout  = time.Second * 10
	interval = time.Millisecond * 250

	// TestLabelKey is the label key test objects contains. All objects generated
	// in the unit test must contain this label, all objects contains test labels
	// should be cleaned up after the test.
	TestLabelKey = "lynx.unit.test.object"
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
				GenerateName: "pod1",
				Name:         "pod1",
				Namespace:    "default",
				Labels: map[string]string{
					"label1": "value1",
					"label2": "value2",
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
			Expect(k8sClient.Create(ctx, pod)).Should(Succeed())
			Eventually(func() int {
				podList := corev1.PodList{}
				Expect(k8sClient.List(ctx, &podList)).Should(Succeed())
				return len(podList.Items)
			}, time.Minute, interval).Should(Equal(1))
		})

		It("should create and delete an endpoint", func() {
			Eventually(func() int {
				endpointList := securityv1alpha1.EndpointList{}
				Expect(k8sClient.List(ctx, &endpointList)).Should(Succeed())
				return len(endpointList.Items)
			}, time.Minute, interval).Should(Equal(1))

			Expect(k8sClient.Get(ctx, endpointReq, &endpoint)).Should(Succeed())
			Expect(endpoint.Spec.Reference.ExternalIDName).Should(Equal("pod-uuid"))
			Expect(endpoint.Spec.Reference.ExternalIDValue).Should(Equal(externalIDValue))
			Expect(len(endpoint.ObjectMeta.Labels)).Should(Equal(2))
			Expect(endpoint.ObjectMeta.Labels["label1"]).Should(Equal("value1"))
			Expect(endpoint.ObjectMeta.Labels["label2"]).Should(Equal("value2"))

			podList := corev1.PodList{}
			Expect(k8sClient.Delete(ctx, pod)).Should(Succeed())
			Eventually(func() int {
				Expect(k8sClient.List(ctx, &podList, client.MatchingLabels{TestLabelKey: TestLabelValue})).Should(Succeed())
				return len(podList.Items)
			}, time.Minute, interval).Should(BeZero())

			Eventually(func() int {
				endpointList := securityv1alpha1.EndpointList{}
				Expect(k8sClient.List(ctx, &endpointList)).Should(Succeed())
				return len(endpointList.Items)
			}, timeout, interval).Should(BeZero())
		})
	})
})
