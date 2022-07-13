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

package activeprobe_test

import (
	"context"
	"fmt"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/uuid"
	"sigs.k8s.io/controller-runtime/pkg/client"

	activeprobev1alpha1 "github.com/everoute/everoute/pkg/apis/activeprobe/v1alpha1"
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

var _ = Describe("ActiveProbeController", func() {
	var ctx context.Context
	var namespace = metav1.NamespaceDefault

	BeforeEach(func() {
		ctx = context.Background()
	})

	AfterEach(func() {
		namespaceDefault := client.InNamespace(metav1.NamespaceDefault)
		By("delete all test activeprobes")
		Expect(k8sClient.DeleteAllOf(ctx, &activeprobev1alpha1.ActiveProbe{}, namespaceDefault, client.MatchingLabels{TestLabelKey: TestLabelValue})).Should(Succeed())
		Eventually(func() int {
			apList := activeprobev1alpha1.ActiveProbeList{}
			Expect(k8sClient.List(ctx, &apList)).Should(Succeed())
			return len(apList.Items)
		}, time.Minute, interval).Should(BeZero())
	})

	Context("One activeprobe has been created", func() {
		var ap *activeprobev1alpha1.ActiveProbe
		BeforeEach(func() {
			ap = newTestActiveProbe(namespace, map[string]string{"label.key": "label.value"})
			By(fmt.Sprintf("create activeprobe %s with labels %v", ap.Name, ap.Labels))
			Expect(k8sClient.Create(ctx, ap)).Should(Succeed())
			Expect(k8sClient.Status().Update(ctx, ap)).Should(Succeed())
		})

		It("activeprobe agent controller update status infos", func() {
			// wait for controller handle activeprobe event
			time.Sleep(10 * time.Second)
			By(fmt.Sprintf("activeprobe %s should has updated state", ap.Name))
			assertHasUpdatedState(ap, activeprobev1alpha1.ActiveProbeSendFinshed)
		})
	})

})

func newTestActiveProbe(namespace string, labels map[string]string) *activeprobev1alpha1.ActiveProbe {
	name := "activeprbe-test" + string(uuid.NewUUID())
	labels[TestLabelKey] = TestLabelValue
	curAgentName := utils.CurrentAgentName()
	return &activeprobev1alpha1.ActiveProbe{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels:    labels,
		},
		Spec: activeprobev1alpha1.ActiveProbeSpec{
			Source: activeprobev1alpha1.Source{
				IP:         "10.0.1.11",
				MAC:        "00:aa:aa:aa:aa:aa",
				AgentName:  curAgentName,
				BridgeName: brName,
				Ofport:     1,
			},
			Destination: activeprobev1alpha1.Destination{
				IP:         "10.0.1.12",
				MAC:        "00:aa:aa:aa:aa:ab",
				AgentName:  curAgentName,
				BridgeName: brName,
				Ofport:     1,
			},
			Packet: activeprobev1alpha1.Packet{
				IPHeader: activeprobev1alpha1.IPHeader{
					Protocol: 6,
					TTL:      64,
				},
				TransportHeader: activeprobev1alpha1.TransportHeader{
					TCP: &activeprobev1alpha1.TCPHeader{
						SrcPort: 8080,
						DstPort: 80,
						Flags:   2,
					},
				},
			},
			ProbeTimes: 10,
		},
		Status: activeprobev1alpha1.ActiveProbeStatus{
			State: activeprobev1alpha1.ActiveProbeRunning,
			Tag:   7,
		},
	}
}

func assertHasUpdatedState(ap *activeprobev1alpha1.ActiveProbe, matchInfo activeprobev1alpha1.ActiveProbeState) {
	matcher := Equal(matchInfo)

	Eventually(func() activeprobev1alpha1.ActiveProbeState {
		curAp := activeprobev1alpha1.ActiveProbe{}

		err := k8sClient.Get(context.Background(), client.ObjectKey{Name: ap.Name}, &curAp)
		Expect(client.IgnoreNotFound(err)).Should(Succeed())

		return curAp.Status.State
	}, timeout, interval).Should(matcher)
}
