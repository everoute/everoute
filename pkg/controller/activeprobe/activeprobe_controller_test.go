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
	securityv1alpha1 "github.com/everoute/everoute/pkg/apis/security/v1alpha1"
	"github.com/everoute/everoute/pkg/types"
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

type AddedInfo struct {
	tag           uint8
	srcIP         string
	srcMAC        string
	srcAgentName  string
	srcBridgeName string
	srcOfport     int32
	dstIP         string
	dstMAC        string
	dstAgentName  string
	dstBridgeName string
	dstOfport     int32
}

var _ = Describe("ActiveProbeController", func() {
	var ctx context.Context
	var srcEp, dstEp *securityv1alpha1.Endpoint
	var namespace = metav1.NamespaceDefault
	var addInfo AddedInfo

	BeforeEach(func() {
		ctx = context.Background()

		srcEp = newTestEndpoint(namespace, map[string]string{"label.key": "label.value"}, "192.168.1.1", "agent1", "aa:aa:aa:aa:aa:aa", "ovsbr-mgt", 1)
		By(fmt.Sprintf("create src endpoint %s with labels %v", srcEp.Name, srcEp.Labels))
		Expect(k8sClient.Create(ctx, srcEp)).Should(Succeed())
		Expect(k8sClient.Status().Update(ctx, srcEp)).Should(Succeed())

		dstEp = newTestEndpoint(namespace, map[string]string{"label.key": "label.value"}, "192.168.2.2", "agent2", "bb:bb:bb:bb:bb:bb", "ovsbr-mgt", 1)
		By(fmt.Sprintf("create dst endpoint %s with labels %v", dstEp.Name, dstEp.Labels))
		Expect(k8sClient.Create(ctx, dstEp)).Should(Succeed())
		Expect(k8sClient.Status().Update(ctx, dstEp)).Should(Succeed())

		addInfo = constructAddedInfo(nil)
	})

	AfterEach(func() {
		namespaceDefault := client.InNamespace(metav1.NamespaceDefault)
		By("delete all test endpoints")
		Expect(k8sClient.DeleteAllOf(ctx, &securityv1alpha1.Endpoint{}, namespaceDefault, client.MatchingLabels{TestLabelKey: TestLabelValue})).Should(Succeed())
		Eventually(func() int {
			epList := securityv1alpha1.EndpointList{}
			Expect(k8sClient.List(ctx, &epList)).Should(Succeed())
			return len(epList.Items)
		}, time.Minute, interval).Should(BeZero())
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
			srcEndpoint := srcEp.Spec.Reference.ExternalIDValue
			dstEndpoint := dstEp.Spec.Reference.ExternalIDValue
			ap = newTestActiveProbe(namespace, map[string]string{"label.key": "label.value"}, srcEndpoint, dstEndpoint)
			By(fmt.Sprintf("create activeprobe %s with labels %v", ap.Name, ap.Labels))
			Expect(k8sClient.Create(ctx, ap)).Should(Succeed())
		})

		It("activeprobe central controller construct src/dst infos", func() {
			// wait for controller handle activeprobe event
			time.Sleep(5 * time.Second)
			By(fmt.Sprintf("activeprobe %s should has constructed infos", ap.Name))
			assertHasAddedInfo(ap, addInfo)
		})
	})

})

func newTestEndpoint(namespace string, labels map[string]string, ip types.IPAddress, agent string, macAddr string,
	bridgeName string, ofport int32) *securityv1alpha1.Endpoint {
	name := "endpoint-test-" + string(uuid.NewUUID())
	id := name
	labels[TestLabelKey] = TestLabelValue

	return &securityv1alpha1.Endpoint{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels:    labels,
		},
		Spec: securityv1alpha1.EndpointSpec{
			Reference: securityv1alpha1.EndpointReference{
				ExternalIDName:  "iface-id",
				ExternalIDValue: id,
			},
		},
		Status: securityv1alpha1.EndpointStatus{
			IPs:        []types.IPAddress{ip},
			MacAddress: macAddr,
			Agents:     []string{agent},
			BridgeName: bridgeName,
			Ofport:     ofport,
		},
	}
}

func newTestActiveProbe(namespace string, labels map[string]string, srcEndpointVal string, dstEndpointVal string) *activeprobev1alpha1.ActiveProbe {
	name := "activeprbe-test" + string(uuid.NewUUID())
	labels[TestLabelKey] = TestLabelValue
	return &activeprobev1alpha1.ActiveProbe{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels:    labels,
		},
		Spec: activeprobev1alpha1.ActiveProbeSpec{
			Source: activeprobev1alpha1.Source{
				Endpoint: srcEndpointVal,
			},
			Destination: activeprobev1alpha1.Destination{
				Endpoint: dstEndpointVal,
			},
		},
	}
}

func assertHasAddedInfo(ap *activeprobev1alpha1.ActiveProbe, matchInfo AddedInfo) {
	matcher := Equal(matchInfo)

	Eventually(func() AddedInfo {
		curAp := activeprobev1alpha1.ActiveProbe{}

		err := k8sClient.Get(context.Background(), client.ObjectKey{Name: ap.Name}, &curAp)
		Expect(client.IgnoreNotFound(err)).Should(Succeed())

		return constructAddedInfo(&curAp)
	}, timeout, interval).Should(matcher)
}

func constructAddedInfo(ap *activeprobev1alpha1.ActiveProbe) AddedInfo {
	if ap == nil {
		return AddedInfo{
			tag:           7,
			srcIP:         "192.168.1.1",
			srcMAC:        "aa:aa:aa:aa:aa:aa",
			srcAgentName:  "agent1",
			srcBridgeName: "ovsbr-mgt",
			srcOfport:     1,
			dstIP:         "192.168.2.2",
			dstMAC:        "bb:bb:bb:bb:bb:bb",
			dstAgentName:  "agent2",
			dstBridgeName: "ovsbr-mgt",
			dstOfport:     1,
		}
	}
	return AddedInfo{
		tag:           ap.Status.Tag,
		srcIP:         ap.Spec.Source.IP,
		srcMAC:        ap.Spec.Source.MAC,
		srcAgentName:  ap.Spec.Source.AgentName,
		srcBridgeName: ap.Spec.Source.BridgeName,
		srcOfport:     ap.Spec.Source.Ofport,
		dstIP:         ap.Spec.Destination.IP,
		dstMAC:        ap.Spec.Destination.MAC,
		dstAgentName:  ap.Spec.Destination.AgentName,
		dstBridgeName: ap.Spec.Destination.BridgeName,
		dstOfport:     ap.Spec.Destination.Ofport,
	}
}
