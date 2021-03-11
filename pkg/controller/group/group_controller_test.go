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

package group_test

import (
	"context"
	"fmt"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/matchers"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/uuid"
	"sigs.k8s.io/controller-runtime/pkg/client"

	groupv1alpha1 "github.com/smartxworks/lynx/pkg/apis/group/v1alpha1"
	securityv1alpha1 "github.com/smartxworks/lynx/pkg/apis/security/v1alpha1"
	lynxctrl "github.com/smartxworks/lynx/pkg/controller"
	"github.com/smartxworks/lynx/pkg/types"
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

var _ = Describe("GroupController", func() {
	var ctx context.Context

	BeforeEach(func() {
		ctx = context.Background()
	})

	AfterEach(func() {
		By("delete all test endpoints")
		Expect(k8sClient.DeleteAllOf(ctx, &securityv1alpha1.Endpoint{}, client.MatchingLabels{TestLabelKey: TestLabelValue})).Should(Succeed())
		Eventually(func() int {
			epList := securityv1alpha1.EndpointList{}
			Expect(k8sClient.List(ctx, &epList)).Should(Succeed())
			return len(epList.Items)
		}, time.Minute, interval).Should(BeZero())

		By("delete all test endpointgroups")
		Expect(k8sClient.DeleteAllOf(ctx, &groupv1alpha1.EndpointGroup{}, client.MatchingLabels{TestLabelKey: TestLabelValue})).Should(Succeed())
		Eventually(func() int {
			groupList := groupv1alpha1.EndpointGroupList{}
			Expect(k8sClient.List(ctx, &groupList)).Should(Succeed())
			return len(groupList.Items)
		}, time.Minute, interval).Should(BeZero())
	})

	Context("an endpointgroup has been created", func() {
		var epGroup *groupv1alpha1.EndpointGroup
		BeforeEach(func() {
			epGroup = newTestEndpointGroup(map[string]string{"label.key": "label.value"})

			By(fmt.Sprintf("create endpointgroup %s with selector %v", epGroup.Name, epGroup.Spec.Selector))
			Expect(k8sClient.Create(ctx, epGroup)).Should(Succeed())
		})
		Context("none endpoint in the group", func() {
			When("create a endpoint in the group", func() {
				var ep *securityv1alpha1.Endpoint
				BeforeEach(func() {
					ep = newTestEndpoint(map[string]string{"label.key": "label.value"}, "192.168.1.1")

					By(fmt.Sprintf("create endpoint %s with labels %v", ep.Name, ep.Labels))
					Expect(k8sClient.Create(ctx, ep)).Should(Succeed())
					Expect(k8sClient.Status().Update(ctx, ep)).Should(Succeed())
				})
				It("should create patch add the endpoint", func() {
					assertHasPatch(epGroup, groupv1alpha1.GroupMembersPatch{AddedGroupMembers: []groupv1alpha1.GroupMember{endpointToGroupMember(ep)}})
				})
				It("should update groupmembers contains the endpoint", func() {
					assertHasGroupMembers(epGroup, groupv1alpha1.GroupMembers{GroupMembers: []groupv1alpha1.GroupMember{endpointToGroupMember(ep)}})
				})
			})
		})
		Context("an endpoint in the group", func() {
			var ep *securityv1alpha1.Endpoint
			BeforeEach(func() {
				ep = newTestEndpoint(map[string]string{"label.key": "label.value"}, "192.168.1.1")

				By(fmt.Sprintf("create endpoint %s with labels %v", ep.Name, ep.Labels))
				Expect(k8sClient.Create(ctx, ep)).Should(Succeed())
				Expect(k8sClient.Status().Update(ctx, ep)).Should(Succeed())

				By(fmt.Sprintf("wait endpoint %s in endpointgroup %s", ep.Name, epGroup.Name))
				assertHasGroupMembers(epGroup, groupv1alpha1.GroupMembers{GroupMembers: []groupv1alpha1.GroupMember{endpointToGroupMember(ep)}})
			})
			When("update the endpoint IPs", func() {
				BeforeEach(func() {
					ep.Status.IPs = append(ep.Status.IPs, "192.168.2.1")

					By(fmt.Sprintf("update endpoint %s ips to %v", ep.Name, ep.Status.IPs))
					Expect(k8sClient.Status().Update(ctx, ep)).Should(Succeed())
				})
				It("should create patch update the endpoint", func() {
					assertHasPatch(epGroup, groupv1alpha1.GroupMembersPatch{UpdatedGroupMembers: []groupv1alpha1.GroupMember{endpointToGroupMember(ep)}})
				})
				It("should update groupmembers contains the endpoint", func() {
					assertHasGroupMembers(epGroup, groupv1alpha1.GroupMembers{GroupMembers: []groupv1alpha1.GroupMember{endpointToGroupMember(ep)}})
				})
			})

			When("update the endpoint labels unmatch the group selector", func() {
				BeforeEach(func() {
					ep.Labels["label.key"] = "no.such.label.value"

					By(fmt.Sprintf("update endpoint %s labels to %v", ep.Name, ep.Labels))
					Expect(k8sClient.Update(ctx, ep)).Should(Succeed())
				})
				It("should create patch remove the endpoint", func() {
					assertHasPatch(epGroup, groupv1alpha1.GroupMembersPatch{RemovedGroupMembers: []groupv1alpha1.GroupMember{endpointToGroupMember(ep)}})
				})
				It("should update groupmembers not contains the endpoint", func() {
					assertHasGroupMembers(epGroup, groupv1alpha1.GroupMembers{GroupMembers: []groupv1alpha1.GroupMember{}})
				})
			})

			When("delete the endpoint", func() {
				BeforeEach(func() {
					By(fmt.Sprintf("delete endpoint %s", ep.Name))
					Expect(k8sClient.Delete(ctx, ep)).Should(Succeed())
				})
				It("should create patch remove the endpoint", func() {
					assertHasPatch(epGroup, groupv1alpha1.GroupMembersPatch{RemovedGroupMembers: []groupv1alpha1.GroupMember{endpointToGroupMember(ep)}})
				})
				It("should update groupmembers not contains the endpoint", func() {
					assertHasGroupMembers(epGroup, groupv1alpha1.GroupMembers{GroupMembers: []groupv1alpha1.GroupMember{}})
				})
			})

			When("update the endpointgroup selector to empty", func() {
				BeforeEach(func() {
					// the group has been modify by controller, retrieve it.
					Expect(k8sClient.Get(ctx, client.ObjectKey{Name: epGroup.Name}, epGroup))
					epGroup.Spec.Selector = nil

					By(fmt.Sprintf("change endpointgroup %s selector to %v", epGroup.Name, epGroup.Spec.Selector))
					Expect(k8sClient.Update(ctx, epGroup)).Should(Succeed())
				})
				It("should create patch remove the endpoint", func() {
					assertHasPatch(epGroup, groupv1alpha1.GroupMembersPatch{RemovedGroupMembers: []groupv1alpha1.GroupMember{endpointToGroupMember(ep)}})
				})
				It("should update groupmembers not contains the endpoint", func() {
					assertHasGroupMembers(epGroup, groupv1alpha1.GroupMembers{GroupMembers: []groupv1alpha1.GroupMember{}})
				})
			})

			When("delete the endpointgroup", func() {
				BeforeEach(func() {
					By(fmt.Sprintf("delete endpointgroup %s ", epGroup.Name))
					Expect(k8sClient.Delete(ctx, epGroup)).Should(Succeed())
				})
				It("should clean depends groupmembers for the endpointgroup", func() {
					Eventually(func() bool {
						err := k8sClient.Get(ctx, client.ObjectKey{Name: epGroup.Name}, &groupv1alpha1.GroupMembers{})
						return apierrors.IsNotFound(err)
					}, timeout, interval).Should(BeTrue())
				})
				It("should clean depends patches for the endpointgroup", func() {
					Eventually(func() int {
						patchList := groupv1alpha1.GroupMembersPatchList{}
						Expect(k8sClient.List(ctx, &patchList, client.MatchingLabels{lynxctrl.OwnerGroupLabel: epGroup.Name})).Should(Succeed())
						return len(patchList.Items)
					}, timeout, interval).Should(Equal(0))
				})
			})
		})
		Context("has more than 10 patches for the group", func() {
			BeforeEach(func() {
				var members = groupv1alpha1.GroupMembers{}

				By("get groupmembers of the group")
				Eventually(func() error {
					return k8sClient.Get(ctx, client.ObjectKey{Name: epGroup.Name}, &members)
				}, timeout, interval).Should(Succeed())

				By("update groupmembers to a high revision")
				members.Revision = 100
				Expect(k8sClient.Update(ctx, &members)).Should(Succeed())

				By("create 10 patches for the group")
				for i := 1; i <= 10; i++ {
					patch := newTestPatch(members.Name, members.Revision-int32(i))
					Expect(k8sClient.Create(ctx, patch)).Should(Succeed())
				}

				By("update the group label to drive reconcile group")
				Expect(k8sClient.Get(ctx, client.ObjectKey{Name: epGroup.Name}, epGroup))
				epGroup.Spec.Selector = nil
				Expect(k8sClient.Update(ctx, epGroup)).Should(Succeed())
			})
			It("should clean up old patches", func() {
				Eventually(func() int {
					patches := groupv1alpha1.GroupMembersPatchList{}
					Expect(k8sClient.List(ctx, &patches, client.MatchingLabels{lynxctrl.OwnerGroupLabel: epGroup.Name})).Should(Succeed())
					return len(patches.Items)
				}, timeout, interval).Should(Equal(lynxctrl.NumOfRetainedGroupMembersPatches))
			})
		})
	})

	Context("none endpointgroup has been created", func() {
		When("create an endpointgroup", func() {
			var epGroup *groupv1alpha1.EndpointGroup

			BeforeEach(func() {
				epGroup = newTestEndpointGroup(map[string]string{})

				By(fmt.Sprintf("create endpointgroup %s with selector %v", epGroup.Name, epGroup.Spec.Selector))
				Expect(k8sClient.Create(ctx, epGroup)).Should(Succeed())
			})

			It("should add finalizer for the endpointgroup", func() {
				Eventually(func() []string {
					err := k8sClient.Get(ctx, client.ObjectKey{Name: epGroup.Name}, epGroup)
					Expect(client.IgnoreNotFound(err)).Should(Succeed())
					return epGroup.Finalizers
				}, timeout, interval).Should(Equal([]string{lynxctrl.DependentsCleanFinalizer}))
			})

			It("should create groupmembers with empty members", func() {
				assertHasGroupMembers(epGroup, groupv1alpha1.GroupMembers{GroupMembers: []groupv1alpha1.GroupMember{}})
			})
		})
	})
})

// endpointToGroupMember conversion endpoint to GroupMember.
func endpointToGroupMember(ep *securityv1alpha1.Endpoint) groupv1alpha1.GroupMember {
	return groupv1alpha1.GroupMember{
		EndpointReference: groupv1alpha1.EndpointReference{
			ExternalIDName:  ep.Spec.ExternalIDName,
			ExternalIDValue: ep.Spec.ExternalIDValue,
		},
		IPs: ep.Status.IPs,
	}
}

// getLatestPatch return the latest revision of patch
func getLatestPatch(patchList groupv1alpha1.GroupMembersPatchList) *groupv1alpha1.GroupMembersPatch {
	var patch *groupv1alpha1.GroupMembersPatch
	var latestRevision int32

	for index := range patchList.Items {
		revision := patchList.Items[index].AppliedToGroupMembers.Revision
		if revision >= latestRevision {
			latestRevision = revision
			patch = &patchList.Items[index]
		}
	}

	return patch
}

func newTestEndpoint(labels map[string]string, ip types.IPAddress) *securityv1alpha1.Endpoint {
	name := "endpoint-test-" + string(uuid.NewUUID())
	id := name
	labels[TestLabelKey] = TestLabelValue

	return &securityv1alpha1.Endpoint{
		ObjectMeta: metav1.ObjectMeta{
			Name:   name,
			Labels: labels,
		},
		Spec: securityv1alpha1.EndpointReference{
			ExternalIDName:  id,
			ExternalIDValue: id,
		},
		Status: securityv1alpha1.EndpointStatus{
			IPs: []types.IPAddress{ip},
		},
	}
}

func newTestEndpointGroup(matchLabels map[string]string) *groupv1alpha1.EndpointGroup {
	name := "endpointgroup-test-" + string(uuid.NewUUID())

	return &groupv1alpha1.EndpointGroup{
		ObjectMeta: metav1.ObjectMeta{
			Name:   name,
			Labels: map[string]string{TestLabelKey: TestLabelValue},
		},
		Spec: groupv1alpha1.EndpointGroupSpec{
			Selector: &metav1.LabelSelector{
				MatchLabels: matchLabels,
			},
		},
	}
}

func newTestPatch(groupName string, revision int32) *groupv1alpha1.GroupMembersPatch {
	name := "patch-test-" + string(uuid.NewUUID())

	return &groupv1alpha1.GroupMembersPatch{
		ObjectMeta: metav1.ObjectMeta{
			Name:   name,
			Labels: map[string]string{lynxctrl.OwnerGroupLabel: groupName},
		},
		AppliedToGroupMembers: groupv1alpha1.GroupMembersReference{
			Name:     groupName,
			Revision: revision,
		},
	}
}

func equal(a interface{}, b interface{}) bool {
	equal, err := (&matchers.EqualMatcher{Expected: a}).Match(b)
	return equal && err == nil
}

func assertHasPatch(epGroup *groupv1alpha1.EndpointGroup, patch groupv1alpha1.GroupMembersPatch) {
	Eventually(func() bool {
		patches := groupv1alpha1.GroupMembersPatchList{}
		Expect(k8sClient.List(context.Background(), &patches, client.MatchingLabels{lynxctrl.OwnerGroupLabel: epGroup.Name})).Should(Succeed())
		latestPatch := getLatestPatch(patches)
		return latestPatch != nil &&
			equal(latestPatch.UpdatedGroupMembers, patch.UpdatedGroupMembers) &&
			equal(latestPatch.AddedGroupMembers, patch.AddedGroupMembers) &&
			equal(latestPatch.RemovedGroupMembers, patch.RemovedGroupMembers)
	}, timeout, interval).Should(BeTrue())
}

func assertHasGroupMembers(epGroup *groupv1alpha1.EndpointGroup, members groupv1alpha1.GroupMembers) {
	matcher := Equal(members.GroupMembers)
	if len(members.GroupMembers) == 0 {
		// equal matcher can't compare two empty array
		matcher = BeEmpty()
	}

	Eventually(func() []groupv1alpha1.GroupMember {
		members := groupv1alpha1.GroupMembers{}

		err := k8sClient.Get(context.Background(), client.ObjectKey{Name: epGroup.Name}, &members)
		Expect(client.IgnoreNotFound(err)).Should(Succeed())

		return members.GroupMembers
	}, timeout, interval).Should(matcher)
}
