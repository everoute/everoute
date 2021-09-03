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
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/uuid"
	"sigs.k8s.io/controller-runtime/pkg/client"

	groupv1alpha1 "github.com/smartxworks/lynx/pkg/apis/group/v1alpha1"
	securityv1alpha1 "github.com/smartxworks/lynx/pkg/apis/security/v1alpha1"
	"github.com/smartxworks/lynx/pkg/constants"
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
		namespaceDefault := client.InNamespace(metav1.NamespaceDefault)

		By("delete all test endpoints")
		Expect(k8sClient.DeleteAllOf(ctx, &securityv1alpha1.Endpoint{}, namespaceDefault, client.MatchingLabels{TestLabelKey: TestLabelValue})).Should(Succeed())
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
			epGroup = newTestEndpointGroup(map[string]string{"label.key": "label.value"}, nil, "")

			By(fmt.Sprintf("create endpointgroup %s with selector %v", epGroup.Name, epGroup.Spec.EndpointSelector))
			Expect(k8sClient.Create(ctx, epGroup)).Should(Succeed())
		})
		Context("none endpoint in the group", func() {
			When("create a endpoint in the group", func() {
				var ep *securityv1alpha1.Endpoint
				var namespace = metav1.NamespaceDefault

				BeforeEach(func() {
					ep = newTestEndpoint(namespace, map[string]string{"label.key": "label.value"}, "192.168.1.1")

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
			var namespace = metav1.NamespaceDefault

			BeforeEach(func() {
				ep = newTestEndpoint(namespace, map[string]string{"label.key": "label.value"}, "192.168.1.1")

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
					updateGroup := epGroup.DeepCopy()
					updateGroup.Spec.EndpointSelector = nil

					By(fmt.Sprintf("change endpointgroup %s selector to %v", epGroup.Name, epGroup.Spec.EndpointSelector))
					Expect(k8sClient.Patch(ctx, updateGroup, client.MergeFrom(epGroup))).Should(Succeed())
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
					assertPatchLen(ctx, epGroup.Name, 0)
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
				assertPatchLen(ctx, epGroup.Name, 10)

				By("update the group label to drive reconcile group")
				updateGroup := epGroup.DeepCopy()
				updateGroup.Spec.EndpointSelector = nil
				Expect(k8sClient.Patch(ctx, updateGroup, client.MergeFrom(epGroup))).Should(Succeed())
			})
			It("should clean up old patches", func() {
				Eventually(func() int {
					patches := groupv1alpha1.GroupMembersPatchList{}
					Expect(k8sClient.List(ctx, &patches, client.MatchingLabels{constants.OwnerGroupLabelKey: epGroup.Name})).Should(Succeed())
					return len(patches.Items)
				}, timeout, interval).Should(Equal(constants.NumOfRetainedGroupMembersPatches))
			})
		})
	})

	Context("none endpointgroup has been created", func() {
		When("create an endpointgroup", func() {
			var epGroup *groupv1alpha1.EndpointGroup

			BeforeEach(func() {
				epGroup = newTestEndpointGroup(map[string]string{}, nil, "")

				By(fmt.Sprintf("create endpointgroup %s with selector %v", epGroup.Name, epGroup.Spec.EndpointSelector))
				Expect(k8sClient.Create(ctx, epGroup)).Should(Succeed())
			})

			It("should add finalizer for the endpointgroup", func() {
				Eventually(func() []string {
					err := k8sClient.Get(ctx, client.ObjectKey{Name: epGroup.Name}, epGroup)
					Expect(client.IgnoreNotFound(err)).Should(Succeed())
					return epGroup.Finalizers
				}, timeout, interval).Should(Equal([]string{constants.DependentsCleanFinalizer}))
			})

			It("should create groupmembers with empty members", func() {
				assertHasGroupMembers(epGroup, groupv1alpha1.GroupMembers{GroupMembers: []groupv1alpha1.GroupMember{}})
			})
		})
	})

	When("create EndpointGroup with namespace selector", func() {
		var epGroup *groupv1alpha1.EndpointGroup
		var namespaceLabel, endpointLabel map[string]string

		BeforeEach(func() {
			endpointLabel = map[string]string{"label.key": "label.value"}
			namespaceLabel = map[string]string{"label.key": "label.value"}
			epGroup = newTestEndpointGroup(endpointLabel, namespaceLabel, "")

			By(fmt.Sprintf("create endpointgroup %s with spec %v", epGroup.Name, epGroup.Spec))
			Expect(k8sClient.Create(ctx, epGroup)).Should(Succeed())
		})

		When("create namespace and endpoint match group.spec", func() {
			var ep *securityv1alpha1.Endpoint
			var namespace *corev1.Namespace

			BeforeEach(func() {
				namespace = newTestNamespace(namespaceLabel)
				ep = newTestEndpoint(namespace.GetName(), endpointLabel, "192.168.1.1")

				By(fmt.Sprintf("create namespace %s", namespace))
				Expect(k8sClient.Create(ctx, namespace)).Should(Succeed())

				By(fmt.Sprintf("create endpoint %s in namespace %s with labels %v", ep.GetName(), ep.GetNamespace(), ep.GetLabels()))
				Expect(k8sClient.Create(ctx, ep)).Should(Succeed())
				Expect(k8sClient.Status().Update(ctx, ep)).Should(Succeed())
			})
			AfterEach(func() {
				By(fmt.Sprintf("remove test namespace %s and endpoint %s", namespace.GetName(), ep.GetName()))
				Expect(k8sClient.Delete(ctx, namespace)).Should(Succeed())
				Expect(k8sClient.Delete(ctx, ep)).Should(Succeed())
			})

			It("should create patch add the endpoint", func() {
				assertHasPatch(epGroup, groupv1alpha1.GroupMembersPatch{AddedGroupMembers: []groupv1alpha1.GroupMember{endpointToGroupMember(ep)}})
			})
			It("should update groupmembers contains the endpoint", func() {
				assertHasGroupMembers(epGroup, groupv1alpha1.GroupMembers{GroupMembers: []groupv1alpha1.GroupMember{endpointToGroupMember(ep)}})
			})

			When("update namespace labels unmatch group.spec", func() {
				BeforeEach(func() {
					updateNamespace := namespace.DeepCopy()
					updateNamespace.Labels = nil

					By(fmt.Sprintf("update namespace %s labels to nil", namespace.GetName()))
					Expect(k8sClient.Patch(ctx, updateNamespace, client.MergeFrom(namespace))).Should(Succeed())
				})

				It("should update groupmembers contains no endpoints", func() {
					assertHasGroupMembers(epGroup, groupv1alpha1.GroupMembers{GroupMembers: []groupv1alpha1.GroupMember{}})
				})
			})
		})
	})

	When("create EndpointGroup with specific namespace", func() {
		var epGroup *groupv1alpha1.EndpointGroup
		var namespace *corev1.Namespace
		var endpointLabel map[string]string

		BeforeEach(func() {
			endpointLabel = map[string]string{"label.key": "label.value"}
			namespace = newTestNamespace(nil)
			epGroup = newTestEndpointGroup(endpointLabel, nil, namespace.GetName())

			By(fmt.Sprintf("create endpointgroup %s with spec %v", epGroup.Name, epGroup.Spec))
			Expect(k8sClient.Create(ctx, epGroup)).Should(Succeed())

			By(fmt.Sprintf("create namespace %s", namespace))
			Expect(k8sClient.Create(ctx, namespace)).Should(Succeed())
		})
		AfterEach(func() {
			By(fmt.Sprintf("remove test namespace %s", namespace.GetName()))
			Expect(k8sClient.Delete(ctx, namespace)).Should(Succeed())
		})

		When("create endpoint in the specific namespace", func() {
			var ep *securityv1alpha1.Endpoint

			BeforeEach(func() {
				ep = newTestEndpoint(namespace.GetName(), endpointLabel, "192.168.1.1")

				By(fmt.Sprintf("create endpoint %s in namespace %s with labels %v", ep.GetName(), ep.GetNamespace(), ep.GetLabels()))
				Expect(k8sClient.Create(ctx, ep)).Should(Succeed())
				Expect(k8sClient.Status().Update(ctx, ep)).Should(Succeed())
			})
			AfterEach(func() {
				Expect(k8sClient.Delete(ctx, ep)).Should(Succeed())
			})
			It("should create patch add the endpoint", func() {
				assertHasPatch(epGroup, groupv1alpha1.GroupMembersPatch{AddedGroupMembers: []groupv1alpha1.GroupMember{endpointToGroupMember(ep)}})
			})
			It("should update groupmembers contains the endpoint", func() {
				assertHasGroupMembers(epGroup, groupv1alpha1.GroupMembers{GroupMembers: []groupv1alpha1.GroupMember{endpointToGroupMember(ep)}})
			})
		})

		When("create endpoint in the default namespace", func() {
			var ep *securityv1alpha1.Endpoint

			BeforeEach(func() {
				ep = newTestEndpoint(metav1.NamespaceDefault, endpointLabel, "192.168.1.1")

				By(fmt.Sprintf("create endpoint %s in namespace %s with labels %v", ep.GetName(), ep.GetNamespace(), ep.GetLabels()))
				Expect(k8sClient.Create(ctx, ep)).Should(Succeed())
				Expect(k8sClient.Status().Update(ctx, ep)).Should(Succeed())
			})
			AfterEach(func() {
				Expect(k8sClient.Delete(ctx, ep)).Should(Succeed())
			})

			It("endpointgroup should not contains the endpoint", func() {
				// wait for controller handle endpoint event
				time.Sleep(5 * time.Second)
				By(fmt.Sprintf("endpointgroup %s should has no members", epGroup.Name))
				assertHasGroupMembers(epGroup, groupv1alpha1.GroupMembers{GroupMembers: []groupv1alpha1.GroupMember{}})
			})

			When("remove namespace in the EndpointGroup spec", func() {
				BeforeEach(func() {
					updateGroup := epGroup.DeepCopy()
					updateGroup.Spec.Namespace = nil

					By(fmt.Sprintf("update endpointgroup %s spec.namespace to nil", epGroup.GetName()))
					Expect(k8sClient.Patch(ctx, updateGroup, client.MergeFrom(epGroup))).Should(Succeed())
				})

				It("should create patch add the endpoint", func() {
					assertHasPatch(epGroup, groupv1alpha1.GroupMembersPatch{AddedGroupMembers: []groupv1alpha1.GroupMember{endpointToGroupMember(ep)}})
				})
				It("should update groupmembers contains the endpoint", func() {
					assertHasGroupMembers(epGroup, groupv1alpha1.GroupMembers{GroupMembers: []groupv1alpha1.GroupMember{endpointToGroupMember(ep)}})
				})
			})
		})
	})
})

// endpointToGroupMember conversion endpoint to GroupMember.
func endpointToGroupMember(ep *securityv1alpha1.Endpoint) groupv1alpha1.GroupMember {
	return groupv1alpha1.GroupMember{
		EndpointReference: groupv1alpha1.EndpointReference{
			ExternalIDName:  ep.Spec.Reference.ExternalIDName,
			ExternalIDValue: ep.Spec.Reference.ExternalIDValue,
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

func newTestEndpoint(namespace string, labels map[string]string, ip types.IPAddress) *securityv1alpha1.Endpoint {
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
				ExternalIDName:  id,
				ExternalIDValue: id,
			},
		},
		Status: securityv1alpha1.EndpointStatus{
			IPs: []types.IPAddress{ip},
		},
	}
}

func newTestNamespace(labels map[string]string) *corev1.Namespace {
	name := "namespace-test-" + string(uuid.NewUUID())

	return &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:   name,
			Labels: labels,
		},
	}
}

func newTestEndpointGroup(epSelector map[string]string, nsSelector map[string]string, namespace string) *groupv1alpha1.EndpointGroup {
	name := "endpointgroup-test-" + string(uuid.NewUUID())
	epGroup := &groupv1alpha1.EndpointGroup{
		ObjectMeta: metav1.ObjectMeta{
			Name:   name,
			Labels: map[string]string{TestLabelKey: TestLabelValue},
		},
	}

	if epSelector != nil {
		epGroup.Spec.EndpointSelector = &metav1.LabelSelector{
			MatchLabels: epSelector,
		}
	}

	if nsSelector != nil {
		epGroup.Spec.NamespaceSelector = &metav1.LabelSelector{
			MatchLabels: nsSelector,
		}
	}

	if namespace != "" {
		epGroup.Spec.Namespace = &namespace
	}

	return epGroup
}

func newTestPatch(groupName string, revision int32) *groupv1alpha1.GroupMembersPatch {
	name := "patch-test-" + string(uuid.NewUUID())

	return &groupv1alpha1.GroupMembersPatch{
		ObjectMeta: metav1.ObjectMeta{
			Name:   name,
			Labels: map[string]string{constants.OwnerGroupLabelKey: groupName},
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
		Expect(k8sClient.List(context.Background(), &patches, client.MatchingLabels{constants.OwnerGroupLabelKey: epGroup.Name})).Should(Succeed())
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

func assertPatchLen(ctx context.Context, groupName string, length int) {
	Eventually(func() int {
		patchList := groupv1alpha1.GroupMembersPatchList{}
		Expect(k8sClient.List(ctx, &patchList, client.MatchingLabels{constants.OwnerGroupLabelKey: groupName})).Should(Succeed())
		return len(patchList.Items)
	}, timeout, interval).Should(Equal(length))
}
