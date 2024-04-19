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
package validates_test

import (
	"context"
	"encoding/json"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	admv1 "k8s.io/api/admission/v1"
	authv1 "k8s.io/api/authentication/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"

	groupv1alpha1 "github.com/everoute/everoute/pkg/apis/group/v1alpha1"
	securityv1alpha1 "github.com/everoute/everoute/pkg/apis/security/v1alpha1"
	"github.com/everoute/everoute/pkg/constants"
	"github.com/everoute/everoute/pkg/labels"
)

func init() {
	ObjectsInitFunc = append(ObjectsCleanFunc, initObject)
	ObjectsCleanFunc = append(ObjectsCleanFunc, removeObject)
}

var (
	securityPolicyIngress *securityv1alpha1.SecurityPolicy
	securityPolicyEgress  *securityv1alpha1.SecurityPolicy
	endpointA             *securityv1alpha1.Endpoint
	endpointGroupA        *groupv1alpha1.EndpointGroup
	endpointGroupB        *groupv1alpha1.EndpointGroup
	globalPolicy          *securityv1alpha1.GlobalPolicy
)

const (
	timeout  = time.Second * 10
	interval = time.Millisecond * 250
)

// init and create all object before each
var initObject = func() {
	securityPolicyIngress = &securityv1alpha1.SecurityPolicy{
		TypeMeta: metav1.TypeMeta{
			Kind:       "SecurityPolicy",
			APIVersion: "security.everoute.io/v1alpha1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "security-policy-ingress",
			Namespace: metav1.NamespaceDefault,
			Labels: map[string]string{
				"app": "validate-test",
			},
		},
		Spec: securityv1alpha1.SecurityPolicySpec{
			Tier: constants.Tier1,
			AppliedTo: []securityv1alpha1.ApplyToPeer{{
				EndpointSelector: &labels.Selector{},
			}},
			IngressRules: []securityv1alpha1.Rule{
				{
					Name: "rule1",
					Ports: []securityv1alpha1.SecurityPolicyPort{{
						Protocol:  securityv1alpha1.ProtocolTCP,
						PortRange: "3-10",
					}},
					From: []securityv1alpha1.SecurityPolicyPeer{{
						IPBlock: &networkingv1.IPBlock{
							CIDR: "192.168.1.1/10",
						},
					}},
				},
			},
		},
	}
	securityPolicyEgress = &securityv1alpha1.SecurityPolicy{
		TypeMeta: metav1.TypeMeta{
			Kind:       "SecurityPolicy",
			APIVersion: "security.everoute.io/v1alpha1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "security-policy-egress",
			Namespace: metav1.NamespaceDefault,
			Labels: map[string]string{
				"app": "validate-test",
			},
		},
		Spec: securityv1alpha1.SecurityPolicySpec{
			Tier: constants.Tier1,
			AppliedTo: []securityv1alpha1.ApplyToPeer{{
				EndpointSelector: &labels.Selector{},
			}},
			EgressRules: []securityv1alpha1.Rule{
				{
					Name: "rule1",
					Ports: []securityv1alpha1.SecurityPolicyPort{{
						Protocol: securityv1alpha1.ProtocolUDP,
					}},
					To: []securityv1alpha1.SecurityPolicyPeer{{
						IPBlock: &networkingv1.IPBlock{
							CIDR: "192.168.1.1/10",
						},
					}},
				},
				{
					Name: "rule2",
					Ports: []securityv1alpha1.SecurityPolicyPort{{
						Protocol: securityv1alpha1.ProtocolICMP,
					}},
				},
			},
		},
	}
	endpointA = &securityv1alpha1.Endpoint{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Endpoint",
			APIVersion: "security.everoute.io/v1alpha1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "endpoint01",
			Namespace: metav1.NamespaceDefault,
			Labels: map[string]string{
				"key1": "value1",
				"app":  "validate-test",
			},
		},
		Spec: securityv1alpha1.EndpointSpec{
			Reference: securityv1alpha1.EndpointReference{
				ExternalIDName:  "idk1",
				ExternalIDValue: "idv1",
			},
		},
	}
	endpointGroupA = &groupv1alpha1.EndpointGroup{
		TypeMeta: metav1.TypeMeta{
			Kind:       "EndpointGroup",
			APIVersion: "group.everoute.io/v1alpha1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "group01",
			Labels: map[string]string{
				"app": "validate-test",
			},
		},
		Spec: groupv1alpha1.EndpointGroupSpec{
			EndpointSelector: &labels.Selector{
				LabelSelector: metav1.LabelSelector{
					MatchLabels: map[string]string{
						"key1": "value1",
					},
				},
			},
		},
	}
	endpointGroupB = &groupv1alpha1.EndpointGroup{
		TypeMeta: metav1.TypeMeta{
			Kind:       "EndpointGroup",
			APIVersion: "group.everoute.io/v1alpha1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "group02",
			Labels: map[string]string{
				"app": "validate-test",
			},
		},
		Spec: groupv1alpha1.EndpointGroupSpec{
			EndpointSelector: &labels.Selector{
				LabelSelector: metav1.LabelSelector{
					MatchExpressions: []metav1.LabelSelectorRequirement{
						{
							Key:      "key2",
							Operator: metav1.LabelSelectorOpExists,
						},
					},
				},
			},
		},
	}
	globalPolicy = &securityv1alpha1.GlobalPolicy{
		TypeMeta: metav1.TypeMeta{
			Kind:       "GlobalPolicy",
			APIVersion: "security.everoute.io/v1alpha1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "global-policy",
		},
		Spec: securityv1alpha1.GlobalPolicySpec{
			DefaultAction: securityv1alpha1.GlobalDefaultActionAllow,
		},
	}

	createAndWait(k8sClient, securityPolicyEgress)
	createAndWait(k8sClient, securityPolicyIngress)
	createAndWait(k8sClient, endpointA)
	createAndWait(k8sClient, endpointGroupA)
	createAndWait(k8sClient, endpointGroupB)
	createAndWait(k8sClient, globalPolicy)
}

// remove all object after each
var removeObject = func() {
	namespaceDefault := client.InNamespace(metav1.NamespaceDefault)
	matchTestLabel := client.MatchingLabels{"app": "validate-test"}

	Expect(k8sClient.DeleteAllOf(context.Background(), &securityv1alpha1.Endpoint{}, namespaceDefault, matchTestLabel)).Should(Succeed())
	Expect(k8sClient.DeleteAllOf(context.Background(), &groupv1alpha1.EndpointGroup{}, matchTestLabel)).Should(Succeed())
	Expect(k8sClient.DeleteAllOf(context.Background(), &securityv1alpha1.SecurityPolicy{}, namespaceDefault, matchTestLabel)).Should(Succeed())
}

// createAndWait will create an object and wait until the object could be get.
func createAndWait(cli client.Client, obj metav1.Object, options ...client.CreateOption) {
	ctx := context.Background()
	Expect(cli.Create(ctx, obj.(runtime.Object).DeepCopyObject().(client.Object), options...)).Should(Succeed())
	Eventually(func() error {
		return cli.Get(ctx, client.ObjectKey{Namespace: obj.GetNamespace(), Name: obj.GetName()}, obj.(runtime.Object).DeepCopyObject().(client.Object))
	}, timeout, interval).Should(Succeed())
}

// fakeAdmissionReview create AdmissionReview by giving newObject, oldObject and username
func fakeAdmissionReview(newObject runtime.Object, oldObject runtime.Object, username string) *admv1.AdmissionReview {
	gvk := schema.GroupVersionKind{}
	var operation admv1.Operation

	switch {
	case newObject == nil && oldObject == nil:
		return &admv1.AdmissionReview{}
	case newObject != nil && oldObject == nil:
		gvk = newObject.GetObjectKind().GroupVersionKind()
		operation = admv1.Create
	case newObject != nil && oldObject != nil:
		gvk = oldObject.GetObjectKind().GroupVersionKind()
		operation = admv1.Update
	case newObject == nil && oldObject != nil:
		gvk = oldObject.GetObjectKind().GroupVersionKind()
		operation = admv1.Delete
	}

	oldObjRaw, _ := json.Marshal(oldObject)
	newObjRaw, _ := json.Marshal(newObject)

	return &admv1.AdmissionReview{
		Request: &admv1.AdmissionRequest{
			Kind: metav1.GroupVersionKind{
				Group:   gvk.Group,
				Version: gvk.Version,
				Kind:    gvk.Kind,
			},
			Operation: operation,
			UserInfo: authv1.UserInfo{
				Username: username,
			},
			Object: runtime.RawExtension{
				Raw: newObjRaw,
			},
			OldObject: runtime.RawExtension{
				Raw: oldObjRaw,
			},
		},
	}
}

var _ = Describe("CRD Validate", func() {

	Context("Validate On EndpointGroup", func() {
		It("Create validate EndpointGroup should always allowed", func() {
			Expect(validate.Validate(fakeAdmissionReview(endpointGroupA, nil, "")).Allowed).Should(BeTrue())
		})
		It("Create EndpointGroup with wrong selector should not allowed", func() {
			endpointGroup := endpointGroupA.DeepCopy()
			endpointGroup.Name = "endpointgroup"
			endpointGroup.Spec.EndpointSelector.ExtendMatchLabels = map[string][]string{"foo": {}}
			Expect(validate.Validate(fakeAdmissionReview(endpointGroup, nil, "")).Allowed).Should(BeFalse())
		})
		It("Create EndpointGroup with both Namespace and NamespaceSelector set should not allowed", func() {
			namespaceDefault := metav1.NamespaceDefault
			endpointGroupA.Spec.Namespace = &namespaceDefault
			endpointGroupA.Spec.NamespaceSelector = &metav1.LabelSelector{}
			Expect(validate.Validate(fakeAdmissionReview(endpointGroupA, nil, "")).Allowed).Should(BeFalse())
		})
		It("Update EndpointGroup with wrong selector should not allowed", func() {
			endpointGroup := endpointGroupA.DeepCopy()
			endpointGroup.Name = "endpointgroup"
			endpointGroup.Spec.EndpointSelector.MatchExpressions = []metav1.LabelSelectorRequirement{{
				Key:      "xxx",
				Operator: "UNKNOW-OPERATOR",
			}}
			Expect(validate.Validate(fakeAdmissionReview(endpointGroup, endpointGroupA, "")).Allowed).Should(BeFalse())
		})
		It("Delete EndpointGroup should always allowed", func() {
			endpointGroupC := endpointGroupA.DeepCopy()
			Expect(validate.Validate(fakeAdmissionReview(nil, endpointGroupC, "")).Allowed).Should(BeTrue())
		})
	})

	Context("Validate On Endpoint", func() {
		It("Create endpoint with empty id should not allowed", func() {
			endpointB := endpointA.DeepCopy()
			endpointB.Name = "endpointB"
			endpointB.Spec.Reference.ExternalIDName = ""
			Expect(validate.Validate(fakeAdmissionReview(endpointB, nil, "")).Allowed).Should(BeFalse())
		})
		It("Create endpoint with invalid labels should not allow", func() {
			endpointB := endpointA.DeepCopy()
			endpointB.Name = "endpointB"
			endpointB.Labels = map[string]string{"foo": "bar"}
			endpointB.Spec.ExtendLabels = map[string][]string{"foo": {"bar", "baz"}}
			Expect(validate.Validate(fakeAdmissionReview(endpointB, nil, "")).Allowed).Should(BeFalse())
		})
		It("Create validate endpoint should allowed", func() {
			endpointB := endpointA.DeepCopy()
			endpointB.Name = "endpointB"
			Expect(validate.Validate(fakeAdmissionReview(endpointB, nil, "")).Allowed).Should(BeTrue())
		})
		It("Update endpoint id should not allowed", func() {
			endpointB := endpointA.DeepCopy()
			endpointB.Spec.Reference.ExternalIDValue = "update-id-value"
			Expect(validate.Validate(fakeAdmissionReview(endpointB, endpointA, "")).Allowed).Should(BeFalse())
		})
		It("Update endpoint with invalid labels should not allow", func() {
			endpointB := endpointA.DeepCopy()
			endpointB.Labels = map[string]string{"foo": "bar"}
			endpointB.Spec.ExtendLabels = map[string][]string{"foo": {"bar", "baz"}}
			Expect(validate.Validate(fakeAdmissionReview(endpointB, endpointA, "")).Allowed).Should(BeFalse())
		})
		It("Delete endpoint should always allowed", func() {
			Expect(validate.Validate(fakeAdmissionReview(nil, endpointA, "")).Allowed).Should(BeTrue())
		})

	})

	Context("Validate On SecurityPolicy", func() {
		It("Create policy with unexists tier should not allowed", func() {
			policy := securityPolicyIngress.DeepCopy()
			policy.Name = "new-policy"
			policy.Spec.Tier = "UNExist-Tier-endpointName"
			Expect(validate.Validate(fakeAdmissionReview(policy, nil, "")).Allowed).Should(BeFalse())
		})
		It("Create blocklist policy can't set symmetric mode", func() {
			policy := securityPolicyIngress.DeepCopy()
			policy.Name = "new-blocklist"
			policy.Spec.IsBlocklist = true
			policy.Spec.SymmetricMode = true
			Expect(validate.Validate(fakeAdmissionReview(policy, nil, "")).Allowed).Should(BeFalse())
		})
		It("Update policy with unexists tier should not allowed", func() {
			policy := securityPolicyIngress.DeepCopy()
			policy.Spec.Tier = "UNExist-Tier-endpointName"
			Expect(validate.Validate(fakeAdmissionReview(policy, securityPolicyIngress, "")).Allowed).Should(BeFalse())
		})
		It("Update policy with unsupported tier in monitor mode should not allowed", func() {
			policy := securityPolicyIngress.DeepCopy()
			policy.Spec.Tier = "tier-ecp"
			policy.Spec.SecurityPolicyEnforcementMode = securityv1alpha1.MonitorMode
			Expect(validate.Validate(fakeAdmissionReview(policy, securityPolicyIngress, "")).Allowed).Should(BeFalse())
		})
		It("Delete policy should always allowed", func() {
			Expect(validate.Validate(fakeAdmissionReview(nil, securityPolicyEgress, "")).Allowed).Should(BeTrue())
			Expect(validate.Validate(fakeAdmissionReview(nil, securityPolicyIngress, "")).Allowed).Should(BeTrue())
		})

		Context("Validate On AppliedTo", func() {
			var policy *securityv1alpha1.SecurityPolicy
			BeforeEach(func() {
				policy = securityPolicyIngress.DeepCopy()
			})

			It("Create policy with nil applied to should allowed", func() {
				policy.Spec.AppliedTo = nil
				Expect(validate.Validate(fakeAdmissionReview(policy, nil, "")).Allowed).Should(BeTrue())
			})
			It("Create policy with empty applied to peers should not allowed", func() {
				policy.Spec.AppliedTo[0] = securityv1alpha1.ApplyToPeer{}
				Expect(validate.Validate(fakeAdmissionReview(policy, nil, "")).Allowed).Should(BeFalse())
			})
			It("Create policy with error format of applied to peer EndpointSelector should not allowed", func() {
				policy.Spec.AppliedTo[0] = securityv1alpha1.ApplyToPeer{
					EndpointSelector: &labels.Selector{
						ExtendMatchLabels: map[string][]string{"foo": {}},
					},
				}
				Expect(validate.Validate(fakeAdmissionReview(policy, nil, "")).Allowed).Should(BeFalse())
			})
			It("Create policy with available applied to peers should allowed", func() {
				policy.Spec.AppliedTo[0] = securityv1alpha1.ApplyToPeer{
					Endpoint: &endpointA.Name,
				}
				Expect(validate.Validate(fakeAdmissionReview(policy, nil, "")).Allowed).Should(BeTrue())

				policy.Spec.AppliedTo[0] = securityv1alpha1.ApplyToPeer{
					EndpointSelector: &labels.Selector{},
				}
				Expect(validate.Validate(fakeAdmissionReview(policy, nil, "")).Allowed).Should(BeTrue())
			})
		})

		Context("Validate On Rules", func() {
			It("Create policy with same rule name should not allowed", func() {
				policy := securityPolicyEgress.DeepCopy()
				policy.Spec.EgressRules[1].Name = policy.Spec.EgressRules[0].Name
				Expect(validate.Validate(fakeAdmissionReview(policy, nil, "")).Allowed).Should(BeFalse())
			})
			It("Create policy with wrong format rule name should not allowed", func() {
				policy := securityPolicyEgress.DeepCopy()
				policy.Spec.EgressRules[0].Name = "rule@name#"
				Expect(validate.Validate(fakeAdmissionReview(policy, nil, "")).Allowed).Should(BeFalse())
			})
			It("Create policy with validate portRange should allowed", func() {
				policy := securityPolicyIngress.DeepCopy()
				policy.Spec.IngressRules[0].Ports[0].PortRange = "20,22-24,80,82-84"
				Expect(validate.Validate(fakeAdmissionReview(policy, nil, "")).Allowed).Should(BeTrue())
			})
			It("Create policy with error format of portRange should not allowed", func() {
				policy := securityPolicyIngress.DeepCopy()
				policy.Spec.IngressRules[0].Ports[0].PortRange = "22,80,"
				Expect(validate.Validate(fakeAdmissionReview(policy, nil, "")).Allowed).Should(BeFalse())
			})
		})

		Context("Validate On SecurityPolicyPeer", func() {
			var policy *securityv1alpha1.SecurityPolicy
			BeforeEach(func() {
				policy = securityPolicyIngress.DeepCopy()
			})

			It("Create policy with empty SecurityPolicyPeer should not allowed", func() {
				policy.Spec.IngressRules[0].From[0] = securityv1alpha1.SecurityPolicyPeer{}
				Expect(validate.Validate(fakeAdmissionReview(policy, nil, "")).Allowed).Should(BeFalse())
			})
			It("Create policy with error fields set in SecurityPolicyPeer should not allowed", func() {
				policy.Spec.IngressRules[0].From[0] = securityv1alpha1.SecurityPolicyPeer{
					IPBlock:          &networkingv1.IPBlock{CIDR: "0.0.0.0/0"},
					EndpointSelector: &labels.Selector{},
				}
				Expect(validate.Validate(fakeAdmissionReview(policy, nil, "")).Allowed).Should(BeFalse())

				policy.Spec.IngressRules[0].From[0] = securityv1alpha1.SecurityPolicyPeer{
					Endpoint: &securityv1alpha1.NamespacedName{
						Name:      endpointA.GetName(),
						Namespace: endpointA.GetNamespace(),
					},
					EndpointSelector: &labels.Selector{},
				}
				Expect(validate.Validate(fakeAdmissionReview(policy, nil, "")).Allowed).Should(BeFalse())
			})
			It("Create policy with nil SecurityPolicyPeer should allowed", func() {
				policy.Spec.IngressRules[0].From = nil
				Expect(validate.Validate(fakeAdmissionReview(policy, nil, "")).Allowed).Should(BeTrue())
			})
			It("Create policy with available SecurityPolicyPeer should allowed", func() {
				policy.Spec.IngressRules[0].From[0] = securityv1alpha1.SecurityPolicyPeer{
					IPBlock: &networkingv1.IPBlock{CIDR: "0.0.0.0/0"},
				}
				Expect(validate.Validate(fakeAdmissionReview(policy, nil, "")).Allowed).Should(BeTrue())

				policy.Spec.IngressRules[0].From[0] = securityv1alpha1.SecurityPolicyPeer{
					Endpoint: &securityv1alpha1.NamespacedName{
						Name:      endpointA.GetName(),
						Namespace: endpointA.GetNamespace(),
					},
				}
				Expect(validate.Validate(fakeAdmissionReview(policy, nil, "")).Allowed).Should(BeTrue())

				policy.Spec.IngressRules[0].From[0] = securityv1alpha1.SecurityPolicyPeer{
					EndpointSelector: &labels.Selector{},
				}
				Expect(validate.Validate(fakeAdmissionReview(policy, nil, "")).Allowed).Should(BeTrue())

				policy.Spec.IngressRules[0].From[0] = securityv1alpha1.SecurityPolicyPeer{
					NamespaceSelector: &metav1.LabelSelector{},
				}
				Expect(validate.Validate(fakeAdmissionReview(policy, nil, "")).Allowed).Should(BeTrue())

				policy.Spec.IngressRules[0].From[0] = securityv1alpha1.SecurityPolicyPeer{
					EndpointSelector:  &labels.Selector{},
					NamespaceSelector: &metav1.LabelSelector{},
				}
				Expect(validate.Validate(fakeAdmissionReview(policy, nil, "")).Allowed).Should(BeTrue())
			})
		})

		Context("Validate On IPBlock", func() {
			var policy *securityv1alpha1.SecurityPolicy
			BeforeEach(func() {
				policy = securityPolicyIngress.DeepCopy()
				policy.Spec.IngressRules[0].From[0] = securityv1alpha1.SecurityPolicyPeer{
					IPBlock: &networkingv1.IPBlock{},
				}
			})

			It("Create policy with error format of IPBlock.CIDR should not allowed", func() {
				policy.Spec.IngressRules[0].From[0].IPBlock.CIDR = "0.0.0.0/231"
				Expect(validate.Validate(fakeAdmissionReview(policy, nil, "")).Allowed).Should(BeFalse())
			})
			It("Create policy with error format of IPBlock.Except should not allowed", func() {
				policy.Spec.IngressRules[0].From[0].IPBlock.Except = []string{"0.0.0.0/231"}
				Expect(validate.Validate(fakeAdmissionReview(policy, nil, "")).Allowed).Should(BeFalse())
			})
			It("Create policy with IPBlock.CIDR not contains IPBlock.Except should not allowed", func() {
				policy.Spec.IngressRules[0].From[0].IPBlock.CIDR = "192.168.0.0/16"

				// cidr mask length > except mask length
				policy.Spec.IngressRules[0].From[0].IPBlock.Except = []string{"192.168.0.0/14"}
				Expect(validate.Validate(fakeAdmissionReview(policy, nil, "")).Allowed).Should(BeFalse())

				// cidr mask length == except mask length
				policy.Spec.IngressRules[0].From[0].IPBlock.Except = []string{"192.168.0.0/16"}
				Expect(validate.Validate(fakeAdmissionReview(policy, nil, "")).Allowed).Should(BeFalse())

				// cidr not contains the except cidr range
				policy.Spec.IngressRules[0].From[0].IPBlock.Except = []string{"192.170.0.0/24"}
				Expect(validate.Validate(fakeAdmissionReview(policy, nil, "")).Allowed).Should(BeFalse())
			})
			It("Create policy with available IPBlock should allowed", func() {
				policy.Spec.IngressRules[0].From[0].IPBlock.CIDR = "192.168.0.0/16"

				policy.Spec.IngressRules[0].From[0].IPBlock.Except = []string{"192.168.0.0/24"}
				Expect(validate.Validate(fakeAdmissionReview(policy, nil, "")).Allowed).Should(BeTrue())

				policy.Spec.IngressRules[0].From[0].IPBlock.Except = []string{"192.168.1.0/24"}
				Expect(validate.Validate(fakeAdmissionReview(policy, nil, "")).Allowed).Should(BeTrue())
			})
		})
	})

	Context("Validate On GlobalPolicy", func() {
		It("Create multiple GlobalPolicy should not allowed", func() {
			policy := globalPolicy.DeepCopy()
			policy.Name = "new-global-policy"
			Expect(validate.Validate(fakeAdmissionReview(policy, nil, "")).Allowed).Should(BeFalse())
		})
		It("Create available GlobalPolicy should allowed", func() {
			policy := globalPolicy.DeepCopy()
			Expect(validate.Validate(fakeAdmissionReview(policy, nil, "")).Allowed).Should(BeTrue())
		})
		It("Update available GlobalPolicy should allowed", func() {
			policy := globalPolicy.DeepCopy()
			policy.Spec.DefaultAction = securityv1alpha1.GlobalDefaultActionDrop
			Expect(validate.Validate(fakeAdmissionReview(policy, globalPolicy, "")).Allowed).Should(BeTrue())
		})
		It("Delete GlobalPolicy should always allowed", func() {
			Expect(validate.Validate(fakeAdmissionReview(nil, globalPolicy, "")).Allowed).Should(BeTrue())
		})
	})
})
