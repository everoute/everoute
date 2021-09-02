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

	groupv1alpha1 "github.com/smartxworks/lynx/pkg/apis/group/v1alpha1"
	securityv1alpha1 "github.com/smartxworks/lynx/pkg/apis/security/v1alpha1"
)

func init() {
	ObjectsInitFunc = append(ObjectsCleanFunc, initObject)
	ObjectsCleanFunc = append(ObjectsCleanFunc, removeObject)
}

var (
	tierPri50             *securityv1alpha1.Tier
	securityPolicyIngress *securityv1alpha1.SecurityPolicy
	securityPolicyEgress  *securityv1alpha1.SecurityPolicy
	endpointA             *securityv1alpha1.Endpoint
	endpointGroupA        *groupv1alpha1.EndpointGroup
	endpointGroupB        *groupv1alpha1.EndpointGroup
)

const (
	timeout  = time.Second * 10
	interval = time.Millisecond * 250
)

// init and create all object before each
var initObject = func() {
	tierPri50 = &securityv1alpha1.Tier{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Tier",
			APIVersion: "security.lynx.smartx.com/v1alpha1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "tier-pri50",
			Labels: map[string]string{
				"app": "validate-test",
			},
		},
		Spec: securityv1alpha1.TierSpec{
			Priority: 50,
			TierMode: securityv1alpha1.TierBlackList,
		},
	}
	securityPolicyIngress = &securityv1alpha1.SecurityPolicy{
		TypeMeta: metav1.TypeMeta{
			Kind:       "SecurityPolicy",
			APIVersion: "security.lynx.smartx.com/v1alpha1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "security-policy-ingress",
			Namespace: metav1.NamespaceDefault,
			Labels: map[string]string{
				"app": "validate-test",
			},
		},
		Spec: securityv1alpha1.SecurityPolicySpec{
			Tier:     "tier-pri50",
			Priority: 60,
			AppliedTo: securityv1alpha1.AppliedTo{
				EndpointGroups: []string{
					"group01",
				},
			},
			IngressRules: []securityv1alpha1.Rule{
				{
					Name: "rule1",
					Ports: []securityv1alpha1.SecurityPolicyPort{
						{
							Protocol:  securityv1alpha1.ProtocolTCP,
							PortRange: "3-10",
						},
					},
					From: securityv1alpha1.SecurityPolicyPeer{
						IPBlocks: []networkingv1.IPBlock{{
							CIDR: "192.168.1.1/10",
						}},
						EndpointGroups: []string{
							"group02",
						},
					},
				},
			},
		},
	}
	securityPolicyEgress = &securityv1alpha1.SecurityPolicy{
		TypeMeta: metav1.TypeMeta{
			Kind:       "SecurityPolicy",
			APIVersion: "security.lynx.smartx.com/v1alpha1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "security-policy-egress",
			Namespace: metav1.NamespaceDefault,
			Labels: map[string]string{
				"app": "validate-test",
			},
		},
		Spec: securityv1alpha1.SecurityPolicySpec{
			Tier:     "tier-pri50",
			Priority: 70,
			AppliedTo: securityv1alpha1.AppliedTo{
				EndpointGroups: []string{
					"group01",
				},
			},
			EgressRules: []securityv1alpha1.Rule{
				{
					Name: "rule1",
					Ports: []securityv1alpha1.SecurityPolicyPort{{
						Protocol: securityv1alpha1.ProtocolUDP,
					}},
					To: securityv1alpha1.SecurityPolicyPeer{
						IPBlocks: []networkingv1.IPBlock{{
							CIDR: "192.168.1.1/10",
						}},
						EndpointGroups: []string{
							"group02",
						},
					},
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
			APIVersion: "security.lynx.smartx.com/v1alpha1",
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
			APIVersion: "group.lynx.smartx.com/v1alpha1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "group01",
			Labels: map[string]string{
				"app": "validate-test",
			},
		},
		Spec: groupv1alpha1.EndpointGroupSpec{
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"key1": "value1",
				},
			},
		},
	}
	endpointGroupB = &groupv1alpha1.EndpointGroup{
		TypeMeta: metav1.TypeMeta{
			Kind:       "EndpointGroup",
			APIVersion: "group.lynx.smartx.com/v1alpha1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "group02",
			Labels: map[string]string{
				"app": "validate-test",
			},
		},
		Spec: groupv1alpha1.EndpointGroupSpec{
			Selector: &metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{
					{
						Key:      "key2",
						Operator: metav1.LabelSelectorOpExists,
					},
				},
			},
		},
	}

	createAndWait(k8sClient, tierPri50)
	createAndWait(k8sClient, securityPolicyEgress)
	createAndWait(k8sClient, securityPolicyIngress)
	createAndWait(k8sClient, endpointA)
	createAndWait(k8sClient, endpointGroupA)
	createAndWait(k8sClient, endpointGroupB)
}

// remove all object after each
var removeObject = func() {
	namespaceDefault := client.InNamespace(metav1.NamespaceDefault)
	matchTestLabel := client.MatchingLabels{"app": "validate-test"}

	Expect(k8sClient.DeleteAllOf(context.Background(), &securityv1alpha1.Tier{}, matchTestLabel)).Should(Succeed())
	Expect(k8sClient.DeleteAllOf(context.Background(), &securityv1alpha1.Endpoint{}, namespaceDefault, matchTestLabel)).Should(Succeed())
	Expect(k8sClient.DeleteAllOf(context.Background(), &groupv1alpha1.EndpointGroup{}, matchTestLabel)).Should(Succeed())
	Expect(k8sClient.DeleteAllOf(context.Background(), &securityv1alpha1.SecurityPolicy{}, namespaceDefault, matchTestLabel)).Should(Succeed())
}

// createAndWait will create an object and wait until the object could be get.
func createAndWait(cli client.Client, obj metav1.Object, options ...client.CreateOption) {
	ctx := context.Background()
	Expect(cli.Create(ctx, obj.(runtime.Object).DeepCopyObject(), options...)).Should(Succeed())
	Eventually(func() error {
		return cli.Get(ctx, client.ObjectKey{Namespace: obj.GetNamespace(), Name: obj.GetName()}, obj.(runtime.Object).DeepCopyObject())
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

	Context("Validate On Tier", func() {
		It("Create tier with same priority should not allowed", func() {
			tier := tierPri50.DeepCopy()
			tier.Name = "tier"
			Expect(validate.Validate(fakeAdmissionReview(tier, nil, "")).Allowed).Should(BeFalse())
		})
		It("Update tier priority should not allowed", func() {
			tier := tierPri50.DeepCopy()
			tier.Spec.Priority = 60
			Expect(validate.Validate(fakeAdmissionReview(tier, tierPri50, "")).Allowed).Should(BeFalse())
		})
		It("Delete tier used by SecurityPolicy should not allowed", func() {
			Expect(validate.Validate(fakeAdmissionReview(nil, tierPri50, "")).Allowed).Should(BeFalse())
		})
		It("Create tier with difference priority should allowed", func() {
			tier := tierPri50.DeepCopy()
			tier.Name = "tier"
			tier.Spec.Priority = 51
			Expect(validate.Validate(fakeAdmissionReview(tier, nil, "")).Allowed).Should(BeTrue())
		})
		It("Delete tier unused by SecurityPolicy should allowed", func() {
			tier := tierPri50.DeepCopy()
			tier.Name = "tier"
			Expect(validate.Validate(fakeAdmissionReview(nil, tier, "")).Allowed).Should(BeTrue())
		})

	})

	Context("Validate On EndpointGroup", func() {
		It("Create validate EndpointGroup should always allowed", func() {
			Expect(validate.Validate(fakeAdmissionReview(endpointGroupA, nil, "")).Allowed).Should(BeTrue())
		})
		It("Create EndpointGroup with wrong selector should not allowed", func() {
			endpointGroup := endpointGroupA.DeepCopy()
			endpointGroup.Name = "endpointgroup"
			endpointGroup.Spec.Selector.MatchLabels["&$XXXX"] = "^*xxxxx"
			Expect(validate.Validate(fakeAdmissionReview(endpointGroup, nil, "")).Allowed).Should(BeFalse())
		})
		It("Update EndpointGroup with wrong selector should not allowed", func() {
			endpointGroup := endpointGroupA.DeepCopy()
			endpointGroup.Name = "endpointgroup"
			endpointGroup.Spec.Selector.MatchExpressions = []metav1.LabelSelectorRequirement{{
				Key:      "xxx",
				Operator: "UNKNOW-OPERATOR",
			}}
			Expect(validate.Validate(fakeAdmissionReview(endpointGroup, endpointGroupA, "")).Allowed).Should(BeFalse())
		})
		It("Delete EndpointGroup used by SecurityPolicy should not allowed", func() {
			Expect(validate.Validate(fakeAdmissionReview(nil, endpointGroupA, "")).Allowed).Should(BeFalse())
		})
		It("Delete unused EndpointGroup should allowed", func() {
			endpointGroupC := endpointGroupA.DeepCopy()
			endpointGroupC.Name = "endpoint03"
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
		It("Delete endpoint should always allowed", func() {
			Expect(validate.Validate(fakeAdmissionReview(nil, endpointA, "")).Allowed).Should(BeTrue())
		})

	})

	Context("Validate On SecurityPolicy", func() {
		It("Create priority with unexists tier should not allowed", func() {
			policy := securityPolicyIngress.DeepCopy()
			policy.Name = "new-policy"
			policy.Spec.Tier = "UNExist-Tier-endpointName"
			Expect(validate.Validate(fakeAdmissionReview(policy, nil, "")).Allowed).Should(BeFalse())
		})
		It("Create priority with unexists EndpointGroup should not allowed", func() {
			policy := securityPolicyIngress.DeepCopy()
			policy.Name = "newPolicy"
			policy.Spec.AppliedTo.EndpointGroups = []string{"UNExist-EndpointGroup-endpointName"}
			Expect(validate.Validate(fakeAdmissionReview(policy, nil, "")).Allowed).Should(BeFalse())
		})
		It("Create validate priority should allowed", func() {
			Expect(validate.Validate(fakeAdmissionReview(securityPolicyIngress, nil, "")).Allowed).Should(BeTrue())
			Expect(validate.Validate(fakeAdmissionReview(securityPolicyEgress, nil, "")).Allowed).Should(BeTrue())
		})
		It("Update priority with unexists tier should not allowed", func() {
			policy := securityPolicyIngress.DeepCopy()
			policy.Spec.Tier = "UNExist-Tier-endpointName"
			Expect(validate.Validate(fakeAdmissionReview(policy, securityPolicyIngress, "")).Allowed).Should(BeFalse())
		})
		It("Update priority with unexists EndpointGroup should not allowed", func() {
			policy := securityPolicyIngress.DeepCopy()
			policy.Spec.AppliedTo.EndpointGroups = []string{"UNExist-EndpointGroup-endpointName"}
			Expect(validate.Validate(fakeAdmissionReview(policy, securityPolicyIngress, "")).Allowed).Should(BeFalse())
		})
		It("Update validate priority should allowed", func() {
			Expect(validate.Validate(fakeAdmissionReview(securityPolicyIngress, securityPolicyEgress, "")).Allowed).Should(BeTrue())
			Expect(validate.Validate(fakeAdmissionReview(securityPolicyEgress, securityPolicyIngress, "")).Allowed).Should(BeTrue())
		})
		// Validate on IPBlock
		It("Create policy with error format of IPBlock.CIDR should not allowed", func() {
			policy := securityPolicyIngress.DeepCopy()
			policy.Name = "newPolicy"
			policy.Spec.IngressRules[0].From.IPBlocks[0].CIDR = "0.0.0.0/231"
			Expect(validate.Validate(fakeAdmissionReview(policy, nil, "")).Allowed).Should(BeFalse())
		})
		It("Create policy with error format of IPBlock.Except should not allowed", func() {
			policy := securityPolicyIngress.DeepCopy()
			policy.Name = "newPolicy"
			policy.Spec.IngressRules[0].From.IPBlocks[0].Except = []string{"0.0.0.0/231"}
			Expect(validate.Validate(fakeAdmissionReview(policy, nil, "")).Allowed).Should(BeFalse())
		})
		It("Create policy with IPBlock.CIDR not contains IPBlock.Except should not allowed", func() {
			policy := securityPolicyIngress.DeepCopy()
			policy.Name = "newPolicy"
			policy.Spec.IngressRules[0].From.IPBlocks[0].CIDR = "192.168.0.0/16"

			// cidr mask length > except mask length
			policy.Spec.IngressRules[0].From.IPBlocks[0].Except = []string{"192.168.0.0/14"}
			Expect(validate.Validate(fakeAdmissionReview(policy, nil, "")).Allowed).Should(BeFalse())

			// cidr mask length == except mask length
			policy.Spec.IngressRules[0].From.IPBlocks[0].Except = []string{"192.168.0.0/16"}
			Expect(validate.Validate(fakeAdmissionReview(policy, nil, "")).Allowed).Should(BeFalse())

			// cidr not contains the except cidr range
			policy.Spec.IngressRules[0].From.IPBlocks[0].Except = []string{"192.170.0.0/24"}
			Expect(validate.Validate(fakeAdmissionReview(policy, nil, "")).Allowed).Should(BeFalse())
		})
		It("Create priority with same rule name should not allowed", func() {
			policy := securityPolicyEgress.DeepCopy()
			policy.Name = "newPolicy"
			policy.Spec.EgressRules[1].Name = policy.Spec.EgressRules[0].Name
			Expect(validate.Validate(fakeAdmissionReview(policy, nil, "")).Allowed).Should(BeFalse())
		})
		It("Create priority with wrong format rule name should not allowed", func() {
			policy := securityPolicyEgress.DeepCopy()
			policy.Name = "newPolicy"
			policy.Spec.EgressRules[0].Name = "rule@name#"
			Expect(validate.Validate(fakeAdmissionReview(policy, nil, "")).Allowed).Should(BeFalse())
		})
		It("Delete priority should allows allowed", func() {
			Expect(validate.Validate(fakeAdmissionReview(nil, securityPolicyEgress, "")).Allowed).Should(BeTrue())
			Expect(validate.Validate(fakeAdmissionReview(nil, securityPolicyIngress, "")).Allowed).Should(BeTrue())
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
})
