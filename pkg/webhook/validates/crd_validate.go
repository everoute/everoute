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

package validates

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	admv1 "k8s.io/api/admission/v1"
	authv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	metav1validation "k8s.io/apimachinery/pkg/apis/meta/v1/validation"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/klog"
	"sigs.k8s.io/controller-runtime/pkg/client"

	groupv1alpha1 "github.com/smartxworks/lynx/pkg/apis/group/v1alpha1"
	securityv1alpha1 "github.com/smartxworks/lynx/pkg/apis/security/v1alpha1"
	ctrltypes "github.com/smartxworks/lynx/pkg/controller/types"
)

// CRDValidate maintains list of validator for validate lynx objects.
type CRDValidate struct {
	client   client.Client
	scheme   *runtime.Scheme
	validate map[metav1.GroupVersionKind][]validator
}

// NewCRDValidate return a new *CRDValidate and register validators.
func NewCRDValidate(client client.Client, scheme *runtime.Scheme) *CRDValidate {
	v := &CRDValidate{
		client:   client,
		scheme:   scheme,
		validate: make(map[metav1.GroupVersionKind][]validator),
	}

	// security.lynx.smartx.com/v1alpha1 endpoint validator
	v.register(metav1.GroupVersionKind{
		Group:   "security.lynx.smartx.com",
		Version: "v1alpha1",
		Kind:    "Endpoint",
	}, &endpointValidator{v.client})

	// group.lynx.smartx.com/v1alpha1 endpointgroup validator
	v.register(metav1.GroupVersionKind{
		Group:   "group.lynx.smartx.com",
		Version: "v1alpha1",
		Kind:    "EndpointGroup",
	}, &endpointGroupValidator{v.client})

	// security.lynx.smartx.com/v1alpha1 securitypolicy validator
	v.register(metav1.GroupVersionKind{
		Group:   "security.lynx.smartx.com",
		Version: "v1alpha1",
		Kind:    "SecurityPolicy",
	}, &securityPolicyValidator{v.client})

	// security.lynx.smartx.com/v1alpha1 tier validator
	v.register(metav1.GroupVersionKind{
		Group:   "security.lynx.smartx.com",
		Version: "v1alpha1",
		Kind:    "Tier",
	}, &tierValidator{v.client})

	return v
}

const (
	tierPriorityIndex        = "TierPriorityIndex"
	policyTierIndex          = "PolicyTierIndex"
	policyEndpointGroupIndex = "PolicyEndpointGroupIndex"

	matchIPV4 = `^((([1]?\d)?\d|2[0-4]\d|25[0-5])\.){3}(([1]?\d)?\d|2[0-4]\d|25[0-5])$`
)

// RegisterIndexFields register custom fields for FieldIndexer, this field
// can later be used by a field selector.
func RegisterIndexFields(f client.FieldIndexer) error {
	ctx := context.Background()

	// index priority in Tier object
	f.IndexField(ctx, &securityv1alpha1.Tier{}, tierPriorityIndex, func(object runtime.Object) []string {
		return []string{fmt.Sprintf("%d", object.(*securityv1alpha1.Tier).Spec.Priority)}
	})

	// index tier in SecurityPolicy object
	f.IndexField(ctx, &securityv1alpha1.SecurityPolicy{}, policyTierIndex, func(object runtime.Object) []string {
		return []string{object.(*securityv1alpha1.SecurityPolicy).Spec.Tier}
	})

	// index endpointGroup in SecurityPolicy object
	f.IndexField(ctx, &securityv1alpha1.SecurityPolicy{}, policyEndpointGroupIndex, func(object runtime.Object) []string {
		policy := object.(*securityv1alpha1.SecurityPolicy)
		groups := sets.NewString(policy.Spec.AppliedToEndpointGroups...)

		for _, rule := range append(policy.Spec.IngressRules, policy.Spec.EgressRules...) {
			groups.Insert(rule.From.EndpointGroups...)
			groups.Insert(rule.To.EndpointGroups...)
		}
		return groups.List()
	})

	return nil
}

// validator interface introduces the set of functions that must be implemented
// by any resource validator.
// see https://github.com/vmware-tanzu/antrea/blob/v0.12.0/pkg/controller/networkpolicy/validate.go#L36
type validator interface {
	// createValidate is the interface which must be satisfied for resource
	// CREATE events.
	createValidate(curObj runtime.Object, userInfo authv1.UserInfo) (string, bool)
	// updateValidate is the interface which must be satisfied for resource
	// UPDATE events.
	updateValidate(oldObj, curObj runtime.Object, userInfo authv1.UserInfo) (string, bool)
	// deleteValidate is the interface which must be satisfied for resource
	// DELETE events.
	deleteValidate(oldObj runtime.Object, userInfo authv1.UserInfo) (string, bool)
}

// Validate read AdmissionReview request, return AdmissionResponse
func (v *CRDValidate) Validate(ar *admv1.AdmissionReview) *admv1.AdmissionResponse {
	var result *metav1.Status
	var msg string
	var curObj, oldObj runtime.Object
	var err error

	// default allowed all validate admission, unless one of the validators return
	// false or some error when process.
	allowed := true
	operation := ar.Request.Operation
	curRaw := ar.Request.Object.Raw
	oldRaw := ar.Request.OldObject.Raw
	gvk := ar.Request.Kind

	// unmarshal object
	if len(curRaw) != 0 {
		if curObj, err = v.unmarshal(curRaw, gvk); err != nil {
			klog.Errorf("failed to unmarshal object %s, raw: %s", gvk, curRaw)
			return &admv1.AdmissionResponse{
				Result: &metav1.Status{
					Message: err.Error(),
				},
			}
		}
	}
	if len(oldRaw) != 0 {
		if oldObj, err = v.unmarshal(oldRaw, gvk); err != nil {
			klog.Errorf("failed to unmarshal object %s, raw: %s", gvk, oldRaw)
			return &admv1.AdmissionResponse{
				Result: &metav1.Status{
					Message: err.Error(),
				},
			}
		}
	}

	klog.V(2).Infof("validate operation %s of object %s", operation, gvk.String())
	switch operation {
	case admv1.Create:
		for _, validator := range v.validate[gvk] {
			msg, allowed = validator.createValidate(curObj, ar.Request.UserInfo)
			if !allowed {
				break
			}
		}
	case admv1.Update:
		for _, validator := range v.validate[gvk] {
			msg, allowed = validator.updateValidate(oldObj, curObj, ar.Request.UserInfo)
			if !allowed {
				break
			}
		}
	case admv1.Delete:
		for _, validator := range v.validate[gvk] {
			msg, allowed = validator.deleteValidate(oldObj, ar.Request.UserInfo)
			if !allowed {
				break
			}
		}
	}

	if !allowed && msg != "" {
		klog.Errorf("unallow to %s objects %s: %s", operation, gvk, msg)
	}

	if msg != "" {
		result = &metav1.Status{
			Message: msg,
		}
	}
	return &admv1.AdmissionResponse{
		Allowed: allowed,
		Result:  result,
	}
}

// unmarshal object from raw to runtime.Object.
func (v *CRDValidate) unmarshal(raw []byte, gvk metav1.GroupVersionKind) (runtime.Object, error) {
	obj, err := v.scheme.New(schema.GroupVersionKind{
		Group:   gvk.Group,
		Version: gvk.Version,
		Kind:    gvk.Kind,
	})
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(raw, obj); err != nil {
		return nil, err
	}
	return obj, nil
}

func (v *CRDValidate) register(kind metav1.GroupVersionKind, t validator) {
	v.validate[kind] = append(v.validate[kind], t)
}

// resourceValidator provides struct for reference implement the validator interface.
type resourceValidator struct {
	client.Client
}

type endpointValidator resourceValidator

func (v endpointValidator) createValidate(curObj runtime.Object, userInfo authv1.UserInfo) (string, bool) {
	endpoint := curObj.(*securityv1alpha1.Endpoint)

	if endpoint.Spec.ExternalIDName == "" || endpoint.Spec.ExternalIDValue == "" {
		return "create endpoint with empty id not allowed", false
	}

	if strings.ContainsRune(endpoint.Spec.ExternalIDName, ctrltypes.Separator) {
		return "externalIDName contains rune / not allow", false
	}
	if strings.ContainsRune(endpoint.Spec.ExternalIDValue, ctrltypes.Separator) {
		return "externalIDValue contains rune / not allow", false
	}

	return "", true
}

func (v endpointValidator) updateValidate(oldObj, curObj runtime.Object, userInfo authv1.UserInfo) (string, bool) {
	curEndpoint := curObj.(*securityv1alpha1.Endpoint)
	oldEndpoint := oldObj.(*securityv1alpha1.Endpoint)

	if curEndpoint.Spec != oldEndpoint.Spec {
		return "update endpoint externalID not allowed", false
	}
	return "", true
}

func (v endpointValidator) deleteValidate(oldObj runtime.Object, userInfo authv1.UserInfo) (string, bool) {
	return "", true
}

type endpointGroupValidator resourceValidator

func (v endpointGroupValidator) createValidate(curObj runtime.Object, userInfo authv1.UserInfo) (string, bool) {
	var allErrs field.ErrorList

	// validate label selector
	allErrs = v.validateSelector(curObj.(*groupv1alpha1.EndpointGroup).Spec.Selector)

	if err := allErrs.ToAggregate(); err != nil {
		return err.Error(), false
	}
	return "", true
}

func (v endpointGroupValidator) updateValidate(oldObj, curObj runtime.Object, userInfo authv1.UserInfo) (string, bool) {
	var allErrs field.ErrorList

	// validate label selector
	allErrs = v.validateSelector(curObj.(*groupv1alpha1.EndpointGroup).Spec.Selector)

	if err := allErrs.ToAggregate(); err != nil {
		return err.Error(), false
	}
	return "", true
}

func (v endpointGroupValidator) validateSelector(selector *metav1.LabelSelector) field.ErrorList {
	return metav1validation.ValidateLabelSelector(selector, field.NewPath("selector"))
}

func (v endpointGroupValidator) deleteValidate(oldObj runtime.Object, userInfo authv1.UserInfo) (string, bool) {
	policyList := securityv1alpha1.SecurityPolicyList{}

	if err := v.List(context.Background(), &policyList, client.MatchingFields{
		policyEndpointGroupIndex: oldObj.(*groupv1alpha1.EndpointGroup).Name,
	}); err != nil {
		return err.Error(), false
	}

	if len(policyList.Items) != 0 {
		return "delete EndpointGroup used by security policy not allowed", false
	}
	return "", true
}

type tierValidator resourceValidator

func (t tierValidator) createValidate(curObj runtime.Object, userInfo authv1.UserInfo) (string, bool) {
	tierList := securityv1alpha1.TierList{}

	if err := t.List(context.Background(), &tierList, client.MatchingFields{
		tierPriorityIndex: fmt.Sprintf("%d", curObj.(*securityv1alpha1.Tier).Spec.Priority),
	}); err != nil {
		return err.Error(), false
	}

	if len(tierList.Items) != 0 {
		return "create tier with same priority not allowed", false
	}
	return "", true
}

func (t tierValidator) updateValidate(oldObj, curObj runtime.Object, userInfo authv1.UserInfo) (string, bool) {
	if oldObj.(*securityv1alpha1.Tier).Spec.Priority != curObj.(*securityv1alpha1.Tier).Spec.Priority {
		return "update tier priority not allowed", false
	}
	return "", true
}

func (t tierValidator) deleteValidate(oldObj runtime.Object, userInfo authv1.UserInfo) (string, bool) {
	policyList := securityv1alpha1.SecurityPolicyList{}

	if err := t.List(context.Background(), &policyList, client.MatchingFields{
		policyTierIndex: oldObj.(*securityv1alpha1.Tier).Name,
	}); err != nil {
		return err.Error(), false
	}

	if len(policyList.Items) != 0 {
		return "delete tier used by security policy not allowed", false
	}
	return "", true
}

type securityPolicyValidator resourceValidator

func (v securityPolicyValidator) createValidate(curObj runtime.Object, userInfo authv1.UserInfo) (string, bool) {
	policy := curObj.(*securityv1alpha1.SecurityPolicy)
	groups := sets.NewString(policy.Spec.AppliedToEndpointGroups...)

	if len(groups) == 0 {
		return fmt.Sprintf("at least one group should specified for policy applied to"), false
	}

	// all groups must exists before security policy create
	for _, rule := range append(policy.Spec.IngressRules, policy.Spec.EgressRules...) {
		groups.Insert(rule.From.EndpointGroups...)
		groups.Insert(rule.To.EndpointGroups...)
	}
	for groupName := range groups {
		endpointGroup := groupv1alpha1.EndpointGroup{}
		if err := v.Get(context.Background(), types.NamespacedName{Name: groupName}, &endpointGroup); err != nil {
			return fmt.Sprintf("endpointGroup must create first: %s", err.Error()), false
		}
	}

	// tier must exists before security policy create
	tier := securityv1alpha1.Tier{}
	if err := v.Get(context.Background(), types.NamespacedName{Name: policy.Spec.Tier}, &tier); err != nil {
		return fmt.Sprintf("tier must create first: %s", err.Error()), false
	}

	// should has difference rule name in egress and ingress, rule name must not empty
	if !v.validateRuleName(policy.Spec.IngressRules, policy.Spec.EgressRules) {
		return fmt.Sprint("rules names must be unique within the policy and not empty"), false
	}

	// rule must complies validate values
	for _, rule := range append(policy.Spec.IngressRules, policy.Spec.EgressRules...) {
		if err := v.validateRule(rule); err != nil {
			return fmt.Sprintf("rule %s: %s", rule.Name, err.Error()), false
		}
	}

	return "", true
}

// validateRule validates if the rule with validate value
func (v *securityPolicyValidator) validateRule(rule securityv1alpha1.Rule) error {
	// match ip address
	for _, ipBlock := range append(rule.From.IPBlocks, rule.To.IPBlocks...) {
		ipv4 := false
		if regexp.MustCompile(matchIPV4).Match([]byte(ipBlock.IP)) {
			ipv4 = true
		}
		if ipv4 {
			if !(ipBlock.PrefixLength <= 32 && ipBlock.PrefixLength >= 0) {
				return fmt.Errorf("PrefixLength for ipv4 must between 0-32")
			}
		} else {
			if !(ipBlock.PrefixLength <= 128 && ipBlock.PrefixLength >= 0) {
				return fmt.Errorf("PrefixLength for ipv6 must between 0-128")
			}
		}
	}

	if len(rule.Ports) == 0 {
		return fmt.Errorf("rule field Ports must not empty slice")
	}

	for _, port := range rule.Ports {
		err := v.validatePortRange(port.PortRange)
		if err != nil {
			return fmt.Errorf("PortRange %s with error format: %s", port.PortRange, err)
		}
	}

	return nil
}

func (v *securityPolicyValidator) validatePortRange(portRange string) error {
	const emptyPort = `^$`
	const singlePort = `^(\d{1,5})$`
	const multiplePort = `^(\d{1,5}-\d{1,5})$`

	switch {
	case regexp.MustCompile(emptyPort).Match([]byte(portRange)):
		return nil
	case regexp.MustCompile(singlePort).Match([]byte(portRange)):
		port, _ := strconv.Atoi(portRange)
		if port < 0 || port > 65535 {
			return fmt.Errorf("port supported must between 0 and 65535")
		}
	case regexp.MustCompile(multiplePort).Match([]byte(portRange)):
		portBegin, _ := strconv.Atoi(strings.Split(portRange, "-")[0])
		portEnd, _ := strconv.Atoi(strings.Split(portRange, "-")[1])

		if portBegin < 0 || portBegin > 65535 || portEnd < 0 || portEnd > 65535 {
			return fmt.Errorf("port supported must between 0 and 65535")
		}

		if portBegin > portEnd {
			return fmt.Errorf("port begin %d is bigger than end %d", portBegin, portEnd)
		}
	default:
		return fmt.Errorf("unsupport format of portrange")
	}

	return nil
}

// validateRuleName validates if the name of each rule is unique within a policy and not empty
func (v *securityPolicyValidator) validateRuleName(ingress, egress []securityv1alpha1.Rule) bool {
	uniqueRuleName := sets.NewString()
	isUnique := func(rules []securityv1alpha1.Rule) bool {
		for _, rule := range rules {
			if uniqueRuleName.Has(rule.Name) || rule.Name == "" {
				return false
			}
			uniqueRuleName.Insert(rule.Name)
		}
		return true
	}
	return isUnique(ingress) && isUnique(egress)
}

func (v securityPolicyValidator) updateValidate(oldObj, curObj runtime.Object, userInfo authv1.UserInfo) (string, bool) {
	// update security policy should limit as create security policy
	return v.createValidate(curObj, userInfo)
}

func (v securityPolicyValidator) deleteValidate(oldObj runtime.Object, userInfo authv1.UserInfo) (string, bool) {
	return "", true
}
