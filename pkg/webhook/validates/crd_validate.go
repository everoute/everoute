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

package validates

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"

	admv1 "k8s.io/api/admission/v1"
	authv1 "k8s.io/api/authentication/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	metav1validation "k8s.io/apimachinery/pkg/apis/meta/v1/validation"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"sigs.k8s.io/controller-runtime/pkg/client"

	groupv1alpha1 "github.com/everoute/everoute/pkg/apis/group/v1alpha1"
	securityv1alpha1 "github.com/everoute/everoute/pkg/apis/security/v1alpha1"
	"github.com/everoute/everoute/pkg/constants"
	ctrltypes "github.com/everoute/everoute/pkg/controller/types"
	"github.com/everoute/everoute/pkg/labels"
)

// CRDValidate maintains list of validator for validate everoute objects.
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

	// security.everoute.io/v1alpha1 endpoint validator
	v.register(metav1.GroupVersionKind{
		Group:   "security.everoute.io",
		Version: "v1alpha1",
		Kind:    "Endpoint",
	}, &endpointValidator{v.client})

	// group.everoute.io/v1alpha1 endpointgroup validator
	v.register(metav1.GroupVersionKind{
		Group:   "group.everoute.io",
		Version: "v1alpha1",
		Kind:    "EndpointGroup",
	}, &endpointGroupValidator{v.client})

	// security.everoute.io/v1alpha1 securitypolicy validator
	v.register(metav1.GroupVersionKind{
		Group:   "security.everoute.io",
		Version: "v1alpha1",
		Kind:    "SecurityPolicy",
	}, &securityPolicyValidator{v.client})

	// security.everoute.io/v1alpha1 globalpolicy validator
	v.register(metav1.GroupVersionKind{
		Group:   "security.everoute.io",
		Version: "v1alpha1",
		Kind:    "GlobalPolicy",
	}, &globalPolicyValidator{v.client})

	return v
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
	if len(curRaw) != 0 && string(curRaw) != "null" {
		if curObj, err = v.unmarshal(curRaw, gvk); err != nil {
			return &admv1.AdmissionResponse{
				Result: &metav1.Status{
					Message: err.Error(),
				},
			}
		}
	}
	if len(oldRaw) != 0 && string(oldRaw) != "null" {
		if oldObj, err = v.unmarshal(oldRaw, gvk); err != nil {
			return &admv1.AdmissionResponse{
				Result: &metav1.Status{
					Message: err.Error(),
				},
			}
		}
	}

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
	default:
		msg = fmt.Sprintf("unsupported operation %s", operation)
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
	err := v.validateEndpoint(curObj.(*securityv1alpha1.Endpoint))
	if err != nil {
		return err.Error(), false
	}
	return "", true
}

func (v endpointValidator) updateValidate(oldObj, curObj runtime.Object, userInfo authv1.UserInfo) (string, bool) {
	curEndpoint := curObj.(*securityv1alpha1.Endpoint)
	oldEndpoint := oldObj.(*securityv1alpha1.Endpoint)

	if curEndpoint.Spec.Reference != oldEndpoint.Spec.Reference {
		return "update endpoint externalID not allowed", false
	}
	err := v.validateEndpoint(curEndpoint)
	if err != nil {
		return err.Error(), false
	}
	return "", true
}

func (v endpointValidator) deleteValidate(oldObj runtime.Object, userInfo authv1.UserInfo) (string, bool) {
	return "", true
}

func (v *endpointValidator) validateEndpoint(endpoint *securityv1alpha1.Endpoint) error {
	if endpoint.Spec.Reference.ExternalIDName == "" || endpoint.Spec.Reference.ExternalIDValue == "" {
		return fmt.Errorf("endpoint with empty not allowed")
	}
	if strings.ContainsRune(endpoint.Spec.Reference.ExternalIDName, ctrltypes.Separator) {
		return fmt.Errorf("externalIDName contains rune / not allow")
	}
	if strings.ContainsRune(endpoint.Spec.Reference.ExternalIDValue, ctrltypes.Separator) {
		return fmt.Errorf("externalIDValue contains rune / not allow")
	}
	_, err := labels.AsSet(endpoint.Labels, endpoint.Spec.ExtendLabels)
	return err
}

type endpointGroupValidator resourceValidator

func (v endpointGroupValidator) createValidate(curObj runtime.Object, userInfo authv1.UserInfo) (string, bool) {
	var message string

	err := v.validateGroupSpec(&curObj.(*groupv1alpha1.EndpointGroup).Spec)
	if err != nil {
		message = err.Error()
		return message, false
	}

	return "", true
}

func (v endpointGroupValidator) updateValidate(oldObj, curObj runtime.Object, userInfo authv1.UserInfo) (string, bool) {
	var message string

	err := v.validateGroupSpec(&curObj.(*groupv1alpha1.EndpointGroup).Spec)
	if err != nil {
		message = err.Error()
		return message, false
	}

	return "", true
}

func (v endpointGroupValidator) validateGroupSpec(spec *groupv1alpha1.EndpointGroupSpec) error {
	var allErrs field.ErrorList

	if spec.NamespaceSelector != nil && spec.Namespace != nil {
		return fmt.Errorf("NamespaceSelector and Namespace cannot be set at the same time")
	}

	valid, message := spec.EndpointSelector.IsValid()
	if !valid {
		allErrs = append(allErrs, &field.Error{Type: field.ErrorTypeInvalid, Detail: message})
	}

	errs := metav1validation.ValidateLabelSelector(spec.NamespaceSelector,
		metav1validation.LabelSelectorValidationOptions{AllowInvalidLabelValueInSelector: true}, field.NewPath("NamespaceSelector"))
	allErrs = append(allErrs, errs...)

	return allErrs.ToAggregate()
}

func (v endpointGroupValidator) deleteValidate(oldObj runtime.Object, userInfo authv1.UserInfo) (string, bool) {
	return "", true
}

type securityPolicyValidator resourceValidator

func (v securityPolicyValidator) createValidate(curObj runtime.Object, userInfo authv1.UserInfo) (string, bool) {
	err := v.validatePolicy(curObj.(*securityv1alpha1.SecurityPolicy))
	if err != nil {
		return err.Error(), false
	}
	return "", true
}

func (v securityPolicyValidator) updateValidate(oldObj, curObj runtime.Object, userInfo authv1.UserInfo) (string, bool) {
	err := v.validatePolicy(curObj.(*securityv1alpha1.SecurityPolicy))
	if err != nil {
		return err.Error(), false
	}
	return "", true
}

func (v securityPolicyValidator) deleteValidate(oldObj runtime.Object, userInfo authv1.UserInfo) (string, bool) {
	return "", true
}

func (v *securityPolicyValidator) validatePolicy(policy *securityv1alpha1.SecurityPolicy) error {
	// check attached tier exist
	switch policy.Spec.Tier {
	case constants.Tier0, constants.Tier1, constants.Tier2:
	case constants.TierECP:
		if policy.Spec.SecurityPolicyEnforcementMode == securityv1alpha1.MonitorMode {
			return fmt.Errorf("monitor mode doesn't support tier %s", policy.Spec.Tier)
		}
	default:
		return fmt.Errorf("tier %s not in: %s, %s, %s, %s", policy.Spec.Tier, constants.Tier0, constants.Tier1, constants.Tier2, constants.TierECP)
	}

	if policy.Spec.IsBlocklist {
		if policy.Spec.SymmetricMode {
			return fmt.Errorf("blocklist don't support SymmetricMode")
		}
	}

	// check validate of spec.appliedTo
	err := v.validateAppliedTo(policy.Spec.AppliedTo)
	if err != nil {
		return fmt.Errorf("error format of spec.appliedTo: %s", err)
	}

	// checkout validate of Ingress and Egress
	err = v.validateRules(policy.Spec.IngressRules, policy.Spec.EgressRules)
	if err != nil {
		return fmt.Errorf("error format of policy rules: %s", err)
	}

	return nil
}

func (v *securityPolicyValidator) validateAppliedTo(appliedTo []securityv1alpha1.ApplyToPeer) error {
	for _, peer := range appliedTo {
		if peer.Endpoint == nil && peer.EndpointSelector == nil {
			return fmt.Errorf("must specific one of Endpoint or EndpointSelector")
		}
		if peer.Endpoint != nil && peer.EndpointSelector != nil {
			return fmt.Errorf("cannot both set Endpoint and EndpointSelector")
		}
		if peer.Endpoint != nil {
			errs := validation.IsDNS1123Subdomain(*peer.Endpoint)
			if len(errs) != 0 {
				return fmt.Errorf("%s not a available endpoint name", *peer.Endpoint)
			}
		}
		if peer.EndpointSelector != nil {
			valid, message := peer.EndpointSelector.IsValid()
			if !valid {
				return fmt.Errorf("%+v not a available selector: %s", peer.EndpointSelector, message)
			}
		}
	}

	return nil
}

func (v *securityPolicyValidator) validateRules(ingress, egress []securityv1alpha1.Rule) error {
	err := v.validateRuleName(ingress, egress)
	if err != nil {
		return fmt.Errorf("validate rules name: %s", err)
	}

	ruleList := append(ingress, egress...)
	errList := make([]error, 0, len(ruleList))

	for item := range ruleList {
		if err = v.validateRule(&ruleList[item]); err != nil {
			errList = append(errList, fmt.Errorf("validate rule %s: %s", ruleList[item].Name, err))
		}
	}
	return errors.NewAggregate(errList)
}

// validateRule validates if the rule with validate value
func (v *securityPolicyValidator) validateRule(rule *securityv1alpha1.Rule) error {
	rulePeerList := append(rule.From, rule.To...)
	// fix: size computation for allocation may overflow
	ruleErrList := make([]error, 0, len(rulePeerList))
	portErrList := make([]error, 0, len(rule.Ports))

	for item := range rulePeerList {
		err := v.validateRulePeer(&rulePeerList[item])
		if err != nil {
			ruleErrList = append(ruleErrList,
				fmt.Errorf("error format of peer %+v: %s", rulePeerList[item], err),
			)
		}
	}

	for item := range rule.Ports {
		err := v.validatePort(&rule.Ports[item])
		if err != nil {
			portErrList = append(portErrList,
				fmt.Errorf("error format of port %+v: %s", rule.Ports[item], err),
			)
		}
	}

	if len(ruleErrList)+len(portErrList) != 0 {
		return errors.NewAggregate(append(ruleErrList, portErrList...))
	}
	return nil
}

func (v *securityPolicyValidator) validateRulePeer(peer *securityv1alpha1.SecurityPolicyPeer) error {
	if peer.IPBlock != nil {
		if peer.Endpoint != nil || peer.EndpointSelector != nil || peer.NamespaceSelector != nil {
			return fmt.Errorf("ipBlock is set then neither of the other fields can be")
		}
		if err := validateIPBlock(*peer.IPBlock); err != nil {
			return fmt.Errorf("error format of ipBlock %+v: %s", peer.IPBlock, err)
		}
		return nil
	}

	if peer.Endpoint != nil {
		if peer.IPBlock != nil || peer.EndpointSelector != nil || peer.NamespaceSelector != nil {
			return fmt.Errorf("endpoint is set then neither of the other fields can be")
		}
		es1 := validation.IsDNS1123Subdomain(peer.Endpoint.Name)
		es2 := validation.IsDNS1123Subdomain(peer.Endpoint.Namespace)
		if len(es1)+len(es2) != 0 {
			return fmt.Errorf("%+v not a available endpoint", peer.Endpoint)
		}
		return nil
	}

	if peer.EndpointSelector == nil && peer.NamespaceSelector == nil {
		return fmt.Errorf("at least one field should be set in SecurityPolicyPeer")
	}

	valid, message := peer.EndpointSelector.IsValid()
	if !valid {
		return fmt.Errorf("%+v not a available selector: %s", peer.EndpointSelector, message)
	}

	if peer.NamespaceSelector != nil {
		errs := metav1validation.ValidateLabelSelector(peer.NamespaceSelector,
			metav1validation.LabelSelectorValidationOptions{AllowInvalidLabelValueInSelector: true}, field.NewPath("NamespaceSelector"))
		if len(errs) != 0 {
			return fmt.Errorf("%+v not a available selector: %+v", peer.NamespaceSelector, errs)
		}
	}

	return nil
}

func (v *securityPolicyValidator) validatePort(port *securityv1alpha1.SecurityPolicyPort) error {
	// Only validate PortRange, port.Protocol and port.Type validate by crd
	if port.Type != securityv1alpha1.PortTypeName {
		return v.validatePortRange(port.PortRange)
	}
	return nil
}

func (v *securityPolicyValidator) validatePortRange(portRange string) error {
	const (
		emptyPort    = `^$`
		singlePort   = `^(\d{1,5})$`
		rangePort    = `^(\d{1,5}-\d{1,5})$`
		multiplePort = `^(((\d{1,5}-\d{1,5})|(\d{1,5})),)*((\d{1,5}-\d{1,5})|(\d{1,5}))$`
	)

	switch {
	case regexp.MustCompile(emptyPort).Match([]byte(portRange)):
		return nil
	case regexp.MustCompile(singlePort).Match([]byte(portRange)):
		port, _ := strconv.Atoi(portRange)
		if port < 0 || port > 65535 {
			return fmt.Errorf("port supported must between 0 and 65535")
		}
	case regexp.MustCompile(rangePort).Match([]byte(portRange)):
		portBegin, _ := strconv.Atoi(strings.Split(portRange, "-")[0])
		portEnd, _ := strconv.Atoi(strings.Split(portRange, "-")[1])

		if portBegin < 0 || portBegin > 65535 || portEnd < 0 || portEnd > 65535 {
			return fmt.Errorf("port supported must between 0 and 65535")
		}

		if portBegin > portEnd {
			return fmt.Errorf("port begin %d is bigger than end %d", portBegin, portEnd)
		}
	case regexp.MustCompile(multiplePort).Match([]byte(portRange)):
		for _, subPortRange := range strings.Split(portRange, ",") {
			if err := v.validatePortRange(subPortRange); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("unsupport format of portrange")
	}

	return nil
}

// validateRuleName validates if the name of each rule is unique within a policy and if rule name
// conforms RFC 1123.
func (v *securityPolicyValidator) validateRuleName(ingress, egress []securityv1alpha1.Rule) error {
	var uniqueRuleName = sets.NewString()

	for _, rule := range append(ingress, egress...) {
		if uniqueRuleName.Has(rule.Name) {
			return fmt.Errorf("rule name %s appears more than twice", rule.Name)
		}

		errs := validation.IsDNS1123Subdomain(rule.Name)
		if len(errs) != 0 {
			return fmt.Errorf("rule name %s not conforms RFC 1123", rule.Name)
		}

		uniqueRuleName.Insert(rule.Name)
	}

	return nil
}

type globalPolicyValidator resourceValidator

func (v globalPolicyValidator) createValidate(curObj runtime.Object, userInfo authv1.UserInfo) (string, bool) {
	policy := curObj.(*securityv1alpha1.GlobalPolicy)
	policyList := securityv1alpha1.GlobalPolicyList{}

	if err := v.List(context.Background(), &policyList); err != nil {
		return err.Error(), false
	}

	switch len(policyList.Items) {
	case 1:
		if policyList.Items[0].Name != policy.Name {
			return "cannot create multiple global policies", false
		}

		// Two situations can lead to create GlobalPolicy with name already exist:
		// 1. GlobalPolicy with this name already delete, but local cache havenot sync yet.
		// 2. Due to retry create (e.g. kubectl apply always try to create resource first).
		// In both cases, we should keep quiet. And leave to handle by apiserver.
		fallthrough
	case 0:
		return "", true
	default:
		return "cannot create multiple global policies", false
	}
}

func (v globalPolicyValidator) updateValidate(oldObj, curObj runtime.Object, userInfo authv1.UserInfo) (string, bool) {
	return "", true
}

func (v globalPolicyValidator) deleteValidate(oldObj runtime.Object, userInfo authv1.UserInfo) (string, bool) {
	return "", true
}

func validateIPBlock(ipBlock networkingv1.IPBlock) error {
	_, cidrIPNet, err := net.ParseCIDR(ipBlock.CIDR)
	if err != nil {
		return fmt.Errorf("unvalid cidr %s: %s", ipBlock.CIDR, err)
	}

	for _, exceptCIDR := range ipBlock.Except {
		_, exceptIPNet, err := net.ParseCIDR(exceptCIDR)
		if err != nil {
			return fmt.Errorf("unvalid except cidr %s: %s", exceptCIDR, err)
		}

		cidrMaskLen, _ := cidrIPNet.Mask.Size()
		exceptMaskLen, _ := exceptIPNet.Mask.Size()

		if !cidrIPNet.Contains(exceptIPNet.IP) || cidrMaskLen >= exceptMaskLen {
			return fmt.Errorf("cidr %s not contains except %s", ipBlock.CIDR, exceptCIDR)
		}
	}

	return nil
}
