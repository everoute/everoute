/*
Copyright 2021 The Lynx authors.

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

package v1alpha1

import (
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8stypes "k8s.io/apimachinery/pkg/types"

	"github.com/smartxworks/lynx/pkg/types"
)

// +genclient
// +k8s:openapi-gen=true
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// SecurityPolicy describes what network traffic is allowed for a set of Endpoint.
// Follow NetworkPolicy https://github.com/kubernetes/api/blob/v0.22.1/networking/v1/types.go#L29.
type SecurityPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Specification of the desired behavior for this SecurityPolicy.
	Spec SecurityPolicySpec `json:"spec"`
}

type SecurityPolicySpec struct {
	// Tier specifies the tier to which this SecurityPolicy belongs to.
	// In v1alpha1, Tier only support tier0, tier1, tier2.
	Tier string `json:"tier"`

	// SymmetricMode will generate symmetry rules for the policy.
	// Defaults to false.
	SymmetricMode bool `json:"symmetricMode,omitempty"`

	// Selects the endpoints to which this SecurityPolicy object applies. This field
	// must not empty.
	AppliedTo []ApplyToPeer `json:"appliedTo"`

	// List of ingress rules to be applied to the selected endpoints. If this field
	// is empty then this SecurityPolicy does not allow any traffic.
	// +optional
	IngressRules []Rule `json:"ingressRules,omitempty"`

	// List of egress rules to be applied to the selected endpoints. If this field
	// is empty then this SecurityPolicy limits all outgoing traffic.
	// +optional
	EgressRules []Rule `json:"egressRules,omitempty"`

	// List of rule types that the Security relates to.
	// Valid options are "Ingress", "Egress", or "Ingress,Egress".
	// If this field is not specified, it will default based on the existence of Ingress or Egress rules;
	// policies that contain an Egress section are assumed to affect Egress, and all policies
	// (whether or not they contain an Ingress section) are assumed to affect Ingress.
	// If you want to write an egress-only policy, you must explicitly specify policyTypes [ "Egress" ].
	// Likewise, if you want to write a policy that specifies that no egress is allowed,
	// you must specify a policyTypes value that include "Egress" (since such a policy would not include
	// an Egress section and would otherwise default to just [ "Ingress" ]).
	// +optional
	PolicyTypes []networkingv1.PolicyType `json:"policyTypes,omitempty"`
}

// ApplyToPeer describes sets of endpoints which this SecurityPolicy object applies
// At least one field (Endpoint or EndpointSelector) should be set.
type ApplyToPeer struct {
	// Endpoint defines policy on a specific Endpoint.
	//
	// If Endpoint is set, then the SecurityPolicy would apply to the endpoint
	// in the SecurityPolicy Namespace. If Endpoint doesnot exist OR has empty
	// IPAddr, the ApplyToPeer would be ignored.
	// If this field is set then neither of the other fields can be.
	// +optional
	Endpoint *string `json:"endpoint,omitempty"`

	// EndpointSelector selects endpoints. This field follows standard label
	// selector semantics; if present but empty, it selects all endpoints.
	//
	// If EndpointSelector is set, then the SecurityPolicy would apply to the
	// endpoints matching EndpointSelector in the SecurityPolicy Namespace.
	// If this field is set then neither of the other fields can be.
	// +optional
	EndpointSelector *metav1.LabelSelector `json:"endpointSelector,omitempty"`
}

// Rule describes a particular set of traffic that is allowed from/to the endpoints
// matched by a SecurityPolicySpec's AppliedTo.
type Rule struct {
	// Name must be unique within the policy and conforms RFC 1123.
	Name string `json:"name"`

	// List of ports which should be made accessible on the endpoints selected for this
	// rule. Each item in this list is combined using a logical OR. If this field is
	// empty or missing, this rule matches all ports (traffic not restricted by port).
	// If this field is present and contains at least one item, then this rule allows
	// traffic only if the traffic matches at least one port in the list.
	// +optional
	Ports []SecurityPolicyPort `json:"ports,omitempty"`

	// List of sources which should be able to access the endpoints selected for this rule.
	// Items in this list are combined using a logical OR operation. If this field is
	// empty or missing, this rule matches all sources (traffic not restricted by
	// source). If this field is present and contains at least one item, this rule
	// allows traffic only if the traffic matches at least one item in the from list.
	// This field only works when rule is ingress.
	// +optional
	From []SecurityPolicyPeer `json:"from,omitempty"`

	// List of destinations for outgoing traffic of endpoints selected for this rule.
	// Items in this list are combined using a logical OR operation. If this field is
	// empty or missing, this rule matches all destinations (traffic not restricted by
	// destination). If this field is present and contains at least one item, this rule
	// allows traffic only if the traffic matches at least one item in the to list.
	// This field only works when rule is egress.
	// +optional
	To []SecurityPolicyPeer `json:"to,omitempty"`
}

// SecurityPolicyPeer describes a peer to allow traffic to/from. Only certain combinations
// of fields are allowed
type SecurityPolicyPeer struct {
	// IPBlock defines policy on a particular IPBlock. If this field is set then
	// neither of the other fields can be.
	// +optional
	IPBlock *networkingv1.IPBlock `json:"ipBlock,omitempty"`

	// Endpoint defines policy on a specific Endpoint. If this field is set then
	// neither of the other fields can be.
	// +optional
	Endpoint *NamespacedName `json:"endpoint,omitempty"`

	// EndpointSelector selects endpoints. This field follows standard label
	// selector semantics; if present but empty, it selects all endpoints.
	//
	// If NamespaceSelector is also set, then the Rule would select the endpoints
	// matching EndpointSelector in the Namespaces selected by NamespaceSelector.
	// Otherwise, it selects the Endpoints matching EndpointSelector in the policy's own Namespace.
	// +optional
	EndpointSelector *metav1.LabelSelector `json:"endpointSelector,omitempty"`

	// NamespaceSelector selects namespaces. This field follows standard label
	// selector semantics; if present but empty, it selects all namespaces.
	//
	// If EndpointSelector is also set, then the Rule would select the endpoints
	// matching EndpointSelector in the Namespaces selected by NamespaceSelector.
	// Otherwise, it selects all Endpoints in the Namespaces selected by NamespaceSelector.
	// +optional
	NamespaceSelector *metav1.LabelSelector `json:"namespaceSelector,omitempty"`
}

// SecurityPolicyPort describes the port and protocol to match in a rule.
type SecurityPolicyPort struct {
	// The protocol (TCP, UDP or ICMP) which traffic must match.
	Protocol Protocol `json:"protocol"`

	// PortRange is a range of port. If you want match all ports, you should set empty. If you
	// want match single port, you should write like 22. If you want match a range of port, you
	// should write like 20-80, ports between 20 and 80 (include 20 and 80) will matches. If you
	// want match multiple ports, you should write like 20,22-24,90.
	// +kubebuilder:validation:Pattern="^(((\\d{1,5}-\\d{1,5})|(\\d{1,5})),)*((\\d{1,5}-\\d{1,5})|(\\d{1,5}))$|^$"
	PortRange string `json:"portRange,omitempty"` // only valid when Protocol is not ICMP
}

type NamespacedName struct {
	// Name is unique within a namespace to reference a resource.
	Name string `json:"name"`
	// Namespace defines the space within which the resource name must be unique.
	Namespace string `json:"namespace"`
}

// String returns the general purpose string representation
func (n NamespacedName) String() string {
	return n.Namespace + string(k8stypes.Separator) + n.Name
}

// +kubebuilder:validation:Enum=TCP;UDP;ICMP
type Protocol string

const (
	// ProtocolTCP is the TCP protocol.
	ProtocolTCP Protocol = "TCP"
	// ProtocolUDP is the UDP protocol.
	ProtocolUDP Protocol = "UDP"
	// ProtocolICMP is the ICMP protocol.
	ProtocolICMP Protocol = "ICMP"
)

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// SecurityPolicyList contains a list of SecurityPolicy
type SecurityPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []SecurityPolicy `json:"items"`
}

// +genclient
// +genclient:nonNamespaced
// +genclient:noStatus
// +k8s:openapi-gen=true
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Cluster

type Tier struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec TierSpec `json:"spec"`
}

type TierSpec struct {
	// Description is an optional field to add more information regarding
	// the purpose of this Tier.
	Description string `json:"description,omitempty"`

	Priority int32    `json:"priority"`
	TierMode TierMode `json:"tierMode"`
}

// +kubebuilder:validation:Enum=Whitelist;Blacklist
type TierMode string

const (
	TierWhiteList TierMode = "Whitelist"
	TierBlackList TierMode = "Blacklist"
)

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// TierList contains a list of Tier
type TierList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Tier `json:"items"`
}

// +genclient
// +k8s:openapi-gen=true
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

type Endpoint struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   EndpointSpec   `json:"spec"`
	Status EndpointStatus `json:"status,omitempty"`
}

type EndpointSpec struct {
	VID       uint32            `json:"vid"`
	Reference EndpointReference `json:"reference"`
}

type EndpointReference struct {
	ExternalIDName  string `json:"externalIDName"`
	ExternalIDValue string `json:"externalIDValue"`
}

type EndpointStatus struct {
	IPs        []types.IPAddress `json:"ips,omitempty"`
	MacAddress string            `json:"macAddress,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// EndpointList contains a list of Endpoint
type EndpointList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Endpoint `json:"items"`
}

// +genclient
// +genclient:nonNamespaced
// +genclient:noStatus
// +k8s:openapi-gen=true
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Cluster

// GlobalPolicy allow defines default action of traffics and global
// ip whitelist. Only one GlobalPolicy can exist on kubernetes.
type GlobalPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec GlobalPolicySpec `json:"spec,omitempty"`
}

type GlobalPolicySpec struct {
	// DefaultAction defines global traffic action
	// +optional
	// +kubebuilder:default="Allow"
	DefaultAction GlobalDefaultAction `json:"defaultAction,omitempty"`

	// Whitelist defines IPBlocks than always allow traffics.
	// +optional
	Whitelist []networkingv1.IPBlock `json:"whitelist,omitempty"`
}

// +kubebuilder:validation:Enum=Allow;Drop
type GlobalDefaultAction string

const (
	GlobalDefaultActionAllow GlobalDefaultAction = "Allow"
	GlobalDefaultActionDrop  GlobalDefaultAction = "Drop"
)

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type GlobalPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []GlobalPolicy `json:"items"`
}
