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

package v1alpha1

import (
	"strings"

	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8stypes "k8s.io/apimachinery/pkg/types"

	"github.com/everoute/everoute/pkg/labels"
	"github.com/everoute/everoute/pkg/types"
)

type PolicyMode string

const (
	WorkMode    PolicyMode = "work"
	MonitorMode PolicyMode = "monitor"
)

// +genclient
// +k8s:openapi-gen=true
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="IsBlocklist",type="boolean",JSONPath=".spec.isBlocklist"
// +kubebuilder:printcolumn:name="Tier",type="string",JSONPath=".spec.tier"
// +kubebuilder:printcolumn:name="Priority",type="integer",JSONPath=".spec.priority"
// +kubebuilder:printcolumn:name="SymmetricMode",type="boolean",JSONPath=".spec.symmetricMode"
// +kubebuilder:printcolumn:name="PolicyTypes",type="string",JSONPath=".spec.policyTypes"
// +kubebuilder:printcolumn:name="Enforcement",type="string",JSONPath=".spec.securityPolicyEnforcementMode"

// SecurityPolicy describes what network traffic is allowed for a set of Endpoint.
// Follow NetworkPolicy https://github.com/kubernetes/api/blob/v0.22.1/networking/v1/types.go#L29.
type SecurityPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Specification of the desired behavior for this SecurityPolicy.
	Spec SecurityPolicySpec `json:"spec"`
}

// DefaultRuleType defines default rule type inSecurityPolicy.
// +kubebuilder:validation:Enum=drop;allow;none
type DefaultRuleType string

const (
	// DefaultRuleDrop will generate default drop for SecurityPolicy.
	DefaultRuleDrop DefaultRuleType = "drop"
	// DefaultRuleAllow will generate default allow for SecurityPolicy.
	DefaultRuleAllow DefaultRuleType = "allow"
	// DefaultRuleNone will not generate default rule for SecurityPolicy.
	DefaultRuleNone DefaultRuleType = "none"
)

// SecurityPolicySpec provides the specification of a SecurityPolicy
type SecurityPolicySpec struct {
	// Tier specifies the tier to which this SecurityPolicy belongs to.
	// In v1alpha1, Tier only support tier0, tier1, tier2, tier-ecp.
	Tier string `json:"tier"`

	// Priority Specifies the priority of the SecurityPolicy on the tier to which it belongs
	// Defaults is 0
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=100
	Priority int32 `json:"priority,omitempty"`

	// Work mode specify the policy enforcement state: monitor or work
	// +kubebuilder:default=work
	SecurityPolicyEnforcementMode PolicyMode `json:"securityPolicyEnforcementMode,omitempty"`

	// SymmetricMode will generate symmetry rules for the policy.
	// Defaults to false.
	SymmetricMode bool `json:"symmetricMode,omitempty"`

	// Selects the endpoints to which this SecurityPolicy object applies.
	// Empty or nil means select all endpoints.
	// Notice: if AppliedTo is empty, IngressRule's Ports can't be namedPorts.
	AppliedTo []ApplyToPeer `json:"appliedTo,omitempty"`

	// List of ingress rules to be applied to the selected endpoints. If this field
	// is empty then this SecurityPolicy does not allow any traffic.
	// +optional
	IngressRules []Rule `json:"ingressRules,omitempty"`

	// List of egress rules to be applied to the selected endpoints. If this field
	// is empty then this SecurityPolicy limits all outgoing traffic.
	// +optional
	EgressRules []Rule `json:"egressRules,omitempty"`

	// DefaultRule will generate default rule for policy
	// +kubebuilder:default=drop
	DefaultRule DefaultRuleType `json:"defaultRule,omitempty"`

	// Logging defines the policy logging configuration.
	// +optional
	Logging *Logging `json:"logging,omitempty"`

	// IsBlocklist specify the SecurityPolicy is allowlist or blocklist
	// Default is false
	IsBlocklist bool `json:"isBlocklist,omitempty"`

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

type Logging struct {
	// Enabled would log connections when the policy matched.
	Enabled bool `json:"enabled"`

	// PolicyID is a user defined identity of policy, which would be record
	// in logs and metrics. Can be repeated between different policies.
	// Defaults to namespace/name.
	// +optional
	PolicyID string `json:"policyID,omitempty"`

	// PolicyName is a user defined name of policy, which would be record
	// in logs. Can be repeated between different policies.
	// Defaults to namespace/name.
	// +optional
	PolicyName string `json:"policyName,omitempty"`
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

	// EndpointSelector selects endpoints. This field follows extend label
	// selector semantics; if present but empty, it selects all endpoints.
	//
	// If EndpointSelector is set, then the SecurityPolicy would apply to the
	// endpoints matching EndpointSelector in the SecurityPolicy Namespace.
	// If this field is set then neither of the other fields can be.
	// +optional
	EndpointSelector *labels.Selector `json:"endpointSelector,omitempty"`
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
	// DisableSymmetric if set true, won't generate symmetric rules for the peer even if
	// SymmetricMode of policy set true, the default value is false
	// +optional
	DisableSymmetric bool `json:"disableSymmetric,omitempty"`
	// IPBlock defines policy on a particular IPBlock. If this field is set then
	// neither of the other fields can be.
	// +optional
	IPBlock *networkingv1.IPBlock `json:"ipBlock,omitempty"`

	// Endpoint defines policy on a specific Endpoint. If this field is set then
	// neither of the other fields can be.
	// +optional
	Endpoint *NamespacedName `json:"endpoint,omitempty"`

	// EndpointSelector selects endpoints. This field follows extend label
	// selector semantics; if present but empty, it selects all endpoints.
	//
	// If NamespaceSelector is also set, then the Rule would select the endpoints
	// matching EndpointSelector in the Namespaces selected by NamespaceSelector.
	// Otherwise, it selects the Endpoints matching EndpointSelector in the policy's own Namespace.
	// +optional
	EndpointSelector *labels.Selector `json:"endpointSelector,omitempty"`

	// NamespaceSelector selects namespaces. This field follows standard label
	// selector semantics; if present but empty, it selects all namespaces.
	//
	// If EndpointSelector is also set, then the Rule would select the endpoints
	// matching EndpointSelector in the Namespaces selected by NamespaceSelector.
	// Otherwise, it selects all Endpoints in the Namespaces selected by NamespaceSelector.
	// +optional
	NamespaceSelector *metav1.LabelSelector `json:"namespaceSelector,omitempty"`
}

// PortType defaines the PortRange is real port numbers or port names which needed resolve. If it is empty, equal to "number".
// +kubebuilder:validation:Enum=number;name
type PortType string

const (
	PortTypeName   PortType = "name"
	PortTypeNumber PortType = "number"
)

// SecurityPolicyPort describes the port and protocol to match in a rule.
type SecurityPolicyPort struct {
	// The ip protocol which traffic must match.
	Protocol Protocol `json:"protocol"`

	// PortRange is a range of port. If you want match all ports, you should set empty. If you
	// want match single port, you should write like 22. If you want match a range of port, you
	// should write like 20-80, ports between 20 and 80 (include 20 and 80) will matches. If you
	// want match multiple ports, you should write like 20,22-24,90.
	PortRange string `json:"portRange,omitempty"` // only valid when Protocol is not ICMP

	// Type defines the PortRange is real port numbers or port names which needed resolve. If it is empty,
	// the effect is equal to "number" for compatibility.
	// +kubebuilder:default:=number
	Type PortType `json:"type,omitempty"`
}

// NamespacedName contains information to specify an object.
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

// Protocol defines network protocols supported for SecurityPolicy.
// +kubebuilder:validation:Enum=TCP;UDP;ICMP;IPIP;VRRP
type Protocol string

const (
	// ProtocolTCP is the TCP protocol.
	ProtocolTCP Protocol = "TCP"
	// ProtocolUDP is the UDP protocol.
	ProtocolUDP Protocol = "UDP"
	// ProtocolICMP is the ICMP protocol.
	ProtocolICMP Protocol = "ICMP"
	// ProtocolIPIP is the IPIP protocol.
	ProtocolIPIP Protocol = "IPIP"
	// ProtocolVRRP is the VRRP protocol.
	ProtocolVRRP Protocol = "VRRP"
)

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// SecurityPolicyList contains a list of SecurityPolicy
type SecurityPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []SecurityPolicy `json:"items"`
}

// +genclient
// +k8s:openapi-gen=true
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".spec.reference.externalIDName"
// +kubebuilder:printcolumn:name="EXTERNAL-VALUE",type="string",JSONPath=".spec.reference.externalIDValue"
// +kubebuilder:printcolumn:name="IPADDR",type="string",JSONPath=".status.ips"
// +kubebuilder:printcolumn:name="EXTEND-LABELS",type="string",JSONPath=".spec.extendLabels"

// Endpoint is a network communication entity. It's provided by the endpoint provider,
// it could be a virtual network interface, a pod, an ovs port or other entities.
type Endpoint struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Spec contains description of the endpoint
	Spec EndpointSpec `json:"spec"`

	// Status is the current state of the Endpoint
	Status EndpointStatus `json:"status,omitempty"`
}

// EndpointType defines network protocols supported for SecurityPolicy.
// +kubebuilder:validation:Enum=dynamic;static;static-ip
type EndpointType string

const (
	// EndpointDynamic update endpoint status with agentInfo.
	EndpointDynamic EndpointType = "dynamic"
	// EndpointStatic will not update endpoint status from agentInfo.
	EndpointStatic EndpointType = "static"
	// EndpointStaticIP will update endpoint status from agentInfo except ip.
	EndpointStaticIP EndpointType = "static-ip"
)

// EndpointSpec provides the specification of an Endpoint
type EndpointSpec struct {
	// VID describe the endpoint in which VLAN
	VID uint32 `json:"vid"`

	// ExtendLabels contains extend labels of endpoint. Each key in the labels
	// could have multiple values, but at least one should be specified.
	// The ExtendLabels could be selected by selector in SecurityPolicy or EndpointGroup.
	// +optional
	ExtendLabels map[string][]string `json:"extendLabels,omitempty"`

	// Reference of an endpoint, also the external_id of an ovs interface.
	// We map between endpoint and ovs interface use the Reference.
	Reference EndpointReference `json:"reference"`

	// Type of this Endpoint
	// +kubebuilder:default="dynamic"
	Type EndpointType `json:"type,omitempty"`

	// StrictMac is a ip filter switch
	// true: filter ip which src mac does not equal interface mac
	// false: no action
	StrictMac bool `json:"strictMac,omitempty"`

	Ports []NamedPort `json:"ports,omitempty"`
}

// EndpointReference uniquely identifies an endpoint
type EndpointReference struct {
	// ExternalIDName of an endpoint.
	ExternalIDName string `json:"externalIDName"`

	// ExternalIDValue of an endpoint.
	ExternalIDValue string `json:"externalIDValue"`
}

// EndpointStatus describe the current state of the Endpoint
type EndpointStatus struct {
	// IPs of an endpoint, can be IPV4 or IPV6.
	IPs []types.IPAddress `json:"ips,omitempty"`
	// MacAddress of an endpoint.
	MacAddress string `json:"macAddress,omitempty"`
	// Agents where this endpoint is currently located
	Agents []string `json:"agents,omitempty"`
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
// +kubebuilder:printcolumn:name="DefaultAction",type="string",JSONPath=".spec.defaultAction"

// GlobalPolicy allow defines default action of traffics and global
// ip whitelist. Only one GlobalPolicy can exist on kubernetes.
type GlobalPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Specification of the desired behavior for this GlobalPolicy.
	// +optional
	Spec GlobalPolicySpec `json:"spec,omitempty"`
}

// GlobalPolicySpec provides the specification of a GlobalPolicy
type GlobalPolicySpec struct {
	// DefaultAction defines global traffic action
	// +optional
	// +kubebuilder:default="Allow"
	DefaultAction GlobalDefaultAction `json:"defaultAction,omitempty"`

	// GlobalPolicy enforcement mode
	// +kubebuilder:default=work
	GlobalPolicyEnforcementMode PolicyMode `json:"globalPolicyEnforcementMode,omitempty"`

	// Logging defines the policy logging configuration.
	// +optional
	Logging *Logging `json:"logging,omitempty"`
}

// GlobalDefaultAction defines actions supported for GlobalPolicy.
// +kubebuilder:validation:Enum=Allow;Drop
type GlobalDefaultAction string

const (
	// GlobalDefaultActionAllow default allow all traffics between Endpoints.
	GlobalDefaultActionAllow GlobalDefaultAction = "Allow"
	// GlobalDefaultActionDrop default drop all traffics between Endpoints.
	GlobalDefaultActionDrop GlobalDefaultAction = "Drop"
)

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type GlobalPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []GlobalPolicy `json:"items"`
}

// NamedPort represents a Port with a name on Pod.
type NamedPort struct {
	// Port represents the Port number.
	Port int32 `json:"port,omitempty" protobuf:"varint,1,opt,name=port"`
	// Name represents the associated name with this Port number.
	Name string `json:"name,omitempty" protobuf:"bytes,2,opt,name=name"`
	// Protocol for port. Must be UDP, TCP  TODO not icmp webhook
	Protocol Protocol `json:"protocol,omitempty" protobuf:"bytes,3,opt,name=protocol"`
}

func (p *NamedPort) ToString() string {
	return strings.Join([]string{p.Name, string(p.Port), string(p.Protocol)}, "-")
}
