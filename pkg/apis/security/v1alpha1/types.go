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

	"github.com/smartxworks/lynx/pkg/types"
)

// +genclient
// +k8s:openapi-gen=true
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

type SecurityPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   SecurityPolicySpec   `json:"spec"`
	Status SecurityPolicyStatus `json:"status,omitempty"`
}

type SecurityPolicySpec struct {
	Tier     string `json:"tier"`
	Priority int32  `json:"priority"`

	// SymmetricMode will generated symmetry rules for the policy.
	// Defaults to false.
	SymmetricMode bool `json:"symmetricMode,omitempty"`

	// Object to be applied to list of ingress rule and egress rule
	AppliedTo AppliedTo `json:"appliedTo"`

	// List of ingress rules to be applied to giving groups. If this field is empty
	// then this SecurityPolicy does not allow any traffic.
	IngressRules []Rule `json:"ingressRules,omitempty"`

	// List of egress rules to be applied to giving groups. If this field is empty
	// then this SecurityPolicy limits all outgoing traffic.
	EgressRules []Rule `json:"egressRules,omitempty"`
}

type AppliedTo struct {
	// List of groups which SecurityPolicy applied to. Each item in this list is
	// combined using a logical OR. This field must not empty.
	EndpointGroups []string `json:"endpointGroups,omitempty"`
	// Endpoint which SecurityPolicy applied to
	Endpoints []string `json:"endpoints,omitempty"`
}

// SecurityPolicyPhase defines the phase in which a SecurityPolicy is.
type SecurityPolicyPhase string

const (
	// SecurityPolicyPending means the SecurityPolicy has been accepted by the system, but it has not been processed by Lynx.
	SecurityPolicyPending SecurityPolicyPhase = "Pending"
	// SecurityPolicyRealizing means the SecurityPolicy has been observed by Lynx and is being realized.
	SecurityPolicyRealizing SecurityPolicyPhase = "Realizing"
	// SecurityPolicyRealized means the SecurityPolicy has been enforced to all Endpoints it applies to.
	SecurityPolicyRealized SecurityPolicyPhase = "Realized"
)

type SecurityPolicyStatus struct {
	// The phase of a SecurityPolicy is a simple, high-level summary of the SecurityPolicy's status.
	Phase SecurityPolicyPhase `json:"phase"`
	// The generation observed by Lynx.
	ObservedGeneration int64 `json:"observedGeneration"`
	// The number of agents that have realized the SecurityPolicy.
	CurrentAgentsRealized int32 `json:"currentAgentsRealized"`
	// The total number of agents that should realize the SecurityPolicy.
	DesiredAgentsRealized int32 `json:"desiredAgentsRealized"`
}

type Rule struct {
	// Name must be unique within the policy and conforms RFC 1123.
	Name string `json:"name"`

	// List of destination ports for outgoing traffic. If this field is empty or
	// missing, this rule matches all ports and protocols. Each item in this list
	// is combined using a logical OR.
	Ports []SecurityPolicyPort `json:"ports,omitempty"`

	// Giving sources which can access applied groups for this rule. If this field
	// is empty or missing, this rule matches all sources. This field only works
	// when rule is ingress.
	From SecurityPolicyPeer `json:"from,omitempty"`

	// Giving destinations which can outgoing traffic of applied groups for this rule.
	// If this field is empty or missing, this rule matches all destinations. This field
	// only works when rule is egress.
	To SecurityPolicyPeer `json:"to,omitempty"`
}

// SecurityPolicyPeer describes the grouping selector of workloads.
type SecurityPolicyPeer struct {
	IPBlocks       []networkingv1.IPBlock `json:"ipBlocks,omitempty"`
	EndpointGroups []string               `json:"endpointGroups,omitempty"`
	Endpoints      []string               `json:"endpoints,omitempty"`
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

	// ICMP type and code is not support in alpha1.
	// ICMPType  *int32 `json:"icmpType,omitempty"`  // only valid when Protocol is ICMP
	// ICMPCode  *int32 `json:"icmpCode,omitempty"`  // only valid when Protocol is ICMP
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

	// ProtocolSCTP is not support in alpha1.
	// ProtocolSCTP is the SCTP protocol.
	// ProtocolSCTP Protocol = "SCTP"
)

// +kubebuilder:validation:Enum=Allow;Drop
// RuleAction describes the action to be applied on traffic matching a rule.
// Default action is allow
type RuleAction string

const (
	// RuleActionAllow describes that rule matching traffic must be allowed.
	RuleActionAllow RuleAction = "Allow"
	// RuleActionDrop describes that rule matching traffic must be dropped.
	RuleActionDrop RuleAction = "Drop"
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
