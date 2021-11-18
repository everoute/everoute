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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Direction",type="string",JSONPath=".spec.direction"
// +kubebuilder:printcolumn:name="RuleType",type="string",JSONPath=".spec.ruleType"
// +kubebuilder:printcolumn:name="Tier",type="string",JSONPath=".spec.tier"
// +kubebuilder:printcolumn:name="SrcIPAddr",type="string",JSONPath=".spec.srcIPAddr"
// +kubebuilder:printcolumn:name="DstIPAddr",type="string",JSONPath=".spec.dstIPAddr"
// +kubebuilder:printcolumn:name="IPProtocol",type="string",JSONPath=".spec.ipProtocol"
// +kubebuilder:printcolumn:name="DstPort",type="string",JSONPath=".spec.dstPort"
// +kubebuilder:printcolumn:name="DstPortMask",type="string",JSONPath=".spec.dstPortMask"
// +kubebuilder:printcolumn:name="Action",type="string",JSONPath=".spec.action"

// PolicyRule
// +k8s:openapi-gen=true
type PolicyRule struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   PolicyRuleSpec   `json:"spec,omitempty"`
	Status PolicyRuleStatus `json:"status,omitempty"`
}

// PolicyRuleList
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type PolicyRuleList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []PolicyRule `json:"items"`
}

// PolicyRuleSpec defines the desired state of PolicyRule
type PolicyRuleSpec struct {
	Direction   RuleDirection `json:"direction"`
	RuleType    RuleType      `json:"ruleType"`
	Tier        string        `json:"tier,omitempty"`
	SrcIPAddr   string        `json:"srcIPAddr,omitempty"`
	DstIPAddr   string        `json:"dstIPAddr,omitempty"`
	IPProtocol  string        `json:"ipProtocol"`
	SrcPort     uint16        `json:"srcPort,omitempty"`
	DstPort     uint16        `json:"dstPort,omitempty"`
	SrcPortMask uint16        `json:"srcPortMask,omitempty"`
	DstPortMask uint16        `json:"dstPortMask,omitempty"`
	TCPFlags    string        `json:"tcpFlags"`
	Action      RuleAction    `json:"action"`
}

type RuleType string

const (
	RuleTypeGlobalDefaultRule RuleType = "GlobalDefaultRule"
	RuleTypeDefaultRule       RuleType = "DefaultRule"
	RuleTypeNormalRule        RuleType = "NormalRule"
)

type RuleAction string

const (
	RuleActionAllow RuleAction = "Allow"
	RuleActionDrop  RuleAction = "Drop"
)

type RuleDirection string

const (
	RuleDirectionIn  RuleDirection = "Ingress"
	RuleDirectionOut RuleDirection = "Egress"
)

type PolicyRuleEnforceState string

const (
	PolicyRuleSuccessEnforced PolicyRuleEnforceState = "SuccessEnforced"
	PolicyRuleFailedEnforced  PolicyRuleEnforceState = "FailedEnforced"
)

// PolicyRuleStatus defines the observed state of PolicyRule
type PolicyRuleStatus struct {
	EnforceState    PolicyRuleEnforceState `json:"enforceState"`
	MatchStatistics int64                  `json:"matchStatistics"`
}
