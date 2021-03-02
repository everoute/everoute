/*
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

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// PolicyRuleSpec defines the desired state of PolicyRule
type PolicyRuleSpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	// Foo is an example field of PolicyRule. Edit PolicyRule_types.go to remove/update
	RuleId     string `json:"ruleId"`
	Tier       string `json:"foo,omitempty"`
	Priority   int32  `json:"priority"`
	SrcIpAddr  string `json:"srcIpAddr,omitempty"`
	DstIpAddr  string `json:"dstIpAddr,omitempty"`
	IpProtocol string `json:"ipProtocol"`
	SrcPort    uint16 `json:"srcPort,omitempty"`
	DstPort    uint16 `json:"dstPort,omitempty"`
	ICMPType   int32  `json:"icmpType,omitempty"`
	ICMPCode   int32  `json:"icmpCode,omitempty"`
	TcpFlags   string `json:"tcpFlags"`
	Action     string `json:"action"`
}

type PolicyRuleEnforceState string

const (
	PolicyRuleSuccessEnforced PolicyRuleEnforceState = "SuccessEnforced"
	PolicyRuleFailedEnforced  PolicyRuleEnforceState = "FailedEnforced"
)

// PolicyRuleStatus defines the observed state of PolicyRule
type PolicyRuleStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file
	EnforceState    PolicyRuleEnforceState `json:"enforceState"`
	MatchStatistics int64                  `json:"matchStatistics"`
}

// +kubebuilder:object:root=true

// PolicyRule is the Schema for the policyrules API
type PolicyRule struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   PolicyRuleSpec   `json:"spec,omitempty"`
	Status PolicyRuleStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// PolicyRuleList contains a list of PolicyRule
type PolicyRuleList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []PolicyRule `json:"items"`
}

func init() {
	SchemeBuilder.Register(&PolicyRule{}, &PolicyRuleList{})
}
