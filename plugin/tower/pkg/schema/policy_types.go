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

package schema

type SecurityPolicy struct {
	ObjectMeta

	EverouteCluster ObjectReference       `json:"everoute_cluster"`
	ApplyTo         []SecurityPolicyApply `json:"apply_to"`
	Ingress         []NetworkPolicyRule   `json:"ingress,omitempty"`
	Egress          []NetworkPolicyRule   `json:"egress,omitempty"`
}

type IsolationPolicy struct {
	ObjectMeta

	EverouteCluster ObjectReference     `json:"everoute_cluster"`
	VM              ObjectReference     `json:"vm"`
	Mode            IsolationMode       `json:"mode"`
	Ingress         []NetworkPolicyRule `json:"ingress,omitempty"`
	Egress          []NetworkPolicyRule `json:"egress,omitempty"`
}

type SecurityPolicyApply struct {
	Communicable bool              `json:"communicable"`
	Selector     []ObjectReference `json:"selector"`
}

type NetworkPolicyRule struct {
	Type     NetworkPolicyRuleType   `json:"type"`
	Ports    []NetworkPolicyRulePort `json:"ports,omitempty"`
	IPBlock  *string                 `json:"ip_block"`
	Selector []ObjectReference       `json:"selector"`
}

type NetworkPolicyRulePort struct {
	Port     *string                       `json:"port,omitempty"`
	Protocol NetworkPolicyRulePortProtocol `json:"protocol"`
}

type IsolationMode string

const (
	IsolationModeAll     IsolationMode = "ALL"
	IsolationModePartial IsolationMode = "PARTIAL"
)

type NetworkPolicyRulePortProtocol string

const (
	NetworkPolicyRulePortProtocolIcmp NetworkPolicyRulePortProtocol = "ICMP"
	NetworkPolicyRulePortProtocolTCP  NetworkPolicyRulePortProtocol = "TCP"
	NetworkPolicyRulePortProtocolUDP  NetworkPolicyRulePortProtocol = "UDP"
)

type NetworkPolicyRuleType string

const (
	NetworkPolicyRuleTypeAll      NetworkPolicyRuleType = "ALL"
	NetworkPolicyRuleTypeIPBlock  NetworkPolicyRuleType = "IP_BLOCK"
	NetworkPolicyRuleTypeSelector NetworkPolicyRuleType = "SELECTOR"
)

// SystemEndpoints contains all internal system endpoints
type SystemEndpoints struct {
	IDEndpoints     []IDSystemEndpoint     `json:"id_endpoints,omitempty"`
	IPPortEndpoints []IPPortSystemEndpoint `json:"ip_port_endpoints,omitempty"`
}

// GetID implements Object
// systemEndpoints has only one instance, we use "systemEndpoints" as its ID
func (*SystemEndpoints) GetID() string {
	return "systemEndpoints"
}

type IDSystemEndpoint struct {
	VMID string `json:"vm_id"`
}

type IPPortSystemEndpoint struct {
	IP   string `json:"ip"`
	Port *int   `json:"port,omitempty"`
}
