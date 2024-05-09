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

import (
	"encoding/json"
	"fmt"
	"reflect"

	"github.com/everoute/everoute/plugin/tower/pkg/utils"
)

type SecurityPolicy struct {
	ObjectMeta

	Name            string                `json:"name"`
	EverouteCluster ObjectReference       `json:"everoute_cluster"`
	ApplyTo         []SecurityPolicyApply `json:"apply_to"`
	Ingress         []NetworkPolicyRule   `json:"ingress,omitempty"`
	Egress          []NetworkPolicyRule   `json:"egress,omitempty"`
	PolicyMode      PolicyMode            `json:"policy_mode,omitempty"`
	IsBlocklist     bool                  `json:"is_blocklist,omitempty"`
}

type PolicyMode string

const (
	PolicyModeMonitor = "MONITOR"
	PolicyModeWork    = "WORK"
)

type IsolationPolicy struct {
	ObjectMeta

	EverouteCluster ObjectReference     `json:"everoute_cluster"`
	VM              ObjectReference     `json:"vm"`
	Mode            IsolationMode       `json:"mode"`
	Ingress         []NetworkPolicyRule `json:"ingress,omitempty"`
	Egress          []NetworkPolicyRule `json:"egress,omitempty"`
}

type SecurityPolicyApply struct {
	Type          SecurityPolicyType `json:"type"`
	Communicable  bool               `json:"communicable"`
	Selector      []ObjectReference  `json:"selector"`
	SecurityGroup *ObjectReference   `json:"security_group,omitempty"`
}

type NetworkPolicyRule struct {
	OnlyApplyToExternalTraffic bool                    `json:"only_apply_to_external_traffic"`
	Type                       NetworkPolicyRuleType   `json:"type"`
	Ports                      []NetworkPolicyRulePort `json:"ports,omitempty"`
	Services                   []ObjectReference       `json:"services,omitempty"`
	IPBlock                    *string                 `json:"ip_block"`
	ExceptIPBlock              []string                `json:"except_ip_block,omitempty"`
	Selector                   []ObjectReference       `json:"selector"`
	SecurityGroup              *ObjectReference        `json:"security_group,omitempty"`
}

type NetworkPolicyRulePort struct {
	Port        *string                          `json:"port,omitempty"`
	Protocol    NetworkPolicyRulePortProtocol    `json:"protocol"`
	AlgProtocol NetworkPolicyRulePortAlgProtocol `json:"alg_protocol"`
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
	NetworkPolicyRulePortProtocolALG  NetworkPolicyRulePortProtocol = "ALG"
	NetworkPolicyRulePortProtocolIPIP NetworkPolicyRulePortProtocol = "IPIP"
)

type NetworkPolicyRulePortAlgProtocol string

const (
	NetworkPolicyRulePortAlgProtocolFTP  NetworkPolicyRulePortAlgProtocol = "FTP"
	NetworkPolicyRulePortAlgProtocolTFTP NetworkPolicyRulePortAlgProtocol = "TFTP"
)

type SecurityPolicyType string

const (
	SecurityPolicyTypeSelector      SecurityPolicyType = "SELECTOR"
	SecurityPolicyTypeSecurityGroup SecurityPolicyType = "SECURITY_GROUP"
)

type NetworkPolicyRuleType string

const (
	NetworkPolicyRuleTypeAll           NetworkPolicyRuleType = "ALL"
	NetworkPolicyRuleTypeIPBlock       NetworkPolicyRuleType = "IP_BLOCK"
	NetworkPolicyRuleTypeSelector      NetworkPolicyRuleType = "SELECTOR"
	NetworkPolicyRuleTypeSecurityGroup NetworkPolicyRuleType = "SECURITY_GROUP"
)

type SecurityGroup struct {
	ObjectMeta

	EverouteCluster ObjectReference   `json:"everoute_cluster"`
	LabelGroups     []LabelGroup      `json:"label_groups"`
	VMs             []ObjectReference `json:"vms"`
}

type LabelGroup struct {
	Labels []ObjectReference `json:"labels"`
}

// SystemEndpoints contains all internal system endpoints
type SystemEndpoints struct {
	IDEndpoints     []IDSystemEndpoint     `json:"id_endpoints,omitempty"`
	IPPortEndpoints []IPPortSystemEndpoint `json:"ip_port_endpoints,omitempty"`
}

func (s *SystemEndpoints) GetSubscriptionRequest(skipFields map[string][]string) string {
	subscriptionFields := utils.GqlTypeMarshal(reflect.TypeOf(s), skipFields, true)
	return fmt.Sprintf("subscription {systemEndpoints %s}", subscriptionFields)
}

func (s *SystemEndpoints) UnmarshalEvent(raw json.RawMessage, event *MutationEvent) error {
	event.Mutation = UpdateEvent
	event.Node = raw
	return nil
}

func (s *SystemEndpoints) UnmarshalSlice(raw json.RawMessage, slice interface{}) error {
	var systemEndpoint SystemEndpoints

	if err := json.Unmarshal(raw, &systemEndpoint); err != nil {
		return err
	}

	if reflect.ValueOf(systemEndpoint).IsZero() {
		return nil
	}

	*slice.(*[]*SystemEndpoints) = []*SystemEndpoints{&systemEndpoint}
	return nil
}

// GetID implements Object
// systemEndpoints has only one instance, we use "systemEndpoints" as its ID
func (*SystemEndpoints) GetID() string {
	return "systemEndpoints"
}

type IDSystemEndpoint struct {
	Key  string `json:"key"`
	VMID string `json:"vm_id"`
}

type IPPortSystemEndpoint struct {
	Key  string `json:"key"`
	IP   string `json:"ip"`
	Port *int   `json:"port,omitempty"`
}

type NetworkPolicyRuleService struct {
	ObjectMeta

	Members []NetworkPolicyRulePort `json:"members"`
}
