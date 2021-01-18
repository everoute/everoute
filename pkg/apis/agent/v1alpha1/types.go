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

package v1alpha1

import (
	"github.com/smartxworks/lynx/pkg/types"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +genclient
// +genclient:nonNamespaced
// +genclient:noStatus
// +k8s:openapi-gen=true
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Cluster

type AgentInfo struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Hostname   string           `json:"hostname,omitempty"`
	OVSInfo    OVSInfo          `json:"ovsInfo,omitempty"`
	Conditions []AgentCondition `json:"conditions,omitempty"`
}

type OVSInfo struct {
	Version string      `json:"version,omitempty"`
	Bridges []OVSBridge `json:"bridges,omitempty"`
}

type OVSBridge struct {
	Name  string    `json:"name,omitempty"`
	Ports []OVSPort `json:"ports,omitempty"`
}

type OVSPort struct {
	Name        string            `json:"name,omitempty"`
	Interfaces  []OVSInterface    `json:"interfaces,omitempty"`
	ExternalIDs map[string]string `json:"externalIDs,omitempty"`

	VlanConfig *VlanConfig `json:"vlanConfig,omitempty"`
	BondConfig *BondConfig `json:"bondConfig,omitempty"`
}

type VlanMode string

const (
	VlanTrunk          VlanMode = "Trunk"
	VlanAccess         VlanMode = "Access"
	VlanNativeTagged   VlanMode = "NativeTagged"
	VlanNativeUntagged VlanMode = "NativeUntagged"
)

type VlanConfig struct {
	VlanMode VlanMode `json:"vlanMode"`
	Tag      int32    `json:"tag,omitempty"`
	Trunks   []int32  `json:"trunks,omitempty"`
}

type BondMode string

const (
	BondModeBalanceSLB   BondMode = "BondModeBalanceSLB"
	BondModeActiveBackup BondMode = "BondModeActiveBackup"
	BondModeBalanceLACP  BondMode = "BondModeBalanceLACP"
)

type BondConfig struct {
	BondMode BondMode `json:"bondMode,omitempty"`
}

type OVSInterface struct {
	Name string            `json:"name,omitempty"`
	Mac  string            `json:"mac,omitempty"`
	IPs  []types.IPAddress `json:"ips,omitempty"`
}

type AgentConditionType string

const (
	AgentHealthy          AgentConditionType = "AgentHealthy"          // Status is always set to be True and LastHeartbeatTime is used to check Agent health status.
	ApiserverConnectionUp AgentConditionType = "ApiserverConnectionUp" // Status True/False is used to mark the connection status between Agent and Apiserver.
	OVSDBConnectionUp     AgentConditionType = "OVSDBConnectionUp"     // Status True/False is used to mark OVSDB connection status.
	OpenflowConnectionUp  AgentConditionType = "OpenflowConnectionUp"  // Status True/False is used to mark Openflow connection status.
)

type AgentCondition struct {
	Type              AgentConditionType     `json:"type"`
	Status            corev1.ConditionStatus `json:"status"`
	LastHeartbeatTime metav1.Time            `json:"lastHeartbeatTime"`
	Reason            string                 `json:"reason,omitempty"`
	Message           string                 `json:"message,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// AgentInfoList contains a list of AgentInfo
type AgentInfoList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []AgentInfo `json:"items"`
}
