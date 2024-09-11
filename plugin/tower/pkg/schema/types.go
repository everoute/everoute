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
	"k8s.io/apimachinery/pkg/util/sets"
)

type VM struct {
	ObjectMeta

	Name         string          `json:"name"`
	OriginalName *string         `json:"original_name,omitempty"`
	Description  string          `json:"description,omitempty"`
	Vcpu         int             `json:"vcpu,omitempty"`
	Memory       float64         `json:"memory,omitempty"`
	Status       VMStatus        `json:"status"`
	VMNics       []VMNic         `json:"vm_nics,omitempty"`
	Cluster      ELFCluster      `json:"cluster"`
	VMUsage      VMUsage         `json:"vm_usage"`
	Internal     bool            `json:"internal"`
	Host         ObjectReference `json:"host"`
}

type VMUsage string

const (
	VMUsageEverouteController    VMUsage = "EVEROUTE_CONTROLLER"
	VMUsageBackupController      VMUsage = "BACKUP_CONTROLLER"
	VMUsageAdvancedMonitoring    VMUsage = "ADVANCED_MONITORING"
	VMUsageCloudtower            VMUsage = "CLOUDTOWER"
	VMUsageRegistry              VMUsage = "REGISTRY"
	VMUsageShareRegistry         VMUsage = "SHARE_REGISTRY"
	VMUsageSksManagement         VMUsage = "SKS_MANAGEMENT"
	VMUsageBundleApplication     VMUsage = "BUNDLE_APPLICATION"
	VMUsageAgentMeshNode         VMUsage = "AGENT_MESH_NODE"
	VMUsageReplicationController VMUsage = "REPLICATION_CONTROLLER"
	VMUsageSfsController         VMUsage = "SFS_CONTROLLER"
)

// VMStatus is enumeration of vm status
type VMStatus string

const (
	VMStatusRunning   VMStatus = "RUNNING"
	VMStatusSuspended VMStatus = "SUSPENDED"
	VMStatusStopped   VMStatus = "STOPPED"
	VMStatusDeleted   VMStatus = "DELETED"
	VMStatusUnknown   VMStatus = "UNKNOWN"
)

type VMNic struct {
	ObjectMeta

	Vlan        Vlan       `json:"vlan,omitempty"`
	Enabled     bool       `json:"enabled,omitempty"`
	Mirror      bool       `json:"mirror,omitempty"`
	Model       VMNicModel `json:"model,omitempty"`
	MacAddress  string     `json:"mac_address,omitempty"`
	IPAddress   string     `json:"ip_address,omitempty"`
	InterfaceID string     `json:"interface_id,omitempty"`
}

// VMNicModel is enumeration of vnic models
type VMNicModel string

const (
	VMNicModelE1000  VMNicModel = "E1000"
	VMNicModelVIRTIO VMNicModel = "VIRTIO"
)

type Vlan struct {
	ObjectMeta

	VDS    ObjectReference `json:"vds"`
	Name   string          `json:"name,omitempty"`
	VlanID int             `json:"vlan_id"`
	Type   NetworkType     `json:"type,omitempty"`
}

// NetworkType is enumeration of network types
type NetworkType string

const (
	NetworkStorage    = "STORAGE"
	NetworkManagement = "MANAGEMENT"
	NetworkVM         = "VM"
	NetworkAccess     = "ACCESS"
	NetworkMigration  = "MIGRATION"
)

// VMList is a list of vms
type VMList struct {
	VMS []VM `json:"vms,omitempty"`
}

type Label struct {
	ObjectMeta

	Key   string            `json:"key"`
	Value string            `json:"value,omitempty"`
	VMs   []ObjectReference `json:"vms,omitempty"`
}

// LabelList is a list of labels
type LabelList struct {
	Labels []Label `json:"labels,omitempty"`
}

// EverouteCluster defines everoute cluster
type EverouteCluster struct {
	ObjectMeta

	AgentELFClusters    []AgentELFCluster            `json:"agent_elf_clusters"`
	AgentELFVDSes       []ObjectReference            `json:"agent_elf_vdses,omitempty"`
	ControllerInstances []EverouteControllerInstance `json:"controller_instances"`
	GlobalDefaultAction GlobalPolicyAction           `json:"global_default_action"`
	GlobalWhitelist     EverouteClusterWhitelist     `json:"global_whitelist,omitempty"`
	EnableLogging       bool                         `json:"enable_logging,omitempty"`
}

type AgentELFCluster struct {
	ObjectMeta

	LocalID string `json:"local_id"`
}

func (e *EverouteCluster) GetELFs() sets.Set[string] {
	res := sets.New[string]()
	if e == nil {
		return res
	}
	for i := range e.AgentELFClusters {
		res.Insert(e.AgentELFClusters[i].LocalID)
	}
	return res
}

type EverouteClusterWhitelist struct {
	Egress  []NetworkPolicyRule `json:"egress"`
	Enable  bool                `json:"enable"`
	Ingress []NetworkPolicyRule `json:"ingress"`
}

type EverouteControllerInstance struct {
	IPAddr string `json:"ipAddr"`
}

type GlobalPolicyAction string

const (
	GlobalPolicyActionAllow GlobalPolicyAction = "ALLOW"
	GlobalPolicyActionDrop  GlobalPolicyAction = "DROP"
)

// Host defines elf host node
type Host struct {
	ObjectMeta

	Name    string     `json:"name,omitempty"`
	Nics    []Nic      `json:"nics,omitempty"`
	Cluster ELFCluster `json:"cluster"`
}

type Nic struct {
	ObjectMeta

	Type       *NetworkType    `json:"type,omitempty"`
	VDS        ObjectReference `json:"vds,omitempty"`
	Physical   bool            `json:"physical"`
	Name       string          `json:"name,omitempty"`
	MacAddress string          `json:"mac_address,omitempty"`
	IPAddress  string          `json:"ip_address,omitempty"`
}

type VDS struct {
	ObjectMeta

	Cluster ObjectReference `json:"cluster"`
	Vlans   []Vlan          `json:"vlans,omitempty"`
}

type ELFCluster struct {
	ObjectMeta

	LocalID string `json:"local_id"`
}
