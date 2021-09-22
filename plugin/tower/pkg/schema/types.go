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

type VM struct {
	ObjectMeta

	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Vcpu        int      `json:"vcpu,omitempty"`
	Memory      float64  `json:"memory,omitempty"`
	Status      VMStatus `json:"status"`
	VMNics      []VMNic  `json:"vm_nics,omitempty"`
}

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

	Name   string      `json:"name,omitempty"`
	VlanID int         `json:"vlan_id"`
	Type   NetworkType `json:"type,omitempty"`
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
