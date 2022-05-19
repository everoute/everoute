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

	"github.com/everoute/everoute/pkg/apis/security/v1alpha1"
	"github.com/everoute/everoute/pkg/types"
)

// +genclient
// +genclient:nonNamespaced
// +genclient:noStatus
// +k8s:openapi-gen=true
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Cluster

type GroupMembers struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Revision should change when group members change.
	Revision     int32         `json:"revision"`
	GroupMembers []GroupMember `json:"groupMembers,omitempty"`
}

// GroupMember represents resource member to be populated in Groups.
type GroupMember struct {
	// EndpointReference maintains the reference to the Endpoint.
	EndpointReference EndpointReference `json:"endpointReference"`
	IPs               []types.IPAddress `json:"ips,omitempty"`
}

type EndpointReference struct {
	ExternalIDName  string `json:"externalIDName"`
	ExternalIDValue string `json:"externalIDValue"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// GroupMembersList contains a list of GroupMembers
type GroupMembersList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []GroupMembers `json:"items"`
}

// +genclient
// +genclient:nonNamespaced
// +genclient:noStatus
// +k8s:openapi-gen=true
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Cluster

type GroupMembersPatch struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// AppliedToGroupMembers means specific revision of GroupMembers Patch applied to.
	AppliedToGroupMembers GroupMembersReference `json:"appliedToGroupMembers"`

	AddedGroupMembers   []GroupMember `json:"addedGroupMembers,omitempty"`
	UpdatedGroupMembers []GroupMember `json:"updatedGroupMembers,omitempty"`
	RemovedGroupMembers []GroupMember `json:"removedGroupMembers,omitempty"`
}

type GroupMembersReference struct {
	Name     string `json:"name"`
	Revision int32  `json:"revision"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// GroupMembersPatchList contains a list of GroupMembersPatch
type GroupMembersPatchList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []GroupMembersPatch `json:"items"`
}

// +genclient
// +genclient:nonNamespaced
// +genclient:noStatus
// +k8s:openapi-gen=true
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Cluster

type EndpointGroup struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec EndpointGroupSpec `json:"spec"`
}

// EndpointGroupSpec defines the desired state for EndpointGroup.
type EndpointGroupSpec struct {
	// EndpointSelector selects endpoints. This field follows standard label
	// selector semantics; if present but empty, it selects all endpoints.
	//
	// If NamespaceSelector is set, then the EndpointGroup would select the endpoints
	// matching EndpointSelector in the Namespaces selected by NamespaceSelector.
	// If Namespace is set, then the EndpointGroup would select the endpoints
	// matching EndpointSelector in the specific Namespace.
	// If neither of NamespaceSelector or Namespace set, then the EndpointGroup
	// would select the endpoints in all namespaces.
	// +optional
	EndpointSelector *metav1.LabelSelector `json:"endpointSelector,omitempty"`

	// NamespaceSelector selects namespaces. This field follows standard label
	// selector semantics; if present but empty, it selects all namespaces.
	//
	// If NamespaceSelector is set, then the EndpointGroup would select the endpoints
	// matching EndpointSelector in the Namespaces selected by NamespaceSelector.
	// If this field is set then the Namespace field cannot be set.
	// +optional
	NamespaceSelector *metav1.LabelSelector `json:"namespaceSelector,omitempty"`

	// This is a namespace for select endpoints in.
	//
	// If Namespace is set, then the EndpointGroup would select the endpoints
	// matching EndpointSelector in the specific Namespace.
	// If this field is set then the NamespaceSelector field cannot be set.
	// +optional
	Namespace *string `json:"namespace,omitempty"`

	Endpoint *v1alpha1.NamespacedName `json:"endpoint,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// EndpointGroupList contains a list of EndpointGroup
type EndpointGroupList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []EndpointGroup `json:"items"`
}
