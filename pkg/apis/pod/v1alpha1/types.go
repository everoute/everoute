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

// +resourceName=k8scluster
// +genclient
// +genclient:noStatus
// +k8s:openapi-gen=true
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true
// +kubebuilder:printcolumn:name="cni",type="string",JSONPath=".spec.cni"
// +kubebuilder:printcolumn:name="managedBy",type="string",JSONPath=".spec.managedBy"
// +kubebuilder:printcolumn:name="kscname",type="string",JSONPath=".spec.sksOption.kscName"
// +kubebuilder:printcolumn:name="kscnamespace",type="string",JSONPath=".spec.sksOption.kscNamespace"
type K8sCluster struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec K8sClusterSpec `json:"spec"`
}

type K8sClusterSpec struct {
	ControlPlaneAvailable bool                      `json:"controlPlaneAvailabel"`
	CNI                   K8sClusterCNIType         `json:"cni"`
	ManagedBy             K8sClusterManagedPlatform `json:"managedBy"`

	SksOption *SksOption `json:"sksOption,omitempty"`
}

type SksOption struct {
	KscName      string `json:"kscName"`
	KscNamespace string `json:"kscNamespace"`
}

// K8sClusterCNIType is cni type.
type K8sClusterCNIType string

// K8sClusterManagedPlatform the platform that a k8scluster managedby.
type K8sClusterManagedPlatform string

const (
	// CNITypeEIC workload use eic cni.
	CNITypeEIC K8sClusterCNIType = "eic"
	// CNITypeOther workload use other cni that everoute doesn't know, such as calico.
	CNITypeOther K8sClusterCNIType = "other"

	// SKSPlatForm k8s cluster manage platform sks.
	SKSPlatForm K8sClusterManagedPlatform = "sks"
)

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type K8sClusterList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []K8sCluster `json:"items"`
}
