/*
Copyright 2023 The Everoute Authors.

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
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +genclient
// +k8s:openapi-gen=true
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true
// +kubebuilder:resource:shortName=sp
// +kubebuilder:printcolumn:name="Backends",type="string",JSONPath=".spec.backends"

// ServicePort collect info from service endpoints
type ServicePort struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec ServicePortSpec `json:"spec"`
}

// ServicePortSpec provides the specification of a ServicePort
type ServicePortSpec struct {
	// SvcRef is the ServicePort related Service name
	SvcRef string `json:"svcRef,omitempty"`
	// Backends is the Backend ip and port and node info
	Backends []Backend `json:"backends,omitempty"`
}

// Backend provides the specification of a ServicePortSpec.Backends
type Backend struct {
	IP       string          `json:"ip"`
	Protocol corev1.Protocol `json:"protocol,omitempty"`
	Port     int32           `json:"port"`
	Node     string          `json:"node"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// ServicePortList contains a list of ServicePort
type ServicePortList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ServicePort `json:"items"`
}
