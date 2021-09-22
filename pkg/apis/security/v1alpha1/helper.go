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
	networkingv1 "k8s.io/api/networking/v1"
)

// IsEnable returns whether SecurityPolicy ingress and egress should enable
func (p *SecurityPolicy) IsEnable() (ingressEnabled bool, egressEnabled bool) {
	for _, policyType := range p.Spec.PolicyTypes {
		if policyType == networkingv1.PolicyTypeIngress {
			ingressEnabled = true
		}
		if policyType == networkingv1.PolicyTypeEgress {
			egressEnabled = true
		}
	}
	// If no policyTypes are specified on a SecurityPolicy then
	// by default Ingress will always be set and Egress will be
	// set if the SecurityPolicy has any egress rules.
	if !ingressEnabled && !egressEnabled {
		ingressEnabled = true
		if len(p.Spec.EgressRules) != 0 {
			egressEnabled = true
		}
	}
	return
}
