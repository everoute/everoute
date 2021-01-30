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

// Code generated by informer-gen. DO NOT EDIT.

package v1alpha1

import (
	internalinterfaces "github.com/smartxworks/lynx/pkg/client/informers_generated/externalversions/internalinterfaces"
)

// Interface provides access to all the informers in this group version.
type Interface interface {
	// Endpoints returns a EndpointInformer.
	Endpoints() EndpointInformer
	// SecurityPolicies returns a SecurityPolicyInformer.
	SecurityPolicies() SecurityPolicyInformer
	// Tiers returns a TierInformer.
	Tiers() TierInformer
}

type version struct {
	factory          internalinterfaces.SharedInformerFactory
	namespace        string
	tweakListOptions internalinterfaces.TweakListOptionsFunc
}

// New returns a new Interface.
func New(f internalinterfaces.SharedInformerFactory, namespace string, tweakListOptions internalinterfaces.TweakListOptionsFunc) Interface {
	return &version{factory: f, namespace: namespace, tweakListOptions: tweakListOptions}
}

// Endpoints returns a EndpointInformer.
func (v *version) Endpoints() EndpointInformer {
	return &endpointInformer{factory: v.factory, tweakListOptions: v.tweakListOptions}
}

// SecurityPolicies returns a SecurityPolicyInformer.
func (v *version) SecurityPolicies() SecurityPolicyInformer {
	return &securityPolicyInformer{factory: v.factory, tweakListOptions: v.tweakListOptions}
}

// Tiers returns a TierInformer.
func (v *version) Tiers() TierInformer {
	return &tierInformer{factory: v.factory, tweakListOptions: v.tweakListOptions}
}
