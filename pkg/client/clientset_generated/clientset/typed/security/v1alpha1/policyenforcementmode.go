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

// Code generated by client-gen. DO NOT EDIT.

package v1alpha1

import (
	"context"
	"time"

	v1alpha1 "github.com/everoute/everoute/pkg/apis/security/v1alpha1"
	scheme "github.com/everoute/everoute/pkg/client/clientset_generated/clientset/scheme"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	rest "k8s.io/client-go/rest"
)

// PolicyEnforcementModesGetter has a method to return a PolicyEnforcementModeInterface.
// A group's client should implement this interface.
type PolicyEnforcementModesGetter interface {
	PolicyEnforcementModes() PolicyEnforcementModeInterface
}

// PolicyEnforcementModeInterface has methods to work with PolicyEnforcementMode resources.
type PolicyEnforcementModeInterface interface {
	Create(ctx context.Context, policyEnforcementMode *v1alpha1.PolicyEnforcementMode, opts v1.CreateOptions) (*v1alpha1.PolicyEnforcementMode, error)
	Update(ctx context.Context, policyEnforcementMode *v1alpha1.PolicyEnforcementMode, opts v1.UpdateOptions) (*v1alpha1.PolicyEnforcementMode, error)
	Delete(ctx context.Context, name string, opts v1.DeleteOptions) error
	DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error
	Get(ctx context.Context, name string, opts v1.GetOptions) (*v1alpha1.PolicyEnforcementMode, error)
	List(ctx context.Context, opts v1.ListOptions) (*v1alpha1.PolicyEnforcementModeList, error)
	Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error)
	Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v1alpha1.PolicyEnforcementMode, err error)
	PolicyEnforcementModeExpansion
}

// policyEnforcementModes implements PolicyEnforcementModeInterface
type policyEnforcementModes struct {
	client rest.Interface
}

// newPolicyEnforcementModes returns a PolicyEnforcementModes
func newPolicyEnforcementModes(c *SecurityV1alpha1Client) *policyEnforcementModes {
	return &policyEnforcementModes{
		client: c.RESTClient(),
	}
}

// Get takes name of the policyEnforcementMode, and returns the corresponding policyEnforcementMode object, and an error if there is any.
func (c *policyEnforcementModes) Get(ctx context.Context, name string, options v1.GetOptions) (result *v1alpha1.PolicyEnforcementMode, err error) {
	result = &v1alpha1.PolicyEnforcementMode{}
	err = c.client.Get().
		Resource("policyenforcementmodes").
		Name(name).
		VersionedParams(&options, scheme.ParameterCodec).
		Do(ctx).
		Into(result)
	return
}

// List takes label and field selectors, and returns the list of PolicyEnforcementModes that match those selectors.
func (c *policyEnforcementModes) List(ctx context.Context, opts v1.ListOptions) (result *v1alpha1.PolicyEnforcementModeList, err error) {
	var timeout time.Duration
	if opts.TimeoutSeconds != nil {
		timeout = time.Duration(*opts.TimeoutSeconds) * time.Second
	}
	result = &v1alpha1.PolicyEnforcementModeList{}
	err = c.client.Get().
		Resource("policyenforcementmodes").
		VersionedParams(&opts, scheme.ParameterCodec).
		Timeout(timeout).
		Do(ctx).
		Into(result)
	return
}

// Watch returns a watch.Interface that watches the requested policyEnforcementModes.
func (c *policyEnforcementModes) Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error) {
	var timeout time.Duration
	if opts.TimeoutSeconds != nil {
		timeout = time.Duration(*opts.TimeoutSeconds) * time.Second
	}
	opts.Watch = true
	return c.client.Get().
		Resource("policyenforcementmodes").
		VersionedParams(&opts, scheme.ParameterCodec).
		Timeout(timeout).
		Watch(ctx)
}

// Create takes the representation of a policyEnforcementMode and creates it.  Returns the server's representation of the policyEnforcementMode, and an error, if there is any.
func (c *policyEnforcementModes) Create(ctx context.Context, policyEnforcementMode *v1alpha1.PolicyEnforcementMode, opts v1.CreateOptions) (result *v1alpha1.PolicyEnforcementMode, err error) {
	result = &v1alpha1.PolicyEnforcementMode{}
	err = c.client.Post().
		Resource("policyenforcementmodes").
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(policyEnforcementMode).
		Do(ctx).
		Into(result)
	return
}

// Update takes the representation of a policyEnforcementMode and updates it. Returns the server's representation of the policyEnforcementMode, and an error, if there is any.
func (c *policyEnforcementModes) Update(ctx context.Context, policyEnforcementMode *v1alpha1.PolicyEnforcementMode, opts v1.UpdateOptions) (result *v1alpha1.PolicyEnforcementMode, err error) {
	result = &v1alpha1.PolicyEnforcementMode{}
	err = c.client.Put().
		Resource("policyenforcementmodes").
		Name(policyEnforcementMode.Name).
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(policyEnforcementMode).
		Do(ctx).
		Into(result)
	return
}

// Delete takes name of the policyEnforcementMode and deletes it. Returns an error if one occurs.
func (c *policyEnforcementModes) Delete(ctx context.Context, name string, opts v1.DeleteOptions) error {
	return c.client.Delete().
		Resource("policyenforcementmodes").
		Name(name).
		Body(&opts).
		Do(ctx).
		Error()
}

// DeleteCollection deletes a collection of objects.
func (c *policyEnforcementModes) DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error {
	var timeout time.Duration
	if listOpts.TimeoutSeconds != nil {
		timeout = time.Duration(*listOpts.TimeoutSeconds) * time.Second
	}
	return c.client.Delete().
		Resource("policyenforcementmodes").
		VersionedParams(&listOpts, scheme.ParameterCodec).
		Timeout(timeout).
		Body(&opts).
		Do(ctx).
		Error()
}

// Patch applies the patch and returns the patched policyEnforcementMode.
func (c *policyEnforcementModes) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v1alpha1.PolicyEnforcementMode, err error) {
	result = &v1alpha1.PolicyEnforcementMode{}
	err = c.client.Patch(pt).
		Resource("policyenforcementmodes").
		Name(name).
		SubResource(subresources...).
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(data).
		Do(ctx).
		Into(result)
	return
}