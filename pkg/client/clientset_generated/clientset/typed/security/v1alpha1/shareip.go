/*
Copyright The Everoute Authors.

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

	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	rest "k8s.io/client-go/rest"

	v1alpha1 "github.com/everoute/everoute/pkg/apis/security/v1alpha1"
	scheme "github.com/everoute/everoute/pkg/client/clientset_generated/clientset/scheme"
)

// ShareIPsGetter has a method to return a ShareIPInterface.
// A group's client should implement this interface.
type ShareIPsGetter interface {
	ShareIPs() ShareIPInterface
}

// ShareIPInterface has methods to work with ShareIP resources.
type ShareIPInterface interface {
	Create(ctx context.Context, shareIP *v1alpha1.ShareIP, opts v1.CreateOptions) (*v1alpha1.ShareIP, error)
	Update(ctx context.Context, shareIP *v1alpha1.ShareIP, opts v1.UpdateOptions) (*v1alpha1.ShareIP, error)
	Delete(ctx context.Context, name string, opts v1.DeleteOptions) error
	DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error
	Get(ctx context.Context, name string, opts v1.GetOptions) (*v1alpha1.ShareIP, error)
	List(ctx context.Context, opts v1.ListOptions) (*v1alpha1.ShareIPList, error)
	Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error)
	Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v1alpha1.ShareIP, err error)
	ShareIPExpansion
}

// shareIPs implements ShareIPInterface
type shareIPs struct {
	client rest.Interface
}

// newShareIPs returns a ShareIPs
func newShareIPs(c *SecurityV1alpha1Client) *shareIPs {
	return &shareIPs{
		client: c.RESTClient(),
	}
}

// Get takes name of the shareIP, and returns the corresponding shareIP object, and an error if there is any.
func (c *shareIPs) Get(ctx context.Context, name string, options v1.GetOptions) (result *v1alpha1.ShareIP, err error) {
	result = &v1alpha1.ShareIP{}
	err = c.client.Get().
		Resource("shareips").
		Name(name).
		VersionedParams(&options, scheme.ParameterCodec).
		Do(ctx).
		Into(result)
	return
}

// List takes label and field selectors, and returns the list of ShareIPs that match those selectors.
func (c *shareIPs) List(ctx context.Context, opts v1.ListOptions) (result *v1alpha1.ShareIPList, err error) {
	var timeout time.Duration
	if opts.TimeoutSeconds != nil {
		timeout = time.Duration(*opts.TimeoutSeconds) * time.Second
	}
	result = &v1alpha1.ShareIPList{}
	err = c.client.Get().
		Resource("shareips").
		VersionedParams(&opts, scheme.ParameterCodec).
		Timeout(timeout).
		Do(ctx).
		Into(result)
	return
}

// Watch returns a watch.Interface that watches the requested shareIPs.
func (c *shareIPs) Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error) {
	var timeout time.Duration
	if opts.TimeoutSeconds != nil {
		timeout = time.Duration(*opts.TimeoutSeconds) * time.Second
	}
	opts.Watch = true
	return c.client.Get().
		Resource("shareips").
		VersionedParams(&opts, scheme.ParameterCodec).
		Timeout(timeout).
		Watch(ctx)
}

// Create takes the representation of a shareIP and creates it.  Returns the server's representation of the shareIP, and an error, if there is any.
func (c *shareIPs) Create(ctx context.Context, shareIP *v1alpha1.ShareIP, opts v1.CreateOptions) (result *v1alpha1.ShareIP, err error) {
	result = &v1alpha1.ShareIP{}
	err = c.client.Post().
		Resource("shareips").
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(shareIP).
		Do(ctx).
		Into(result)
	return
}

// Update takes the representation of a shareIP and updates it. Returns the server's representation of the shareIP, and an error, if there is any.
func (c *shareIPs) Update(ctx context.Context, shareIP *v1alpha1.ShareIP, opts v1.UpdateOptions) (result *v1alpha1.ShareIP, err error) {
	result = &v1alpha1.ShareIP{}
	err = c.client.Put().
		Resource("shareips").
		Name(shareIP.Name).
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(shareIP).
		Do(ctx).
		Into(result)
	return
}

// Delete takes name of the shareIP and deletes it. Returns an error if one occurs.
func (c *shareIPs) Delete(ctx context.Context, name string, opts v1.DeleteOptions) error {
	return c.client.Delete().
		Resource("shareips").
		Name(name).
		Body(&opts).
		Do(ctx).
		Error()
}

// DeleteCollection deletes a collection of objects.
func (c *shareIPs) DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error {
	var timeout time.Duration
	if listOpts.TimeoutSeconds != nil {
		timeout = time.Duration(*listOpts.TimeoutSeconds) * time.Second
	}
	return c.client.Delete().
		Resource("shareips").
		VersionedParams(&listOpts, scheme.ParameterCodec).
		Timeout(timeout).
		Body(&opts).
		Do(ctx).
		Error()
}

// Patch applies the patch and returns the patched shareIP.
func (c *shareIPs) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v1alpha1.ShareIP, err error) {
	result = &v1alpha1.ShareIP{}
	err = c.client.Patch(pt).
		Resource("shareips").
		Name(name).
		SubResource(subresources...).
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(data).
		Do(ctx).
		Into(result)
	return
}