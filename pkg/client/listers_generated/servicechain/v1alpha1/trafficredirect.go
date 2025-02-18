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

// Code generated by lister-gen. DO NOT EDIT.

package v1alpha1

import (
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/tools/cache"

	v1alpha1 "github.com/everoute/everoute/pkg/apis/servicechain/v1alpha1"
)

// TrafficRedirectLister helps list TrafficRedirects.
// All objects returned here must be treated as read-only.
type TrafficRedirectLister interface {
	// List lists all TrafficRedirects in the indexer.
	// Objects returned here must be treated as read-only.
	List(selector labels.Selector) (ret []*v1alpha1.TrafficRedirect, err error)
	// TrafficRedirects returns an object that can list and get TrafficRedirects.
	TrafficRedirects(namespace string) TrafficRedirectNamespaceLister
	TrafficRedirectListerExpansion
}

// trafficRedirectLister implements the TrafficRedirectLister interface.
type trafficRedirectLister struct {
	indexer cache.Indexer
}

// NewTrafficRedirectLister returns a new TrafficRedirectLister.
func NewTrafficRedirectLister(indexer cache.Indexer) TrafficRedirectLister {
	return &trafficRedirectLister{indexer: indexer}
}

// List lists all TrafficRedirects in the indexer.
func (s *trafficRedirectLister) List(selector labels.Selector) (ret []*v1alpha1.TrafficRedirect, err error) {
	err = cache.ListAll(s.indexer, selector, func(m interface{}) {
		ret = append(ret, m.(*v1alpha1.TrafficRedirect))
	})
	return ret, err
}

// TrafficRedirects returns an object that can list and get TrafficRedirects.
func (s *trafficRedirectLister) TrafficRedirects(namespace string) TrafficRedirectNamespaceLister {
	return trafficRedirectNamespaceLister{indexer: s.indexer, namespace: namespace}
}

// TrafficRedirectNamespaceLister helps list and get TrafficRedirects.
// All objects returned here must be treated as read-only.
type TrafficRedirectNamespaceLister interface {
	// List lists all TrafficRedirects in the indexer for a given namespace.
	// Objects returned here must be treated as read-only.
	List(selector labels.Selector) (ret []*v1alpha1.TrafficRedirect, err error)
	// Get retrieves the TrafficRedirect from the indexer for a given namespace and name.
	// Objects returned here must be treated as read-only.
	Get(name string) (*v1alpha1.TrafficRedirect, error)
	TrafficRedirectNamespaceListerExpansion
}

// trafficRedirectNamespaceLister implements the TrafficRedirectNamespaceLister
// interface.
type trafficRedirectNamespaceLister struct {
	indexer   cache.Indexer
	namespace string
}

// List lists all TrafficRedirects in the indexer for a given namespace.
func (s trafficRedirectNamespaceLister) List(selector labels.Selector) (ret []*v1alpha1.TrafficRedirect, err error) {
	err = cache.ListAllByNamespace(s.indexer, s.namespace, selector, func(m interface{}) {
		ret = append(ret, m.(*v1alpha1.TrafficRedirect))
	})
	return ret, err
}

// Get retrieves the TrafficRedirect from the indexer for a given namespace and name.
func (s trafficRedirectNamespaceLister) Get(name string) (*v1alpha1.TrafficRedirect, error) {
	obj, exists, err := s.indexer.GetByKey(s.namespace + "/" + name)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, errors.NewNotFound(v1alpha1.Resource("trafficredirect"), name)
	}
	return obj.(*v1alpha1.TrafficRedirect), nil
}
