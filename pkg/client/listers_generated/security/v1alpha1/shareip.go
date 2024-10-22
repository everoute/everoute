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

	v1alpha1 "github.com/everoute/everoute/pkg/apis/security/v1alpha1"
)

// ShareIPLister helps list ShareIPs.
type ShareIPLister interface {
	// List lists all ShareIPs in the indexer.
	List(selector labels.Selector) (ret []*v1alpha1.ShareIP, err error)
	// Get retrieves the ShareIP from the index for a given name.
	Get(name string) (*v1alpha1.ShareIP, error)
	ShareIPListerExpansion
}

// shareIPLister implements the ShareIPLister interface.
type shareIPLister struct {
	indexer cache.Indexer
}

// NewShareIPLister returns a new ShareIPLister.
func NewShareIPLister(indexer cache.Indexer) ShareIPLister {
	return &shareIPLister{indexer: indexer}
}

// List lists all ShareIPs in the indexer.
func (s *shareIPLister) List(selector labels.Selector) (ret []*v1alpha1.ShareIP, err error) {
	err = cache.ListAll(s.indexer, selector, func(m interface{}) {
		ret = append(ret, m.(*v1alpha1.ShareIP))
	})
	return ret, err
}

// Get retrieves the ShareIP from the index for a given name.
func (s *shareIPLister) Get(name string) (*v1alpha1.ShareIP, error) {
	obj, exists, err := s.indexer.GetByKey(name)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, errors.NewNotFound(v1alpha1.Resource("shareip"), name)
	}
	return obj.(*v1alpha1.ShareIP), nil
}
