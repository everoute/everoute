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

// Code generated by informer-gen. DO NOT EDIT.

package v1alpha1

import (
	"context"
	time "time"

	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
	watch "k8s.io/apimachinery/pkg/watch"
	cache "k8s.io/client-go/tools/cache"

	groupv1alpha1 "github.com/everoute/everoute/pkg/apis/group/v1alpha1"
	clientset "github.com/everoute/everoute/pkg/client/clientset_generated/clientset"
	internalinterfaces "github.com/everoute/everoute/pkg/client/informers_generated/externalversions/internalinterfaces"
	v1alpha1 "github.com/everoute/everoute/pkg/client/listers_generated/group/v1alpha1"
)

// GroupMembersInformer provides access to a shared informer and lister for
// GroupMemberses.
type GroupMembersInformer interface {
	Informer() cache.SharedIndexInformer
	Lister() v1alpha1.GroupMembersLister
}

type groupMembersInformer struct {
	factory          internalinterfaces.SharedInformerFactory
	tweakListOptions internalinterfaces.TweakListOptionsFunc
}

// NewGroupMembersInformer constructs a new informer for GroupMembers type.
// Always prefer using an informer factory to get a shared informer instead of getting an independent
// one. This reduces memory footprint and number of connections to the server.
func NewGroupMembersInformer(client clientset.Interface, resyncPeriod time.Duration, indexers cache.Indexers) cache.SharedIndexInformer {
	return NewFilteredGroupMembersInformer(client, resyncPeriod, indexers, nil)
}

// NewFilteredGroupMembersInformer constructs a new informer for GroupMembers type.
// Always prefer using an informer factory to get a shared informer instead of getting an independent
// one. This reduces memory footprint and number of connections to the server.
func NewFilteredGroupMembersInformer(client clientset.Interface, resyncPeriod time.Duration, indexers cache.Indexers, tweakListOptions internalinterfaces.TweakListOptionsFunc) cache.SharedIndexInformer {
	return cache.NewSharedIndexInformer(
		&cache.ListWatch{
			ListFunc: func(options v1.ListOptions) (runtime.Object, error) {
				if tweakListOptions != nil {
					tweakListOptions(&options)
				}
				return client.GroupV1alpha1().GroupMemberses().List(context.TODO(), options)
			},
			WatchFunc: func(options v1.ListOptions) (watch.Interface, error) {
				if tweakListOptions != nil {
					tweakListOptions(&options)
				}
				return client.GroupV1alpha1().GroupMemberses().Watch(context.TODO(), options)
			},
		},
		&groupv1alpha1.GroupMembers{},
		resyncPeriod,
		indexers,
	)
}

func (f *groupMembersInformer) defaultInformer(client clientset.Interface, resyncPeriod time.Duration) cache.SharedIndexInformer {
	return NewFilteredGroupMembersInformer(client, resyncPeriod, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc}, f.tweakListOptions)
}

func (f *groupMembersInformer) Informer() cache.SharedIndexInformer {
	return f.factory.InformerFor(&groupv1alpha1.GroupMembers{}, f.defaultInformer)
}

func (f *groupMembersInformer) Lister() v1alpha1.GroupMembersLister {
	return v1alpha1.NewGroupMembersLister(f.Informer().GetIndexer())
}
