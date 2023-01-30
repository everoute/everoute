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

package fake

import (
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/discovery"
	fakediscovery "k8s.io/client-go/discovery/fake"
	"k8s.io/client-go/testing"

	clientset "github.com/everoute/everoute/pkg/client/clientset_generated/clientset"
	agentv1alpha1 "github.com/everoute/everoute/pkg/client/clientset_generated/clientset/typed/agent/v1alpha1"
	fakeagentv1alpha1 "github.com/everoute/everoute/pkg/client/clientset_generated/clientset/typed/agent/v1alpha1/fake"
	groupv1alpha1 "github.com/everoute/everoute/pkg/client/clientset_generated/clientset/typed/group/v1alpha1"
	fakegroupv1alpha1 "github.com/everoute/everoute/pkg/client/clientset_generated/clientset/typed/group/v1alpha1/fake"
	securityv1alpha1 "github.com/everoute/everoute/pkg/client/clientset_generated/clientset/typed/security/v1alpha1"
	fakesecurityv1alpha1 "github.com/everoute/everoute/pkg/client/clientset_generated/clientset/typed/security/v1alpha1/fake"
)

// NewSimpleClientset returns a clientset that will respond with the provided objects.
// It's backed by a very simple object tracker that processes creates, updates and deletions as-is,
// without applying any validations and/or defaults. It shouldn't be considered a replacement
// for a real clientset and is mostly useful in simple unit tests.
func NewSimpleClientset(objects ...runtime.Object) *Clientset {
	o := testing.NewObjectTracker(scheme, codecs.UniversalDecoder())
	for _, obj := range objects {
		if err := o.Add(obj); err != nil {
			panic(err)
		}
	}

	cs := &Clientset{tracker: o}
	cs.discovery = &fakediscovery.FakeDiscovery{Fake: &cs.Fake}
	cs.AddReactor("*", "*", testing.ObjectReaction(o))
	cs.AddWatchReactor("*", func(action testing.Action) (handled bool, ret watch.Interface, err error) {
		gvr := action.GetResource()
		ns := action.GetNamespace()
		watch, err := o.Watch(gvr, ns)
		if err != nil {
			return false, nil, err
		}
		return true, watch, nil
	})

	return cs
}

// Clientset implements clientset.Interface. Meant to be embedded into a
// struct to get a default implementation. This makes faking out just the method
// you want to test easier.
type Clientset struct {
	testing.Fake
	discovery *fakediscovery.FakeDiscovery
	tracker   testing.ObjectTracker
}

func (c *Clientset) Discovery() discovery.DiscoveryInterface {
	return c.discovery
}

func (c *Clientset) Tracker() testing.ObjectTracker {
	return c.tracker
}

var _ clientset.Interface = &Clientset{}

// AgentV1alpha1 retrieves the AgentV1alpha1Client
func (c *Clientset) AgentV1alpha1() agentv1alpha1.AgentV1alpha1Interface {
	return &fakeagentv1alpha1.FakeAgentV1alpha1{Fake: &c.Fake}
}

// GroupV1alpha1 retrieves the GroupV1alpha1Client
func (c *Clientset) GroupV1alpha1() groupv1alpha1.GroupV1alpha1Interface {
	return &fakegroupv1alpha1.FakeGroupV1alpha1{Fake: &c.Fake}
}

// SecurityV1alpha1 retrieves the SecurityV1alpha1Client
func (c *Clientset) SecurityV1alpha1() securityv1alpha1.SecurityV1alpha1Interface {
	return &fakesecurityv1alpha1.FakeSecurityV1alpha1{Fake: &c.Fake}
}
