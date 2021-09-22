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

package clientset

import (
	"fmt"

	agentv1alpha1 "github.com/everoute/everoute/pkg/client/clientset_generated/clientset/typed/agent/v1alpha1"
	groupv1alpha1 "github.com/everoute/everoute/pkg/client/clientset_generated/clientset/typed/group/v1alpha1"
	policyrulev1alpha1 "github.com/everoute/everoute/pkg/client/clientset_generated/clientset/typed/policyrule/v1alpha1"
	securityv1alpha1 "github.com/everoute/everoute/pkg/client/clientset_generated/clientset/typed/security/v1alpha1"
	discovery "k8s.io/client-go/discovery"
	rest "k8s.io/client-go/rest"
	flowcontrol "k8s.io/client-go/util/flowcontrol"
)

type Interface interface {
	Discovery() discovery.DiscoveryInterface
	AgentV1alpha1() agentv1alpha1.AgentV1alpha1Interface
	GroupV1alpha1() groupv1alpha1.GroupV1alpha1Interface
	PolicyruleV1alpha1() policyrulev1alpha1.PolicyruleV1alpha1Interface
	SecurityV1alpha1() securityv1alpha1.SecurityV1alpha1Interface
}

// Clientset contains the clients for groups. Each group has exactly one
// version included in a Clientset.
type Clientset struct {
	*discovery.DiscoveryClient
	agentV1alpha1      *agentv1alpha1.AgentV1alpha1Client
	groupV1alpha1      *groupv1alpha1.GroupV1alpha1Client
	policyruleV1alpha1 *policyrulev1alpha1.PolicyruleV1alpha1Client
	securityV1alpha1   *securityv1alpha1.SecurityV1alpha1Client
}

// AgentV1alpha1 retrieves the AgentV1alpha1Client
func (c *Clientset) AgentV1alpha1() agentv1alpha1.AgentV1alpha1Interface {
	return c.agentV1alpha1
}

// GroupV1alpha1 retrieves the GroupV1alpha1Client
func (c *Clientset) GroupV1alpha1() groupv1alpha1.GroupV1alpha1Interface {
	return c.groupV1alpha1
}

// PolicyruleV1alpha1 retrieves the PolicyruleV1alpha1Client
func (c *Clientset) PolicyruleV1alpha1() policyrulev1alpha1.PolicyruleV1alpha1Interface {
	return c.policyruleV1alpha1
}

// SecurityV1alpha1 retrieves the SecurityV1alpha1Client
func (c *Clientset) SecurityV1alpha1() securityv1alpha1.SecurityV1alpha1Interface {
	return c.securityV1alpha1
}

// Discovery retrieves the DiscoveryClient
func (c *Clientset) Discovery() discovery.DiscoveryInterface {
	if c == nil {
		return nil
	}
	return c.DiscoveryClient
}

// NewForConfig creates a new Clientset for the given config.
// If config's RateLimiter is not set and QPS and Burst are acceptable,
// NewForConfig will generate a rate-limiter in configShallowCopy.
func NewForConfig(c *rest.Config) (*Clientset, error) {
	configShallowCopy := *c
	if configShallowCopy.RateLimiter == nil && configShallowCopy.QPS > 0 {
		if configShallowCopy.Burst <= 0 {
			return nil, fmt.Errorf("burst is required to be greater than 0 when RateLimiter is not set and QPS is set to greater than 0")
		}
		configShallowCopy.RateLimiter = flowcontrol.NewTokenBucketRateLimiter(configShallowCopy.QPS, configShallowCopy.Burst)
	}
	var cs Clientset
	var err error
	cs.agentV1alpha1, err = agentv1alpha1.NewForConfig(&configShallowCopy)
	if err != nil {
		return nil, err
	}
	cs.groupV1alpha1, err = groupv1alpha1.NewForConfig(&configShallowCopy)
	if err != nil {
		return nil, err
	}
	cs.policyruleV1alpha1, err = policyrulev1alpha1.NewForConfig(&configShallowCopy)
	if err != nil {
		return nil, err
	}
	cs.securityV1alpha1, err = securityv1alpha1.NewForConfig(&configShallowCopy)
	if err != nil {
		return nil, err
	}

	cs.DiscoveryClient, err = discovery.NewDiscoveryClientForConfig(&configShallowCopy)
	if err != nil {
		return nil, err
	}
	return &cs, nil
}

// NewForConfigOrDie creates a new Clientset for the given config and
// panics if there is an error in the config.
func NewForConfigOrDie(c *rest.Config) *Clientset {
	var cs Clientset
	cs.agentV1alpha1 = agentv1alpha1.NewForConfigOrDie(c)
	cs.groupV1alpha1 = groupv1alpha1.NewForConfigOrDie(c)
	cs.policyruleV1alpha1 = policyrulev1alpha1.NewForConfigOrDie(c)
	cs.securityV1alpha1 = securityv1alpha1.NewForConfigOrDie(c)

	cs.DiscoveryClient = discovery.NewDiscoveryClientForConfigOrDie(c)
	return &cs
}

// New creates a new Clientset for the given RESTClient.
func New(c rest.Interface) *Clientset {
	var cs Clientset
	cs.agentV1alpha1 = agentv1alpha1.New(c)
	cs.groupV1alpha1 = groupv1alpha1.New(c)
	cs.policyruleV1alpha1 = policyrulev1alpha1.New(c)
	cs.securityV1alpha1 = securityv1alpha1.New(c)

	cs.DiscoveryClient = discovery.NewDiscoveryClient(c)
	return &cs
}
