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

package model

import (
	"context"
	"fmt"
	"strings"
)

// Endpoint is a network communication entity. It's provided by the endpoint provider,
// it could be a virtual machine, a pod, an ovs port or other entities.
type Endpoint struct {
	// Name is the unique identity of endpoint
	Name string
	// Labels are key/value pairs that are attached to an endpoint.
	// Multiple values can be associated with the same key.
	Labels map[string][]string

	// The endpoint expect IP addr from the subnet
	ExpectSubnet string
	// Virtual network identifier, update VID not supported.
	// VID must between 0-4095 when network is vlan.
	VID int
	// Expose tcp port. TODO: support tcp-ports
	TCPPort int
	// Expose udp port. TODO: support udp-ports
	UDPPort int
	// protoco beyond tcp udp
	Proto string

	// Status of endpoint, should managed by the endpoint provider
	Status *EndpointStatus
}

type EndpointStatus struct {
	// IPAddr of the endpoint, should include subnet mask
	IPAddr string
	// The name of the host where the endpoint is located
	Host string
	// LocalID is the endpoint unique identity on host
	LocalID string
}

func (es *EndpointStatus) GetIP() string {
	return strings.Split(es.IPAddr, "/")[0]
}

func (es *EndpointStatus) String() string {
	if es != nil {
		return fmt.Sprintf("%+v", *es)
	}
	return ""
}

// EndpointProvider provides an interface to manage the lifecycle of the endpoint.
// It should be a stateless application, which means it should not keep any state in the instance.
type EndpointProvider interface {
	Name() string
	EndpointLister
	EndpointOperator
	EndpointExecutor
}

// EndpointOperator know how to create, delete or update state of endpoint.
type EndpointOperator interface {
	Create(ctx context.Context, endpoint *Endpoint) (*Endpoint, error)

	Update(ctx context.Context, endpoint *Endpoint) (*Endpoint, error)

	Delete(ctx context.Context, name string) error

	RenewIP(ctx context.Context, name string) (*Endpoint, error)

	Migrate(ctx context.Context, name string) (*Endpoint, error)
}

// EndpointLister know how to list and get endpoint from store.
type EndpointLister interface {
	Get(ctx context.Context, name string) (*Endpoint, error)

	List(ctx context.Context) ([]*Endpoint, error)
}

// EndpointExecutor know how to execute command in the endpoint.
type EndpointExecutor interface {
	RunScript(ctx context.Context, name string, script []byte, arg ...string) (int, []byte, error)

	RunCommand(ctx context.Context, name string, cmd string, arg ...string) (int, []byte, error)
}
