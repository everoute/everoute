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

package netns

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/rand"
	"k8s.io/klog"

	"github.com/everoute/everoute/pkg/apis/security/v1alpha1"
	"github.com/everoute/everoute/pkg/client/clientset_generated/clientset"
	"github.com/everoute/everoute/tests/e2e/framework/ipam"
	"github.com/everoute/everoute/tests/e2e/framework/model"
	"github.com/everoute/everoute/tests/e2e/framework/node"
)

// provider provide endpoint from netns
type provider struct {
	ipPool      ipam.Pool
	namespace   string // in which namespace are endpoints created
	nodeManager *node.Manager
	kubeClient  clientset.Interface
}

func NewProvider(pool ipam.Pool, namespace string, nodeManager *node.Manager, client clientset.Interface) model.EndpointProvider {
	return &provider{
		ipPool:      pool,
		namespace:   namespace,
		nodeManager: nodeManager,
		kubeClient:  client,
	}
}

const (
	endpointLastStatusAnnotation = "EndpointLastStatus"
)

func (m *provider) Name() string {
	return "netns"
}

func (m *provider) Get(ctx context.Context, name string) (*model.Endpoint, error) {
	endpoint, _, err := m.getEndpoint(ctx, name)
	return endpoint, err
}

func (m *provider) List(ctx context.Context) ([]*model.Endpoint, error) {
	var epList []*model.Endpoint

	list, err := m.kubeClient.SecurityV1alpha1().Endpoints(m.namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	for _, obj := range list.Items {
		if obj.Annotations == nil || obj.Annotations[endpointLastStatusAnnotation] == "" {
			// ignore endpoint without the annotation
			continue
		}
		var endpoint model.Endpoint
		var lastVMStatusRow = obj.Annotations[endpointLastStatusAnnotation]

		err = json.Unmarshal([]byte(lastVMStatusRow), &endpoint)
		if err != nil {
			return nil, fmt.Errorf("can't unmarshal last update status: %s", err)
		}
		epList = append(epList, &endpoint)
	}

	return epList, nil
}

func (m *provider) Create(ctx context.Context, endpoint *model.Endpoint) (*model.Endpoint, error) {
	var err error

	if _, err = m.Get(ctx, endpoint.Name); err == nil {
		return nil, fmt.Errorf("endpoint %s has been setup already", endpoint.Name)
	}

	if err = m.setupNewEndpoint(endpoint); err != nil {
		return nil, fmt.Errorf("failed build endpoint %s status: %s", endpoint.Name, err)
	}

	_, err = m.kubeClient.SecurityV1alpha1().Endpoints(m.namespace).Create(ctx, toCrdEndpoint(endpoint, ""), metav1.CreateOptions{})
	if err != nil {
		return nil, fmt.Errorf("unable create endpoint %s: %s", endpoint.Name, err)
	}

	return endpoint, nil
}

func (m *provider) Update(ctx context.Context, endpoint *model.Endpoint) (*model.Endpoint, error) {
	var old *model.Endpoint
	var rv string
	var err error

	if old, rv, err = m.getEndpoint(ctx, endpoint.Name); err != nil {
		return nil, err
	}
	endpoint.Status = old.Status

	agent, err := m.nodeManager.GetAgent(endpoint.Status.Host)
	if err != nil {
		return nil, fmt.Errorf("get agent %s client: %s", endpoint.Status.Host, err)
	}

	client, err := agent.GetClient()
	if err != nil {
		return nil, fmt.Errorf("get agent %s client: %s", endpoint.Status.Host, err)
	}

	if old.TCPPort != endpoint.TCPPort || old.UDPPort != endpoint.UDPPort {
		// need update port
		err = runUpdateEndpointPort(client, endpoint.Status.LocalID, endpoint.TCPPort, endpoint.UDPPort)
		if err != nil {
			return nil, fmt.Errorf("failed to update endpoint %s port: %s", endpoint.Name, err)
		}
	}

	return endpoint, m.updateEndpoint(ctx, endpoint, rv)
}

func (m *provider) Delete(ctx context.Context, name string) error {
	var endpoint *model.Endpoint
	var err error

	if endpoint, err = m.Get(ctx, name); err != nil {
		return err
	}

	if err = m.destroyEndpoint(endpoint); err != nil {
		return fmt.Errorf("unable delete endpoint %s on agent %s: %s", endpoint.Name, endpoint.Status.Host, err)
	}

	return m.kubeClient.SecurityV1alpha1().Endpoints(m.namespace).Delete(ctx, name, metav1.DeleteOptions{})
}

func (m *provider) RenewIP(ctx context.Context, name string) (*model.Endpoint, error) {
	var endpoint *model.Endpoint
	var rv string
	var err error

	if endpoint, rv, err = m.getEndpoint(ctx, name); err != nil {
		return nil, err
	}

	agent, err := m.nodeManager.GetAgent(endpoint.Status.Host)
	if err != nil {
		return nil, fmt.Errorf("get agent %s client: %s", endpoint.Status.Host, err)
	}

	client, err := agent.GetClient()
	if err != nil {
		return nil, fmt.Errorf("get agent %s client: %s", endpoint.Status.Host, err)
	}

	// todo: release old ip addr
	endpoint.Status.IPAddr, err = m.ipPool.AssignFromSubnet(endpoint.ExpectSubnet)
	if err != nil {
		return nil, fmt.Errorf("failed to get newIP for %s: %s", name, err)
	}

	err = runUpdateEndpointIP(client, endpoint.Status.LocalID, endpoint.Status.IPAddr)
	if err != nil {
		return nil, fmt.Errorf("unable delete endpoint %s on agent %s: %s", endpoint.Name, endpoint.Status.Host, err)
	}

	return endpoint, m.updateEndpoint(ctx, endpoint, rv)
}

func (m *provider) Migrate(ctx context.Context, name string) (*model.Endpoint, error) {
	var endpoint *model.Endpoint
	var rv string
	var err error

	if endpoint, rv, err = m.getEndpoint(ctx, name); err != nil {
		return nil, err
	}

	if err = m.destroyEndpoint(endpoint); err != nil {
		return nil, fmt.Errorf("failed to destroy endpoint %s: %s", endpoint.Name, err)
	}

	agent, err := m.nodeManager.GetRandomAgent(endpoint.Status.Host)
	if err != nil {
		return nil, err
	}
	endpoint.Status.Host = agent.Name

	if err = m.setupNewEndpoint(endpoint); err != nil {
		return nil, fmt.Errorf("failed build endpoint %s status: %s", endpoint.Name, err)
	}

	return endpoint, m.updateEndpoint(ctx, endpoint, rv)
}

func (m *provider) RunScript(ctx context.Context, name string, script []byte, arg ...string) (int, []byte, error) {
	session, netns, err := m.getExecutePath(ctx, name)
	if err != nil {
		return 0, nil, err
	}
	defer session.Close()

	session.Stdin = bytes.NewBuffer(script)
	command := fmt.Sprintf("ip netns exec %s bash -s %s", netns, strings.Join(arg, " "))

	out, err := session.CombinedOutput(command)
	if _, ok := err.(*ssh.ExitError); ok {
		return err.(*ssh.ExitError).ExitStatus(), out, nil
	}

	return 0, out, err
}

func (m *provider) RunCommand(ctx context.Context, name string, cmd string, arg ...string) (int, []byte, error) {
	session, netns, err := m.getExecutePath(ctx, name)
	if err != nil {
		return 0, nil, err
	}
	defer session.Close()

	command := fmt.Sprintf("ip netns exec %s %s %s", netns, cmd, strings.Join(arg, " "))
	klog.Infof("---cmd : %#+v", command)
	out, err := session.CombinedOutput(command)
	if _, ok := err.(*ssh.ExitError); ok {
		return err.(*ssh.ExitError).ExitStatus(), out, nil
	}

	return 0, out, err
}

func (m *provider) updateEndpoint(ctx context.Context, endpoint *model.Endpoint, rv string) error {
	var err error

	for {
		crdEp := toCrdEndpoint(endpoint, rv)
		_, err = m.kubeClient.SecurityV1alpha1().Endpoints(m.namespace).Update(ctx, crdEp, metav1.UpdateOptions{})

		if err != nil && apierrors.IsConflict(err) {
			// if got error StatusReasonConflict, fetch resource version and try again
			_, rv, err = m.getEndpoint(ctx, endpoint.Name)
			if err == nil {
				continue
			}
		}
		break
	}

	return err
}

func (m *provider) getEndpoint(ctx context.Context, name string) (*model.Endpoint, string, error) {
	crdEp, err := m.kubeClient.SecurityV1alpha1().Endpoints(m.namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return nil, "", err
	}

	if crdEp.Annotations == nil || crdEp.Annotations[endpointLastStatusAnnotation] == "" {
		return nil, "", fmt.Errorf("can't found last update status")
	}

	var endpoint model.Endpoint
	var lastEndpointStatusRow = crdEp.Annotations[endpointLastStatusAnnotation]

	err = json.Unmarshal([]byte(lastEndpointStatusRow), &endpoint)
	if err != nil {
		return nil, "", fmt.Errorf("can't unmarshal last update status: %s", err)
	}
	return &endpoint, crdEp.ResourceVersion, nil
}

func (m *provider) getExecutePath(ctx context.Context, name string) (*ssh.Session, string, error) {
	var vm *model.Endpoint
	var err error

	if vm, err = m.Get(ctx, name); err != nil {
		return nil, "", err
	}

	agent, err := m.nodeManager.GetAgent(vm.Status.Host)
	if err != nil {
		return nil, "", fmt.Errorf("get agent %s client: %s", vm.Status.Host, err)
	}

	client, err := agent.GetClient()
	if err != nil {
		return nil, "", fmt.Errorf("get agent %s client: %s", vm.Status.Host, err)
	}

	session, err := client.NewSession()
	return session, vm.Status.LocalID, err
}

func (m *provider) setupNewEndpoint(endpoint *model.Endpoint) error {
	var agent *node.Agent
	var client *ssh.Client
	var err error

	if endpoint.Status == nil {
		endpoint.Status = &model.EndpointStatus{}
	}

	if endpoint.Status.LocalID == "" {
		endpoint.Status.LocalID = rand.String(6)
	}

	if endpoint.Status.IPAddr == "" {
		ipAddr, err := m.ipPool.AssignFromSubnet(endpoint.ExpectSubnet)
		if err != nil {
			return fmt.Errorf("failed assign ipaddr for %s: %s", endpoint.Name, err)
		}
		endpoint.Status.IPAddr = ipAddr
	}

	if endpoint.Status.Host == "" {
		agent, err = m.nodeManager.GetRandomAgent()
		if err != nil {
			return err
		}
		endpoint.Status.Host = agent.Name
	} else {
		agent, err = m.nodeManager.GetAgent(endpoint.Status.Host)
		if err != nil {
			return err
		}
	}

	if client, err = agent.GetClient(); err != nil {
		return err
	}

	return runStartNewEndpoint(client, endpoint.Status.LocalID, agent.BridgeName, endpoint.Status.IPAddr, endpoint.TCPPort, endpoint.UDPPort, endpoint.VID, endpoint.Proto)
}

func (m *provider) destroyEndpoint(endpoint *model.Endpoint) error {
	agent, err := m.nodeManager.GetAgent(endpoint.Status.Host)
	if err != nil {
		return fmt.Errorf("get agent %s client: %s", endpoint.Status.Host, err)
	}

	client, err := agent.GetClient()
	if err != nil {
		return fmt.Errorf("get agent %s client: %s", endpoint.Status.Host, err)
	}

	err = runDestroyEndpoint(client, endpoint.Status.LocalID)
	if err != nil {
		return fmt.Errorf("unable delete endpoint %s on agent %s: %s", endpoint.Name, endpoint.Status.Host, err)
	}
	return nil
}

func toCrdEndpoint(endpoint *model.Endpoint, resourceVersion string) *v1alpha1.Endpoint {
	var securityEp = v1alpha1.Endpoint{}

	securityEp.Name = endpoint.Name
	securityEp.ResourceVersion = resourceVersion

	data, _ := json.Marshal(endpoint)
	securityEp.Annotations = map[string]string{endpointLastStatusAnnotation: string(data)}

	securityEp.Spec = v1alpha1.EndpointSpec{
		ExtendLabels: endpoint.Labels,
		Reference: v1alpha1.EndpointReference{
			ExternalIDName:  "iface-id",
			ExternalIDValue: fmt.Sprintf("uuid-%s", endpoint.Status.LocalID),
		},
	}
	return &securityEp
}
