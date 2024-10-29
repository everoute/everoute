/*
Copyright 2024 The Everoute Authors.

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

package pod

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/samber/lo"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	k8sclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/everoute/everoute/tests/e2e/framework/config"
	"github.com/everoute/everoute/tests/e2e/framework/ipam"
	"github.com/everoute/everoute/tests/e2e/framework/model"
	"github.com/everoute/everoute/tests/e2e/framework/node"
)

const (
	epDescKey = "endpoint-description"
)

// provider provide pod from k8s cluster as endpoint
type provider struct {
	ipPool      ipam.Pool
	nodeManager *node.Manager

	kubeClientSet *kubernetes.Clientset
	kubeClient    k8sclient.Client
	kubeConfig    *rest.Config

	namespace string

	// concurrent mutation labels cause mistakes
	mutationLabelLock sync.Mutex
}

func NewProvider(kubeConfig *rest.Config, kubeClient k8sclient.Client, nodeManager *node.Manager, namespace string) model.EndpointProvider {
	p := &provider{
		kubeConfig:  kubeConfig,
		kubeClient:  kubeClient,
		nodeManager: nodeManager,
		namespace:   namespace,
	}

	var err error
	p.kubeClientSet, err = kubernetes.NewForConfig(kubeConfig)
	if err != nil {
		return nil
	}

	return p
}

func (m *provider) Name() string {
	return "pod"
}

func (m *provider) Get(ctx context.Context, name string) (*model.Endpoint, error) {
	req := types.NamespacedName{
		Name:      name,
		Namespace: m.namespace,
	}
	var pod corev1.Pod
	if err := m.kubeClient.Get(ctx, req, &pod); err != nil {
		return nil, fmt.Errorf("get pod error: %s", err)
	}

	return m.toEndpoint(&pod)
}

func (m *provider) List(ctx context.Context) ([]*model.Endpoint, error) {
	var epList []*model.Endpoint

	var podList corev1.PodList
	if err := m.kubeClient.List(ctx, &podList); err != nil {
		return epList, err
	}

	for _, pod := range podList.Items {
		if pod.Annotations == nil || pod.Annotations[epDescKey] == "" {
			continue
		}
		if endpoint, err := m.toEndpoint(&pod); err == nil {
			epList = append(epList, endpoint)
		}
	}

	return epList, nil
}

func (m *provider) Create(ctx context.Context, endpoint *model.Endpoint) (*model.Endpoint, error) {
	var err error
	var description string

	if endpoint.Status == nil {
		endpoint.Status = &model.EndpointStatus{}
	}

	if endpoint.Status.Host == "" {
		agent, err := m.nodeManager.GetRandomAgent()
		if err != nil {
			return nil, err
		}
		endpoint.Status.Host = agent.Name
	}

	if description, err = m.endpointIntoDescription(endpoint); err != nil {
		return nil, err
	}

	// set server port
	cmd := []string{"net-utils", "server", "-s"}
	if endpoint.TCPPort != 0 {
		cmd = append(cmd, "--tcp-ports", fmt.Sprintf("%d", endpoint.TCPPort))
	}
	if endpoint.UDPPort != 0 {
		cmd = append(cmd, "--udp-ports", fmt.Sprintf("%d", endpoint.UDPPort))
	}
	if endpoint.Proto == "FTP" {
		cmd = append(cmd, "--ftp-server", "0.0.0.0")
	}

	pod := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      endpoint.Name,
			Namespace: m.namespace,
			Labels:    m.endpointLabelIntoPodLabel(endpoint),
			Annotations: map[string]string{
				epDescKey: description,
			},
		},
		Spec: corev1.PodSpec{
			NodeName: endpoint.Status.Host,
			Containers: []corev1.Container{{
				Name:            "e2e",
				Image:           "registry.smtx.io/everoute/net-utils",
				Command:         cmd,
				ImagePullPolicy: corev1.PullAlways,
				SecurityContext: &corev1.SecurityContext{
					Privileged: lo.ToPtr(true),
				},
			}},
		},
	}

	// set labels
	for key, value := range endpoint.Labels {
		if len(value[0]) >= 1 {
			pod.Labels[key] = value[0]
		} else {
			pod.Labels[key] = ""
		}
	}
	if err = m.kubeClient.Create(ctx, &pod); err != nil {
		return nil, err
	}
	for {
		_ = m.kubeClient.Get(ctx, types.NamespacedName{
			Name:      pod.Name,
			Namespace: pod.Namespace,
		}, &pod)
		if pod.Status.PodIP != "" {
			break
		}
	}

	endpoint.Status.IPAddr = pod.Status.PodIP + "/32"

	if endpoint.Proto == "FTP" {
		_, _, _ = m.RunCommand(ctx, endpoint.Name, "mkdir", "/ftp")
		_, _, _ = m.RunCommand(ctx, endpoint.Name, "touch", "/ftp/test-ftp")
	}

	return endpoint, nil
}

func (m *provider) Update(ctx context.Context, endpoint *model.Endpoint) (*model.Endpoint, error) {
	// Only Label will updated
	req := types.NamespacedName{
		Name:      endpoint.Name,
		Namespace: m.namespace,
	}
	var pod corev1.Pod
	var err error
	if err = m.kubeClient.Get(ctx, req, &pod); err != nil {
		return nil, fmt.Errorf("get pod error: %s", err)
	}

	if pod.Annotations[epDescKey], err = m.endpointIntoDescription(endpoint); err != nil {
		return nil, err
	}

	pod.Labels = m.endpointLabelIntoPodLabel(endpoint)

	return endpoint, m.kubeClient.Update(ctx, &pod)
}

func (m *provider) Delete(ctx context.Context, name string) error {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: m.namespace,
		},
	}
	_ = m.kubeClient.Delete(ctx, pod)
	for {
		err := m.kubeClient.Get(ctx, client.ObjectKeyFromObject(pod), pod)
		if apierrors.IsNotFound(err) {
			return nil
		}
	}
}

func (m *provider) RenewIP(ctx context.Context, name string) (*model.Endpoint, error) {
	endpoint, err := m.Get(ctx, name)
	if err != nil {
		return endpoint, err
	}
	if err := m.Delete(ctx, name); err != nil {
		return endpoint, err
	}

	endpoint.Status.IPAddr = ""

	return m.Create(ctx, endpoint)
}

func (m *provider) Migrate(ctx context.Context, name string) (*model.Endpoint, error) {
	var endpoint *model.Endpoint
	var err error
	var agent *node.Agent

	if endpoint, err = m.Get(ctx, name); err != nil {
		return nil, err
	}

	if err := m.Delete(ctx, name); err != nil {
		return endpoint, err
	}

	agent, err = m.nodeManager.GetRandomAgent(endpoint.Status.Host)
	if err != nil {
		return nil, err
	}

	endpoint.Status.Host = agent.Name
	endpoint.Status.IPAddr = ""

	return m.Create(ctx, endpoint)
}

func (m *provider) RunScript(ctx context.Context, name string, script []byte, arg ...string) (int, []byte, error) {
	return 0, nil, fmt.Errorf("not implement")
}

func (m *provider) RunCommand(ctx context.Context, name string, cmd string, arg ...string) (int, []byte, error) {

	return config.ExecCmd(ctx, m.kubeConfig, m.kubeClientSet, name, m.namespace, "", cmd, arg...)
}

/*
endpointProvider is designed as a stateless application, so we store endpoint info into vm.description
*/
func (m *provider) toEndpoint(pod *corev1.Pod) (*model.Endpoint, error) {
	var endpoint *model.Endpoint
	err := json.NewDecoder(bytes.NewBufferString(pod.Annotations[epDescKey])).Decode(&endpoint)
	if err != nil {
		return nil, err
	}
	if endpoint.Status.LocalID == "" {
		endpoint.Status.LocalID = string(pod.GetUID())
	}
	endpoint.Status.IPAddr = pod.Status.PodIP + "/32"

	return endpoint, nil
}

func (m *provider) endpointIntoDescription(endpoint *model.Endpoint) (string, error) {
	var description bytes.Buffer
	err := json.NewEncoder(&description).Encode(endpoint)
	return description.String(), err
}

func (m *provider) endpointLabelIntoPodLabel(endpoint *model.Endpoint) map[string]string {
	labels := make(map[string]string)
	for key, value := range endpoint.Labels {
		if len(value[0]) >= 1 {
			labels[key] = value[0]
		} else {
			labels[key] = ""
		}
	}
	return labels
}
