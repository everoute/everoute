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

package config

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/samber/lo"
	"gopkg.in/yaml.v3"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	corescheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/remotecommand"

	"github.com/everoute/everoute/plugin/tower/pkg/client"
)

// Config of everoute e2e framework
type Config struct {
	KubeConfigPath string `yaml:"kube-config-path,omitempty"`
	// KubeConfig connect to kube-apiserver
	KubeConfig *rest.Config `yaml:"kube-config,omitempty"`
	// TowerClient connect to tower
	TowerClient *client.Client `yaml:"tower-client,omitempty"`

	Endpoint     EndpointConfig     `yaml:"endpoint"`
	GlobalPolicy GlobalPolicyConfig `yaml:"globalPolicy,omitempty"`
	Nodes        NodesConfig        `yaml:"nodes,omitempty"`
	IPAM         *IPAMConfig        `yaml:"ipam,omitempty"`
	Timeout      *time.Duration     `yaml:"timeout,omitempty"`
	Interval     *time.Duration     `yaml:"interval,omitempty"`

	// In which namespace are endpoints and policies created
	Namespace string `yaml:"namespace,omitempty"`
}

type NodesConfig struct {
	DisableAgentRestarter      bool         `yaml:"disableAgentRestarter,omitempty"`
	DisableControllerRestarter bool         `yaml:"disableControllerRestarter,omitempty"`
	Instances                  []NodeConfig `yaml:"instances,omitempty"`
}

type NodeConfig struct {
	Name           string   `yaml:"name"`
	Roles          []string `yaml:"roles,omitempty"`
	User           string   `yaml:"user,omitempty"`
	DialAddress    string   `yaml:"dial-address,omitempty"`
	Password       *string  `yaml:"password,omitempty"`
	PrivateKeyData *string  `yaml:"private-key-data,omitempty"`
	BridgeName     *string  `yaml:"bridge-name,omitempty"`
}

type EndpointConfig struct {
	// if provider is netns and kubeConfig is empty, config.KubeConfig will use
	KubeConfig *rest.Config `yaml:"kube-config,omitempty"`
	// if provider is tower and towerClient is empty, config.TowerClient will use
	TowerClient *client.Client `yaml:"tower-client,omitempty"`

	// Endpoint Provider, must "tower", "netns", "pod" or nil, default netns
	Provider *string `yaml:"provider,omitempty"`
	// template for create vm, only valid when provider is tower
	VMTemplateID *string `yaml:"vm-template-id,omitempty"`
	// create vm in the specify vds, only valid when provider is tower
	VdsID *string `yaml:"vds-id,omitempty"`
}

type GlobalPolicyConfig struct {
	// if provider is netns and kubeConfig is empty, config.KubeConfig will use
	KubeConfig *rest.Config `yaml:"kube-config,omitempty"`
	// if provider is tower and towerClient is empty, config.TowerClient will use
	TowerClient *client.Client `yaml:"tower-client,omitempty"`

	// Endpoint Provider, must "tower", "kubernetes" or nil, default kubernetes
	Provider *string `yaml:"provider,omitempty"`
	// update the specified ERCluster global action, only valid when provider is tower
	EverouteClusterID *string `yaml:"everouteClusterID,omitempty"`
}

type IPAMConfig struct {
	IPRange string `yaml:"ip-range"`
}

func RegisterTestFlags(config *Config) {
	provider := ""
	config.KubeConfigPath = os.Getenv("Kubeconfig")
	config.Namespace = os.Getenv("Namespace")
	provider = os.Getenv("Provider")

	if provider != "" {
		config.Endpoint.Provider = &provider
		config.Timeout = lo.ToPtr(time.Second * 30)
	}
}

func LoadDefault(kubeConfig string) (*Config, error) {
	var defaultConfigMap = types.NamespacedName{Namespace: metav1.NamespaceSystem, Name: `everoute-e2e-framework-config`}
	return LoadFromConfigMap(kubeConfig, defaultConfigMap)
}

func LoadFromConfigMap(kubeConfigPath string, namespacedName types.NamespacedName) (*Config, error) {
	var config Config
	var err error

	RegisterTestFlags(&config)

	if config.KubeConfigPath == "" {
		config.KubeConfigPath = kubeConfigPath
	}
	config.KubeConfig, err = clientcmd.BuildConfigFromFlags("", config.KubeConfigPath)
	if err != nil {
		return nil, err
	}

	kubeClientset, err := kubernetes.NewForConfig(config.KubeConfig)
	if err != nil {
		return nil, err
	}

	// config from cli
	if config.Endpoint.Provider == nil {
		configMap, err := kubeClientset.CoreV1().ConfigMaps(namespacedName.Namespace).Get(context.Background(), namespacedName.Name, metav1.GetOptions{})
		if err != nil {
			return nil, err
		}

		err = yaml.Unmarshal([]byte(configMap.Data["config"]), &config)
		if err != nil {
			return nil, err
		}
	}

	return verifyAndComplete(&config)
}

func verifyAndComplete(config *Config) (*Config, error) {
	if config.KubeConfig == nil {
		return nil, fmt.Errorf("kubeconfig must set in config")
	}

	if config.Endpoint.KubeConfig == nil {
		config.Endpoint.KubeConfig = config.KubeConfig
	}
	if config.Endpoint.TowerClient == nil {
		config.Endpoint.TowerClient = config.TowerClient
	}

	if config.GlobalPolicy.KubeConfig == nil {
		config.GlobalPolicy.KubeConfig = config.KubeConfig
	}
	if config.GlobalPolicy.TowerClient == nil {
		config.GlobalPolicy.TowerClient = config.TowerClient
	}

	if config.GlobalPolicy.Provider != nil && *config.GlobalPolicy.Provider == "tower" {
		if config.GlobalPolicy.EverouteClusterID == nil {
			return nil, fmt.Errorf("EverouteClusterID must set when provider is tower")
		}
	}

	if config.Endpoint.Provider != nil && *config.Endpoint.Provider == "tower" {
		if config.Endpoint.TowerClient == nil {
			return nil, fmt.Errorf("tower client must set when provider is tower")
		}
		if config.Endpoint.VMTemplateID == nil {
			return nil, fmt.Errorf("vmTemplateID must set when provider is tower")
		}
		if config.Endpoint.VdsID == nil {
			return nil, fmt.Errorf("vdsID must set when provider is tower")
		}
		if _, err := config.Endpoint.TowerClient.Auth(context.Background()); err != nil {
			return nil, fmt.Errorf("could not login tower %s", config.Endpoint.TowerClient.URL)
		}
	}

	if config.IPAM == nil {
		config.IPAM = &IPAMConfig{IPRange: "10.0.0.0/24"}
	}

	var (
		defaultTimeout  = time.Second * 20
		defaultInterval = time.Millisecond * 250
	)

	if config.Timeout == nil {
		config.Timeout = &defaultTimeout
	}

	if config.Interval == nil {
		config.Interval = &defaultInterval
	}

	if config.Namespace == "" {
		config.Namespace = metav1.NamespaceDefault
	}

	return config, nil
}

// ExecCmd exec command on specific pod and wait the command's output.
func ExecCmd(ctx context.Context, kubeConfig *rest.Config, kubeClient *kubernetes.Clientset, name, namespace, container, command string, args ...string) (int, []byte, error) {
	var stdin io.Reader
	var stdout, stderr bytes.Buffer
	var err error
	var rc int

	cmd := append([]string{command}, args...)

	if kubeClient == nil {
		kubeClient, err = kubernetes.NewForConfig(kubeConfig)
		if err != nil {
			return 0, nil, err
		}
	}

	req := kubeClient.CoreV1().RESTClient().Post().Resource("pods").Name(name).
		Namespace(namespace).SubResource("exec")
	option := &corev1.PodExecOptions{
		Command:   cmd,
		Stdin:     true,
		Stdout:    true,
		Stderr:    true,
		TTY:       true,
		Container: container,
	}
	if stdin == nil {
		option.Stdin = false
	}
	req.VersionedParams(
		option,
		corescheme.ParameterCodec,
	)
	exec, err := remotecommand.NewSPDYExecutor(kubeConfig, "POST", req.URL())
	if err != nil {
		return 0, nil, err
	}
	err = exec.StreamWithContext(ctx, remotecommand.StreamOptions{
		Stdin:  stdin,
		Stdout: &stdout,
		Stderr: &stderr,
	})

	if err != nil {
		terminalPrefix := "command terminated with exit code"
		isExit := strings.Contains(err.Error(), terminalPrefix)
		if !isExit {
			return 0, nil, fmt.Errorf("run command %s failed, err: %+v", cmd, err)
		}
		rc, err = strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(err.Error()), terminalPrefix)))
	}

	out := stdout.Bytes()
	out = append(out, stderr.Bytes()...)
	return rc, out, err
}
