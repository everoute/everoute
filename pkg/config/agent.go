package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

const agentConfigFilePath = "/var/lib/everoute/agentconfig.yaml"

type CNIConf struct {
	EnableProxy      bool   `yaml:"enableProxy,omitempty"`
	EncapMode        string `yaml:"encapMode,omitempty"`
	MTU              int    `yaml:"mtu,omitempty"`
	IPAM             string `yaml:"ipam,omitempty"`
	LocalGwIP        string `yaml:"localGwIP,omitempty"`
	KubeProxyReplace bool   `yaml:"kubeProxyReplace,omitempty"`
	SvcInternalIP    string `yaml:"svcInternalIP,omitempty"`
}

type VdsConfig struct {
	BrideName string `yaml:"bridgeName"`
	EnableMS  bool   `yaml:"enableMS"`
	// if len=0, disable trafficRedirect
	TrafficRedirects []TRConfig `yaml:"trafficRedirects,omitempty"`
}

type TRConfig struct {
	// iface id
	NicIn string `yaml:"nicIn"`
	// iface id
	NicOut string `yaml:"nicOut"`
}

type AgentConfig struct {
	// remain for cni
	DatapathConfig map[string]string `yaml:"datapathConfig"`
	// key is vds id
	VdsConfigs map[string]VdsConfig `yaml:"vdsConfigs"`

	// InternalIPs allow the items all ingress and egress traffics
	InternalIPs []string `yaml:"internalIPs,omitempty"`

	// use it to connect kube-apiServer
	APIServer string `yaml:"apiServer,omitempty"`

	// cni config
	EnableCNI bool    `yaml:"enableCNI,omitempty"`
	CNIConf   CNIConf `yaml:"CNIConf,omitempty"`
}

func (a *AgentConfig) IsEnableMS() bool {
	if a.EnableCNI {
		return true
	}

	for k := range a.VdsConfigs {
		if a.VdsConfigs[k].EnableMS {
			return true
		}
	}
	return false
}

func (a *AgentConfig) IsEnableTR() bool {
	if a.EnableCNI {
		return false
	}
	for k := range a.VdsConfigs {
		if len(a.VdsConfigs[k].TrafficRedirects) > 0 {
			return true
		}
	}
	return false
}

func GetAgentConfig() (*AgentConfig, error) {
	var err error
	agentConfig := AgentConfig{}

	configdata, err := os.ReadFile(agentConfigFilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read agentConfig, error: %v. ", err)
	}

	err = yaml.Unmarshal(configdata, &agentConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to Unmarshal agentConfig, error: %v. ", err)
	}

	return &agentConfig, nil
}
