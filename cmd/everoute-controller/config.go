package main

import (
	"fmt"
	"io/ioutil"
	"os"

	"gopkg.in/yaml.v3"
	"k8s.io/klog"

	"github.com/everoute/everoute/pkg/constants"
)

const configPath = "/var/lib/everoute/controllerconfig.yaml"

type Options struct {
	metricsAddr             string
	enableLeaderElection    bool
	tlsCertDir              string
	leaderElectionNamespace string
	serverPort              int

	Config *controllerConfig
}

type controllerConfig struct {
	EnableCNI bool    `yaml:"enableCNI,omitempty"`
	CNIConf   CNIConf `yaml:"CNIConf,omitempty"`
}

type CNIConf struct {
	EnableProxy bool   `yaml:"enableProxy,omitempty"`
	EncapMode   string `yaml:"encapMode,omitempty"`
}

func NewOptions() *Options {
	return &Options{
		Config: &controllerConfig{},
	}
}

func (o *Options) IsEnableCNI() bool {
	return o.Config.EnableCNI
}

func (o *Options) IsEnableProxy() bool {
	if !o.Config.EnableCNI {
		return false
	}

	return o.Config.CNIConf.EnableProxy
}

func (o *Options) IsEnableOverlay() bool {
	if !o.Config.EnableCNI {
		return false
	}

	return o.Config.CNIConf.EncapMode == constants.EncapModeGeneve
}

func (o *Options) complete() error {
	config, err := getControllerConfig()
	if err != nil {
		return err
	}
	o.Config = config
	return nil
}

func getControllerConfig() (*controllerConfig, error) {
	var err error
	controllerConfig := controllerConfig{}

	_, statErr := os.Stat(configPath)
	if statErr != nil && os.IsNotExist(statErr) {
		klog.Infof("Controller config file %s is not exists, cni must has the config, so set cni disable", configPath)
		controllerConfig.EnableCNI = false
		return &controllerConfig, nil
	}

	configData, err := ioutil.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read controllerConfig, error: %v. ", err)
	}

	err = yaml.Unmarshal(configData, &controllerConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to Unmarshal controllerConfig, error: %v. ", err)
	}

	return &controllerConfig, nil
}
