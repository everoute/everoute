package main

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
	"k8s.io/klog/v2"

	"github.com/everoute/everoute/pkg/constants"
	cniconst "github.com/everoute/everoute/pkg/constants/cni"
)

const configPath = "/var/lib/everoute/controllerconfig.yaml"

type Options struct {
	metricsAddr          string
	enableLeaderElection bool
	tlsCertDir           string
	namespace            string
	serverPort           int
	serverAddr           string

	Config *controllerConfig
}

type controllerConfig struct {
	EnableCNI bool    `yaml:"enableCNI,omitempty"`
	CNIConf   CNIConf `yaml:"CNIConf,omitempty"`

	// use it to connect kube-apiServer
	APIServer string `yaml:"apiServer,omitempty"`
}

type CNIConf struct {
	EnableProxy     bool   `yaml:"enableProxy,omitempty"`
	EncapMode       string `yaml:"encapMode,omitempty"`
	IPAM            string `yaml:"ipam,omitempty"`
	IPAMCleanPeriod int    `yaml:"ipamCleanPeriod,omitempty"`
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

	return o.Config.CNIConf.EncapMode == cniconst.EncapModeGeneve
}

func (o *Options) getAPIServer() string {
	return o.Config.APIServer
}

func (o *Options) useEverouteIPAM() bool {
	if !o.IsEnableOverlay() {
		return false
	}

	return o.Config.CNIConf.IPAM == cniconst.EverouteIPAM
}

func (o *Options) getIPAMCleanPeriod() int {
	if !o.useEverouteIPAM() {
		return 0
	}

	return o.Config.CNIConf.IPAMCleanPeriod
}

func (o *Options) complete() error {
	config, err := getControllerConfig()
	if err != nil {
		return err
	}
	o.Config = config

	if o.namespace == "" {
		ns := os.Getenv(constants.NamespaceNameENV)
		if ns == "" {
			return fmt.Errorf("can't get controller namespace from env")
		}
		o.namespace = ns
	}

	return o.cniConfigCheck()
}

func (o *Options) cniConfigCheck() error {
	if !o.IsEnableCNI() {
		return nil
	}

	if o.Config.CNIConf.IPAM == cniconst.EverouteIPAM {
		if !o.IsEnableOverlay() || !o.IsEnableProxy() {
			return fmt.Errorf("everoute ipam can only used in overlay mode with everoute proxy")
		}

		if o.Config.CNIConf.IPAMCleanPeriod <= 0 {
			return fmt.Errorf("everoute ipam must set config ipamCleanPeriod and ipamCleanPeriod >= 0")
		}
	}

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

	configData, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read controllerConfig, error: %v. ", err)
	}

	err = yaml.Unmarshal(configData, &controllerConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to Unmarshal controllerConfig, error: %v. ", err)
	}

	return &controllerConfig, nil
}
