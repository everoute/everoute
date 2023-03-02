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

package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	cnitypes "github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/plugins/pkg/ip"
	"gopkg.in/yaml.v2"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/klog"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/everoute/everoute/pkg/agent/datapath"
	"github.com/everoute/everoute/pkg/constants"
	"github.com/everoute/everoute/pkg/utils"
)

const agentConfigFilePath = "/var/lib/everoute/agentconfig.yaml"

type Options struct {
	Config *agentConfig

	metricsAddr string
}

type CNIConf struct {
	EnableProxy bool `yaml:"enableProxy,omitempty"`
}

type agentConfig struct {
	DatapathConfig map[string]string `yaml:"datapathConfig"`

	// InternalIPs allow the items all ingress and egress traffics
	InternalIPs []string `yaml:"internalIPs,omitempty"`

	// cni config
	EnableCNI bool    `yaml:"enableCNI,omitempty"`
	CNIConf   CNIConf `yaml:"CNIConf,omitempty"`
}

func NewOptions() *Options {
	return &Options{
		Config: &agentConfig{},
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

func (o *Options) complete() error {
	agentConfig, err := getAgentConfig()
	if err != nil {
		return fmt.Errorf("failed to get agentConfig, error: %v. ", err)
	}
	o.Config = agentConfig
	return nil
}

func (o *Options) getDatapathConfig() *datapath.DpManagerConfig {
	agentConfig := o.Config

	dpConfig := &datapath.DpManagerConfig{
		InternalIPs:      agentConfig.InternalIPs,
		EnableIPLearning: true,
		EnableCNI:        agentConfig.EnableCNI,
	}

	// cni disable ip learning
	if dpConfig.EnableCNI {
		dpConfig.EnableIPLearning = false
	}

	managedVDSMap := make(map[string]string)
	for managedvds, ovsbrname := range agentConfig.DatapathConfig {
		managedVDSMap[managedvds] = ovsbrname
	}
	dpConfig.ManagedVDSMap = managedVDSMap

	if dpConfig.EnableCNI {
		cniConfig := &datapath.DpManagerCNIConfig{
			EnableProxy: agentConfig.CNIConf.EnableProxy,
		}
		dpConfig.CNIConfig = cniConfig
	}

	return dpConfig
}

func setAgentConf(datapathManager *datapath.DpManager, k8sReader client.Reader) {
	var err error

	k8sClient := k8sReader.(client.Client)
	agentInfo := datapathManager.Info
	agentInfo.NodeName = os.Getenv(constants.AgentNodeNameENV)

	node := corev1.Node{}
	if err = k8sClient.Get(context.Background(), client.ObjectKey{
		Name: agentInfo.NodeName,
	}, &node); err != nil {
		klog.Fatalf("get node info error, err:%s", err)
	}

	// record all pod CIDRs
	for _, cidrString := range node.Spec.PodCIDRs {
		cidr, _ := cnitypes.ParseCIDR(cidrString)
		agentInfo.PodCIDR = append(agentInfo.PodCIDR, cnitypes.IPNet(*cidr))
	}
	if len(agentInfo.PodCIDR) == 0 {
		klog.Fatalf("PodCIDR should be specified when setup kubernetes cluster. E.g. `kubeadm init --pod-network-cidr 10.0.0.0/16`")
	}

	// get cluster CIDR
	pods := corev1.PodList{}
	if err = k8sClient.List(context.Background(), &pods, client.InNamespace("kube-system")); err != nil {
		klog.Fatalf("get pod info error, err:%s", err)
	}

	klog.Info("----g-----")
	loopExit := false
	for _, pod := range pods.Items {
		if loopExit {
			break
		}
		if strings.HasPrefix(pod.Name, "kube-apiserver-") {
			for _, container := range pod.Spec.Containers {
				for _, commond := range container.Command {
					if strings.HasPrefix(commond, "--service-cluster-ip-range=") {
						cidr, _ := cnitypes.ParseCIDR(strings.TrimPrefix(commond, "--service-cluster-ip-range="))
						g := strings.TrimPrefix(commond, "--service-cluster-ip-range=")
						klog.Infof("----g: %+v", g)
						klog.Infof("-----cidr: %+v", *cidr)
						if cidr == nil {
							klog.Fatalf("get service cluster ip range failed")
						}
						cidrNet := cnitypes.IPNet(*cidr)
						agentInfo.ClusterCIDR = &cidrNet
						loopExit = true
					}
				}
			}
		}
	}
	if agentInfo.ClusterCIDR == nil {
		klog.Fatalf("Service cluster CIDR should be specified when setup kubernetes cluster. E.g. `kubeadm init --service-cidr 10.244.0.0/16`")
	}

	for bridge := range datapathManager.OvsdbDriverMap {
		agentInfo.BridgeName = datapathManager.OvsdbDriverMap[bridge][datapath.LOCAL_BRIDGE_KEYWORD].OvsBridgeName
		agentInfo.GatewayName = agentInfo.BridgeName + "-gw"
		if !opts.IsEnableProxy() {
			agentInfo.LocalGwName = agentInfo.BridgeName + "-gw-local"
			agentInfo.LocalGwOfPort, err = datapathManager.OvsdbDriverMap[bridge][datapath.LOCAL_BRIDGE_KEYWORD].GetOfpPortNo(agentInfo.LocalGwName)
			if err != nil {
				klog.Fatalf("fetch local gateway ofport error, err: %s", err)
			}
		}
		break // only one VDS in CNI scene
	}

	if !opts.IsEnableProxy() {
		// get gateway ip and mac
		localGwIP, err := utils.GetIfaceIP(agentInfo.LocalGwName)
		if err != nil {
			klog.Fatalf("Failed to get local gateway ip address, error:%s", err)
		}
		localGwMac, err := utils.GetIfaceMAC(agentInfo.LocalGwName)
		if err != nil {
			klog.Fatalf("Failed to get local gateway mac address, error:%s", err)
		}
		agentInfo.LocalGwIP = localGwIP
		agentInfo.LocalGwMac = localGwMac
	}

	GwMac, err := utils.GetIfaceMAC(agentInfo.GatewayName)
	if err != nil {
		klog.Fatalf("Failed to get gateway mac address, error:%s", err)
	}
	agentInfo.GatewayIP = ip.NextIP(agentInfo.PodCIDR[0].IP)
	agentInfo.GatewayMac = GwMac
}

func getAgentConfig() (*agentConfig, error) {
	var err error
	agentConfig := agentConfig{}

	configdata, err := ioutil.ReadFile(agentConfigFilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read agentConfig, error: %v. ", err)
	}

	err = yaml.Unmarshal(configdata, &agentConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to Unmarshal agentConfig, error: %v. ", err)
	}

	return &agentConfig, nil
}
