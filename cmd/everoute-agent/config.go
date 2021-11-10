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
	"github.com/everoute/everoute/pkg/utils"
)

const agentConfigFilePath = "/var/lib/everoute/agentconfig.yaml"

type agentConfig struct {
	DatapathConfig map[string]string `yaml:"datapathConfig"`
	LocalGwIP      string            `yaml:"localGwIP,omitempty"`
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

func getDatapathConfig() (*datapath.Config, error) {
	agentConfig, err := getAgentConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to get agentConfig, error: %v. ", err)
	}

	dpConfig := new(datapath.Config)
	managedVDSMap := make(map[string]string)
	for managedvds, ovsbrname := range agentConfig.DatapathConfig {
		managedVDSMap[managedvds] = ovsbrname
	}
	dpConfig.ManagedVDSMap = managedVDSMap

	return dpConfig, nil
}

func setAgentConf(datapathManager *datapath.DpManager, k8sReader client.Reader) {
	k8sClient := k8sReader.(client.Client)
	agentInfo := datapathManager.AgentInfo
	agentInfo.EnableCNI = true

	nodeName, _ := os.Hostname()
	nodeName = strings.ToLower(nodeName)
	agentInfo.NodeName = nodeName

	node := corev1.Node{}

	if err := k8sClient.Get(context.Background(), client.ObjectKey{
		Name: nodeName,
	}, &node); err != nil {
		klog.Fatalf("get node info error, err:%s", err)
	}

	// record all pod CIDRs
	for _, cidrString := range node.Spec.PodCIDRs {
		cidr, _ := cnitypes.ParseCIDR(cidrString)
		agentInfo.PodCIDR = append(agentInfo.PodCIDR, cnitypes.IPNet(*cidr))
	}

	for bridge := range datapathManager.OvsdbDriverMap {
		agentInfo.BridgeName = datapathManager.OvsdbDriverMap[bridge][datapath.LOCAL_BRIDGE_KEYWORD].OvsBridgeName
		agentInfo.GatewayName = agentInfo.BridgeName + "-gw"
		agentInfo.LocalGwName = agentInfo.BridgeName + "-gw-local"
	}

	// get gateway ip and mac
	localGwIP, err := utils.GetIfaceIP(agentInfo.LocalGwName)
	if err != nil {
		klog.Fatalf("Failed to get local gateway ip address, error:%s", err)
	}
	localGwMac, err := utils.GetIfaceMAC(agentInfo.LocalGwName)
	if err != nil {
		klog.Fatalf("Failed to get local gateway mac address, error:%s", err)
	}
	GwMac, err := utils.GetIfaceMAC(agentInfo.GatewayName)
	if err != nil {
		klog.Fatalf("Failed to get gateway mac address, error:%s", err)
	}

	agentInfo.LocalGwIP = localGwIP
	agentInfo.LocalGwMac = localGwMac
	agentInfo.GatewayIP = ip.NextIP(agentInfo.PodCIDR[0].IP)
	agentInfo.GatewayMac = GwMac
}
