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
	ipamv1alpha1 "github.com/everoute/ipam/api/ipam/v1alpha1"
	"github.com/everoute/ipam/pkg/ipam"
	"gopkg.in/yaml.v3"
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
	namespace   string
}

type CNIConf struct {
	EnableProxy bool   `yaml:"enableProxy,omitempty"`
	EncapMode   string `yaml:"encapMode,omitempty"`
	MTU         int    `yaml:"mtu,omitempty"`
	IPAM        string `yaml:"ipam,omitempty"`
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

func (o *Options) IsEnableOverlay() bool {
	if !o.Config.EnableCNI {
		return false
	}

	return o.Config.CNIConf.EncapMode == constants.EncapModeGeneve
}

func (o *Options) UseEverouteIPAM() bool {
	if !o.IsEnableOverlay() {
		return false
	}

	return o.Config.CNIConf.IPAM == constants.EverouteIPAM
}

func (o *Options) complete() error {
	agentConfig, err := getAgentConfig()
	if err != nil {
		return fmt.Errorf("failed to get agentConfig, error: %v. ", err)
	}
	o.Config = agentConfig

	if o.IsEnableCNI() {
		ns := os.Getenv(constants.NamespaceNameENV)
		if ns == "" {
			return fmt.Errorf("can't get agent namespace from env to create gw-ep endpoint in overlay mode")
		}
		o.namespace = ns
		if !o.IsEnableOverlay() {
			if o.Config.CNIConf.IPAM == constants.EverouteIPAM {
				return fmt.Errorf("everoute ipam can only used in overlay mode")
			}
		}
	}

	return nil
}

func (o *Options) getDatapathConfig() *datapath.DpManagerConfig {
	agentConfig := o.Config

	dpConfig := &datapath.DpManagerConfig{
		InternalIPs:      agentConfig.InternalIPs,
		EnableIPLearning: true,
		EnableCNI:        agentConfig.EnableCNI,
	}

	managedVDSMap := make(map[string]string)
	for managedvds, ovsbrname := range agentConfig.DatapathConfig {
		managedVDSMap[managedvds] = ovsbrname
	}
	dpConfig.ManagedVDSMap = managedVDSMap

	if dpConfig.EnableCNI {
		// cni disable ip learning
		dpConfig.EnableIPLearning = false

		// cni config
		cniConfig := &datapath.DpManagerCNIConfig{
			EnableProxy: agentConfig.CNIConf.EnableProxy,
			EncapMode:   agentConfig.CNIConf.EncapMode,
			MTU:         agentConfig.CNIConf.MTU,
			IPAMType:    agentConfig.CNIConf.IPAM,
		}
		dpConfig.CNIConfig = cniConfig
	}

	return dpConfig
}

func setAgentConf(datapathManager *datapath.DpManager, k8sClient client.Client) {
	var err error

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
	if !opts.UseEverouteIPAM() && len(agentInfo.PodCIDR) == 0 {
		klog.Fatalf("PodCIDR should be specified when setup kubernetes cluster. E.g. `kubeadm init --pod-network-cidr 10.0.0.0/16`")
	}

	// get pod mtu
	if datapathManager.Config.CNIConfig.MTU == 0 {
		podMTU, err := getPodMTU(&node)
		if err != nil {
			klog.Fatalf("Failed to get pod mtu, err: %v", err)
		}
		datapathManager.Config.CNIConfig.MTU = podMTU
	}

	// get cluster CIDR and cluster pod cidr
	setClusterCIDR(agentInfo, k8sClient)
	setOfPort(datapathManager)
	setLocalGwInfo(agentInfo)
	setGwInfo(agentInfo, k8sClient)
}

func setClusterCIDR(agentInfo *datapath.DpManagerInfo, k8sClient client.Client) {
	pods := corev1.PodList{}
	if err := k8sClient.List(context.Background(), &pods, client.InNamespace("kube-system")); err != nil {
		klog.Fatalf("get pod info error, err:%s", err)
	}

	for _, pod := range pods.Items {
		if agentInfo.ClusterCIDR != nil && agentInfo.ClusterPodCIDR != nil {
			break
		}
		if strings.HasPrefix(pod.Name, "kube-controller-manager") {
			for _, container := range pod.Spec.Containers {
				for _, commond := range container.Command {
					if strings.HasPrefix(commond, "--service-cluster-ip-range=") {
						cidr, _ := cnitypes.ParseCIDR(strings.TrimPrefix(commond, "--service-cluster-ip-range="))
						cidrNet := cnitypes.IPNet(*cidr)
						agentInfo.ClusterCIDR = &cidrNet
					}
					if strings.HasPrefix(commond, "--cluster-cidr=") {
						cidr, _ := cnitypes.ParseCIDR(strings.TrimPrefix(commond, "--cluster-cidr="))
						agentInfo.ClusterPodCIDR = cidr
					}
				}
			}
		}
	}
	if agentInfo.ClusterCIDR == nil {
		klog.Fatalf("Service cluster CIDR should be specified when setup kubernetes cluster. E.g. `kubeadm init --service-cidr 10.244.0.0/16`")
	}
	if opts.IsEnableOverlay() && !opts.UseEverouteIPAM() && agentInfo.ClusterPodCIDR == nil {
		klog.Fatalf("Cluster pod CIDR should be specified when setup kubernetes cluster, E.g. `kubeadm init --pod-cidr 10.0.0.0/16`")
	}
}

func setOfPort(datapathManager *datapath.DpManager) {
	agentInfo := datapathManager.Info
	var err error

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

		if opts.IsEnableOverlay() {
			agentInfo.GatewayOfPort, err = datapathManager.OvsdbDriverMap[bridge][datapath.UPLINK_BRIDGE_KEYWORD].GetOfpPortNo(agentInfo.GatewayName)
			if err != nil {
				klog.Fatalf("fetch gateway ofport error, err: %v", err)
			}
			tunnelName := agentInfo.BridgeName + "-tunnel"
			agentInfo.TunnelOfPort, err = datapathManager.OvsdbDriverMap[bridge][datapath.UPLINK_BRIDGE_KEYWORD].GetOfpPortNo(tunnelName)
			if err != nil {
				klog.Fatalf("fetch tunnel ofport error, err: %v", err)
			}
		}
		return // only one VDS in CNI scene
	}
}

func setLocalGwInfo(agentInfo *datapath.DpManagerInfo) {
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
}

func setGwInfo(agentInfo *datapath.DpManagerInfo, k8sClient client.Client) {
	GwMac, err := utils.GetIfaceMAC(agentInfo.GatewayName)
	if err != nil {
		klog.Fatalf("Failed to get gateway mac address, error:%s", err)
	}
	agentInfo.GatewayMac = GwMac
	if err := getGatewayIP(agentInfo, k8sClient); err != nil {
		klog.Fatalf("Failed to get gateway ip, err: %v", err)
	}

	if opts.UseEverouteIPAM() {
		agentInfo.Namespace = opts.namespace
	}
}

func getGatewayIP(agentInfo *datapath.DpManagerInfo, k8sClient client.Client) error {
	if !opts.UseEverouteIPAM() {
		agentInfo.GatewayIP = ip.NextIP(agentInfo.PodCIDR[0].IP)
		agentInfo.GatewayMask = agentInfo.PodCIDR[0].Mask
		return nil
	}

	// get from ipam
	netconf := &ipam.NetConf{
		AllocateIdentify: agentInfo.NodeName,
		Type:             ipamv1alpha1.AllocateTypeCNIUsed,
		Pool:             constants.GwIPPoolName,
	}
	ipInfo, err := ipam.InitIpam(k8sClient, opts.namespace).ExecAdd(context.Background(), netconf)
	if err != nil {
		return err
	}
	agentInfo.GatewayIP = ipInfo.IPs[0].Address.IP
	agentInfo.GatewayMask = ipInfo.IPs[0].Address.Mask
	agentInfo.ClusterPodGw = &ipInfo.IPs[0].Gateway
	return nil
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

func getPodMTU(node *corev1.Node) (int, error) {
	nodeIP := utils.GetNodeInternalIP(node)
	if nodeIP == "" {
		return 0, fmt.Errorf("failed to get node mtu for doesn't find node internal IP")
	}
	nodeMTU, err := utils.GetIfaceMTUByIP(nodeIP)
	if err != nil {
		return 0, err
	}
	if nodeMTU <= 0 {
		return 0, fmt.Errorf("find invalid node mtu %d", nodeMTU)
	}

	podMTU := nodeMTU
	if opts.IsEnableOverlay() {
		podMTU = nodeMTU - constants.GeneveHeaderLen
	}

	if podMTU <= 0 {
		return 0, fmt.Errorf("find invalid pod mtu %d", podMTU)
	}
	return podMTU, nil
}
