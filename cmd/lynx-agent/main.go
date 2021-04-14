/*
Copyright 2021 The Lynx Authors.

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
	"flag"
	"net"
	"time"

	"github.com/contiv/ofnet"
	"github.com/contiv/ofnet/ovsdbDriver"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/klog"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	"github.com/smartxworks/lynx/pkg/agent/controller/policyrule"
	agentv1alpha1 "github.com/smartxworks/lynx/pkg/apis/agent/v1alpha1"
	networkpolicyv1alpha1 "github.com/smartxworks/lynx/pkg/apis/policyrule/v1alpha1"
	"github.com/smartxworks/lynx/pkg/monitor"
)

var (
	scheme = runtime.NewScheme()
)

func init() {
	_ = networkpolicyv1alpha1.AddToScheme(scheme)
	_ = agentv1alpha1.AddToScheme(scheme)
}

func main() {
	// Init ofnetAgent: init config and default flow
	stopChan := ctrl.SetupSignalHandler()
	ofPortIpAddrMoniotorChan := make(chan map[uint32][]net.IP, 1024)
	agentConfig, err := getAgentConfig()
	if err != nil {
		klog.Fatalf("error %v when get agentconfig.", err)
	}
	uplinkConfig := initUplinkConfig(agentConfig)

	localIp := net.ParseIP(agentConfig.LocalIp)
	var uplinks []string
	if len(agentConfig.UplinkInfo.Links) == 0 {
		klog.Fatalf("error when get uplink config")
	}
	for _, link := range agentConfig.UplinkInfo.Links {
		uplinks = append(uplinks, link.LinkInterfaceName)
	}

	ovsDriver := ovsdbDriver.NewOvsDriver(agentConfig.BridgeName)
	err = ovsDriver.AddController(agentConfig.LocalIp, agentConfig.OvsCtlPort)
	if err != nil {
		klog.Fatalf("error %v when config ovs controller.", err)
	}

	vlanArpLearnerAgent, err := ofnet.NewOfnetAgent(
		agentConfig.BridgeName, agentConfig.DatapathName,
		localIp, agentConfig.RpcPort, agentConfig.OvsCtlPort,
		uplinkConfig, uplinks, ofPortIpAddrMoniotorChan)
	if err != nil {
		klog.Fatalf("error %v when init ofnetAgent.", err)
	}

	// We need to wait for long enough to guarantee that datapath completes flowtable initialize. It is a temporary
	// method.
	// Implement datapath initialized status Synchronization mechanism. TODO
	time.Sleep(5 * time.Second)

	// NetworkPolicy controller: watch policyRule crud and update flow
	mgr, err := startManager(scheme, vlanArpLearnerAgent, stopChan)
	if err != nil {
		klog.Fatalf("error %v when start controller manager.", err)
	}

	k8sClient := mgr.GetClient()
	agentmonitor, err := monitor.NewAgentMonitor(k8sClient, ofPortIpAddrMoniotorChan)
	if err != nil {
		klog.Fatalf("error %v when start agentmonitor.", err)
	}
	agentmonitor.RegisterOvsdbEventHandler(monitor.OvsdbEventHandlerFuncs{
		LocalEndpointAddFunc: func(endpointInfo ofnet.EndpointInfo) {
			err := vlanArpLearnerAgent.AddLocalEndpoint(endpointInfo)
			if err != nil {
				klog.Errorf("Failed to add local endpoint: %+v, error: %+v", endpointInfo, err)
			}
		},
		LocalEndpointDeleteFunc: func(portNo uint32) {
			err := vlanArpLearnerAgent.RemoveLocalEndpoint(portNo)
			if err != nil {
				klog.Errorf("Failed to del local endpoint with OfPort: %+v, error: %+v", portNo, err)
			}
		},
		UplinkActiveSlaveUpdateFunc: func(uplinkName string, updates ofnet.PortUpdates) {
			err := vlanArpLearnerAgent.UpdateUplink(uplinkName, updates)
			if err != nil {
				klog.Errorf("Failed to update uplink: %+v active slave, error: %+v", uplinkName, err)
			}
		},
		UplinkAddFunc: func(port *ofnet.PortInfo) {
			err := vlanArpLearnerAgent.AddUplink(port)
			if err != nil {
				klog.Errorf("Failed to add uplink: %+v, error: %+v", port, err)
			}
		},
		UplinkDelFunc: func(portName string) {
			err := vlanArpLearnerAgent.RemoveUplink(portName)
			if err != nil {
				klog.Errorf("Failed to del uplink: %+v, error: %+v", portName, err)
			}
		},
	})

	go agentmonitor.Run(stopChan)

	<-stopChan
}

func startManager(scheme *runtime.Scheme, agent *ofnet.OfnetAgent, stopChan <-chan struct{}) (manager.Manager, error) {
	var metricsAddr string
	flag.StringVar(&metricsAddr, "metrics-addr", "0", "The address the metric endpoint binds to.")
	klog.InitFlags(nil)
	flag.Parse()

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:             scheme,
		MetricsBindAddress: metricsAddr,
		Port:               9443,
	})
	if err != nil {
		klog.Errorf("unable to start manager: %s", err.Error())
		return nil, err
	}

	if err = (&policyrule.PolicyRuleReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
		Agent:  agent,
	}).SetupWithManager(mgr); err != nil {
		klog.Errorf("unable to create policyrule controller: %s", err.Error())
		return nil, err
	}

	klog.Info("starting manager")
	go func() {
		if err := mgr.Start(stopChan); err != nil {
			klog.Fatalf("error while start manager: %s", err.Error())
		}
	}()

	return mgr, nil
}
