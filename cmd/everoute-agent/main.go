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
	"flag"
	"net"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/klog"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	"github.com/everoute/everoute/pkg/agent/cniserver"
	"github.com/everoute/everoute/pkg/agent/controller/policyrule"
	"github.com/everoute/everoute/pkg/agent/datapath"
	"github.com/everoute/everoute/pkg/agent/proxy"
	agentv1alpha1 "github.com/everoute/everoute/pkg/apis/agent/v1alpha1"
	networkpolicyv1alpha1 "github.com/everoute/everoute/pkg/apis/policyrule/v1alpha1"
	"github.com/everoute/everoute/pkg/monitor"
)

var (
	scheme      = runtime.NewScheme()
	enableCNI   bool
	metricsAddr string
)

func init() {
	_ = networkpolicyv1alpha1.AddToScheme(scheme)
	_ = agentv1alpha1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)
}

func main() {
	flag.BoolVar(&enableCNI, "enable-cni", false, "Enable CNI in agent.")
	flag.StringVar(&metricsAddr, "metrics-addr", "0", "The address the metric endpoint binds to.")
	klog.InitFlags(nil)
	flag.Parse()

	// Init everoute datapathManager: init bridge chain config and default flow
	stopChan := ctrl.SetupSignalHandler()
	ofPortIPAddrMoniotorChan := make(chan map[string][]net.IP, 1024)

	// TODO Update vds which is managed by everoute agent from datapathConfig.
	datapathConfig, err := getDatapathConfig()
	if err != nil {
		klog.Fatalf("Failed to get datapath config. error: %v. ", err)
	}
	datapathManager := datapath.NewDatapathManager(datapathConfig, ofPortIPAddrMoniotorChan)

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:             scheme,
		MetricsBindAddress: metricsAddr,
		Port:               9443,
	})
	if err != nil {
		klog.Fatalf("unable to create manager: %s", err.Error())
	}

	k8sClient := mgr.GetClient()

	if enableCNI {
		setAgentConf(datapathManager, mgr.GetAPIReader())

		// cni server
		cniServer := cniserver.Initialize(k8sClient, datapathManager)
		go cniServer.Run(stopChan)
	}

	datapathManager.InitializeDatapath()

	if err = startManager(mgr, datapathManager, stopChan); err != nil {
		klog.Fatalf("error %v when start controller manager.", err)
	}

	agentmonitor, err := monitor.NewAgentMonitor(k8sClient, ofPortIPAddrMoniotorChan)
	if err != nil {
		klog.Fatalf("error %v when start agentmonitor.", err)
	}
	agentmonitor.RegisterOvsdbEventHandler(monitor.OvsdbEventHandlerFuncs{
		LocalEndpointAddFunc: func(endpoint datapath.Endpoint) {
			err := datapathManager.AddLocalEndpoint(&endpoint)
			if err != nil {
				klog.Errorf("Failed to add local endpoint: %+v, error: %+v", endpoint, err)
			}
		},
		LocalEndpointDeleteFunc: func(endpoint datapath.Endpoint) {
			err := datapathManager.RemoveLocalEndpoint(&endpoint)
			if err != nil {
				klog.Errorf("Failed to del local endpoint with OfPort: %+v, error: %+v", endpoint, err)
			}
		},
	})
	go agentmonitor.Run(stopChan)

	<-stopChan
}

func startManager(mgr manager.Manager, datapathManager *datapath.DpManager, stopChan <-chan struct{}) error {
	var err error
	// NetworkPolicy controller: watch policyRule crud and update flow
	if err = (&policyrule.PolicyRuleReconciler{
		Client:          mgr.GetClient(),
		Scheme:          mgr.GetScheme(),
		DatapathManager: datapathManager,
	}).SetupWithManager(mgr); err != nil {
		klog.Errorf("unable to create policyrule controller: %s", err.Error())
		return err
	}

	if enableCNI {
		if err = (&proxy.NodeReconciler{
			Client:          mgr.GetClient(),
			Scheme:          mgr.GetScheme(),
			DatapathManager: datapathManager,
			StopChan:        stopChan,
		}).SetupWithManager(mgr); err != nil {
			klog.Errorf("unable to create node controller: %s", err.Error())
			return err
		}
	}

	klog.Info("starting manager")
	go func() {
		if err := mgr.Start(stopChan); err != nil {
			klog.Fatalf("error while start manager: %s", err.Error())
		}
	}()

	return nil
}
