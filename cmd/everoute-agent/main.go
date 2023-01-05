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
	"time"

	corev1 "k8s.io/api/core/v1"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/util/flowcontrol"
	"k8s.io/klog"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	"github.com/everoute/everoute/pkg/agent/controller/policy"
	"github.com/everoute/everoute/pkg/agent/datapath"
	"github.com/everoute/everoute/pkg/agent/proxy"
	"github.com/everoute/everoute/pkg/agent/rpcserver"
	clientsetscheme "github.com/everoute/everoute/pkg/client/clientset_generated/clientset/scheme"
	"github.com/everoute/everoute/pkg/constants"
	"github.com/everoute/everoute/pkg/monitor"
)

var (
	opts *Options
)

func init() {
	utilruntime.Must(corev1.AddToScheme(clientsetscheme.Scheme))
}

func main() {
	// init opts
	opts = NewOptions()

	// parse cmd param
	flag.StringVar(&opts.metricsAddr, "metrics-addr", "0", "The address the metric endpoint binds to.")
	klog.InitFlags(nil)
	flag.Parse()
	defer klog.Flush()

	// Init everoute datapathManager: init bridge chain config and default flow
	stopChan := ctrl.SetupSignalHandler()
	ofPortIPAddrMoniotorChan := make(chan map[string]net.IP, 1024)

	// complete options
	err := opts.complete()
	if err != nil {
		klog.Fatalf("Failed to complete options. error: %v. ", err)
	}

	// TODO Update vds which is managed by everoute agent from datapathConfig.
	datapathConfig := opts.getDatapathConfig()
	datapathManager := datapath.NewDatapathManager(datapathConfig, ofPortIPAddrMoniotorChan)
	datapathManager.InitializeDatapath(stopChan)

	ovsdbMonitor, err := monitor.NewOVSDBMonitor()
	if err != nil {
		klog.Fatalf("unable to create ovsdb monitor: %s", err.Error())
	}
	ovsdbMonitor.RegisterOvsdbEventHandler(monitor.OvsdbEventHandlerFuncs{
		LocalEndpointAddFunc: func(endpoint *datapath.Endpoint) {
			err := datapathManager.AddLocalEndpoint(endpoint)
			if err != nil {
				klog.Errorf("Failed to add local endpoint: %+v, error: %+v", endpoint, err)
			}
		},
		LocalEndpointDeleteFunc: func(endpoint *datapath.Endpoint) {
			err := datapathManager.RemoveLocalEndpoint(endpoint)
			if err != nil {
				klog.Errorf("Failed to del local endpoint with OfPort: %+v, error: %+v", endpoint, err)
			}
		},
		LocalEndpointUpdateFunc: func(newEndpoint, oldEndpoint *datapath.Endpoint) {
			err := datapathManager.UpdateLocalEndpoint(newEndpoint, oldEndpoint)
			if err != nil {
				klog.Errorf("Failed to update local endpoint from %v to %v, error: %v", oldEndpoint, newEndpoint, err)
			}
		},
	})
	go ovsdbMonitor.Run(stopChan)

	if err := datapath.ExcuteCommand("sudo %s", "conntrack -F"); err != nil {
		klog.Error("Clean conntrack failed, err:", err)
	} else {
		klog.Info("Clean conntrack success.")
	}

	var mgr manager.Manager
	config := ctrl.GetConfigOrDie()
	config.RateLimiter = flowcontrol.NewTokenBucketRateLimiter(constants.ControllerRuntimeQPS, constants.ControllerRuntimeBurst)

	// loop initialize manager until success or stop
	err = wait.PollImmediateUntil(time.Second, func() (bool, error) {
		mgr, err = ctrl.NewManager(config, ctrl.Options{
			Scheme:             clientsetscheme.Scheme,
			MetricsBindAddress: opts.metricsAddr,
			Port:               9443,
		})
		if err != nil {
			klog.Errorf("unable to create manager: %s", err.Error())
		}
		return err == nil, nil
	}, stopChan)
	if err != nil {
		klog.Fatalf("unable to create manager: %s", err.Error())
	}

	k8sClient := mgr.GetClient()

	if opts.IsEnableCNI() {
		setAgentConf(datapathManager, mgr.GetAPIReader())
		datapathManager.InitializeCNI()
	}

	if err = startManager(mgr, datapathManager, stopChan); err != nil {
		klog.Fatalf("error %v when start controller manager.", err)
	}

	agentmonitor := monitor.NewAgentMonitor(k8sClient, ovsdbMonitor, ofPortIPAddrMoniotorChan)
	go agentmonitor.Run(stopChan)

	rpcServer := rpcserver.Initialize(datapathManager, k8sClient, opts.IsEnableCNI())
	go rpcServer.Run(stopChan)

	<-stopChan
}

func startManager(mgr manager.Manager, datapathManager *datapath.DpManager, stopChan <-chan struct{}) error {
	var err error
	// Policy controller: watch policy related resource and update
	if err = (&policy.Reconciler{
		Client:          mgr.GetClient(),
		Scheme:          mgr.GetScheme(),
		DatapathManager: datapathManager,
	}).SetupWithManager(mgr); err != nil {
		klog.Fatalf("unable to create policy controller: %s", err.Error())
	}

	if opts.IsEnableCNI() {
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
