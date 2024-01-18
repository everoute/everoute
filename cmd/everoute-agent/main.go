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
	"time"

	corev1 "k8s.io/api/core/v1"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/record"
	"k8s.io/client-go/util/flowcontrol"
	"k8s.io/klog"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	"github.com/everoute/everoute/pkg/agent/controller/policy"
	ctrlProxy "github.com/everoute/everoute/pkg/agent/controller/proxy"
	"github.com/everoute/everoute/pkg/agent/datapath"
	"github.com/everoute/everoute/pkg/agent/proxy"
	"github.com/everoute/everoute/pkg/agent/rpcserver"
	"github.com/everoute/everoute/pkg/client/clientset_generated/clientset"
	clientsetscheme "github.com/everoute/everoute/pkg/client/clientset_generated/clientset/scheme"
	"github.com/everoute/everoute/pkg/constants"
	evehealthz "github.com/everoute/everoute/pkg/healthz"
	"github.com/everoute/everoute/pkg/monitor"
	"github.com/everoute/everoute/pkg/types"
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
	flag.BoolVar(&opts.disableProbeTimeoutIP, "disable-probe-timeout-ip", false, "Disable probe timeout ip with arp.")
	klog.InitFlags(nil)
	flag.Parse()
	defer klog.Flush()

	// Init everoute datapathManager: init bridge chain config and default flow
	stopChan := ctrl.SetupSignalHandler()
	ofportIPMonitorChan := make(chan *types.EndpointIP, 1024)
	proxySyncChan := make(chan event.GenericEvent)
	config := ctrl.GetConfigOrDie()
	config.RateLimiter = flowcontrol.NewTokenBucketRateLimiter(constants.ControllerRuntimeQPS, constants.ControllerRuntimeBurst)

	// complete options
	err := opts.complete()
	if err != nil {
		klog.Fatalf("Failed to complete options. error: %v. ", err)
	}

	// TODO Update vds which is managed by everoute agent from datapathConfig.
	datapathConfig := opts.getDatapathConfig()
	datapathManager := datapath.NewDatapathManager(datapathConfig, ofportIPMonitorChan)
	datapathManager.InitializeDatapath(stopChan)

	var mgr manager.Manager
	if opts.IsEnableCNI() {
		// in the cni scenario, cni initialization must precede ovsdb monitor initialization
		mgr = initK8sCtrlManager(config, stopChan)
		initCNI(datapathManager, mgr, proxySyncChan)
		startMonitor(datapathManager, config, ofportIPMonitorChan, stopChan)
	} else {
		// In the virtualization scenario, k8sCtrl manager initializer reply on ovsdbmonitor initialization to connect to kube-apiserver
		startMonitor(datapathManager, config, ofportIPMonitorChan, stopChan)
		mgr = initK8sCtrlManager(config, stopChan)
	}

	// add health check handler
	loadModuleHealthz := evehealthz.NewLoadModuleHealthz(constants.AlgNeedModules)
	err = mgr.AddMetricsExtraHandler(constants.HealthCheckPath, healthz.CheckHandler{Checker: loadModuleHealthz.Check})
	if err != nil {
		klog.Fatalf("failed to add health check handler: %s", err)
	}

	proxyCache, err := startManager(mgr, datapathManager, stopChan, proxySyncChan)
	if err != nil {
		klog.Fatalf("error %v when start controller manager.", err)
	}

	rpcServer := rpcserver.Initialize(datapathManager, mgr.GetClient(), opts.IsEnableCNI(), proxyCache)
	go rpcServer.Run(stopChan)

	<-stopChan
}

func initCNI(datapathManager *datapath.DpManager, mgr manager.Manager, proxySyncChan chan event.GenericEvent) {
	if opts.IsEnableProxy() {
		proxyReplayFunc := func() {
			proxySyncChan <- ctrlProxy.NewReplayEvent()
		}
		datapathManager.SetProxySyncFunc(proxyReplayFunc)
	}
	setAgentConf(datapathManager, mgr.GetAPIReader())
	datapathManager.InitializeCNI()
}

func initK8sCtrlManager(config *rest.Config, stopChan <-chan struct{}) manager.Manager {
	var mgr manager.Manager
	var err error

	// create eventBroadcaster before manager to avoid goroutine leakage: kubernetes-sigs/controller-runtime#637
	eventBroadcaster := record.NewBroadcaster()

	// loop initialize manager until success or stop
	err = wait.PollImmediateUntil(time.Second, func() (bool, error) {
		mgr, err = ctrl.NewManager(config, ctrl.Options{
			Scheme:             clientsetscheme.Scheme,
			MetricsBindAddress: opts.metricsAddr,
			EventBroadcaster:   eventBroadcaster,
		})
		if err != nil {
			klog.Errorf("unable to create manager: %s", err.Error())
		}
		return err == nil, nil
	}, stopChan)
	if err != nil {
		klog.Fatalf("unable to create manager: %s", err.Error())
	}
	return mgr
}

func startMonitor(datapathManager *datapath.DpManager, config *rest.Config, ofportIPMonitorChan chan *types.EndpointIP, stopChan <-chan struct{}) {
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

	agentmonitor := monitor.NewAgentMonitor(&monitor.NewAgentMonitorOptions{
		DisableProbeTimeoutIP:  opts.disableProbeTimeoutIP,
		ProbeTimeoutIPCallback: datapathManager.HandleEndpointIPTimeout,
		Clientset:              clientset.NewForConfigOrDie(config),
		OVSDBMonitor:           ovsdbMonitor,
		OFPortIPMonitorChan:    ofportIPMonitorChan,
	})

	go ovsdbMonitor.Run(stopChan)
	go agentmonitor.Run(stopChan)
}

func startManager(mgr manager.Manager, datapathManager *datapath.DpManager, stopChan <-chan struct{}, proxySyncChan chan event.GenericEvent) (*ctrlProxy.Cache, error) {
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
			return nil, err
		}
	}

	var proxyCache *ctrlProxy.Cache
	if opts.IsEnableProxy() {
		proxyReconciler := &ctrlProxy.Reconciler{
			Client:   mgr.GetClient(),
			Scheme:   mgr.GetScheme(),
			DpMgr:    datapathManager,
			SyncChan: proxySyncChan,
		}
		if err = proxyReconciler.SetupWithManager(mgr); err != nil {
			klog.Errorf("unable to create proxy controller: %s", err.Error())
			return nil, err
		}
		proxyCache = proxyReconciler.GetCache()
	}

	klog.Info("starting manager")
	go func() {
		if err := mgr.Start(stopChan); err != nil {
			klog.Fatalf("error while start manager: %s", err.Error())
		}
	}()

	return proxyCache, nil
}
