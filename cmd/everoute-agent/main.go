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
	"flag"
	"fmt"
	"net"
	"os"
	"time"

	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	coretypes "k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/record"
	"k8s.io/client-go/util/flowcontrol"
	"k8s.io/klog"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	"github.com/everoute/everoute/pkg/agent/controller/overlay"
	"github.com/everoute/everoute/pkg/agent/controller/policy"
	ctrlProxy "github.com/everoute/everoute/pkg/agent/controller/proxy"
	"github.com/everoute/everoute/pkg/agent/datapath"
	"github.com/everoute/everoute/pkg/agent/proxy"
	"github.com/everoute/everoute/pkg/agent/rpcserver"
	"github.com/everoute/everoute/pkg/apis/security/v1alpha1"
	"github.com/everoute/everoute/pkg/client/clientset_generated/clientset"
	clientsetscheme "github.com/everoute/everoute/pkg/client/clientset_generated/clientset/scheme"
	"github.com/everoute/everoute/pkg/constants"
	evehealthz "github.com/everoute/everoute/pkg/healthz"
	"github.com/everoute/everoute/pkg/monitor"
	ersource "github.com/everoute/everoute/pkg/source"
	"github.com/everoute/everoute/pkg/types"
	"github.com/everoute/everoute/pkg/utils"
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
	stopCtx := ctrl.SetupSignalHandler()
	ofportIPMonitorChan := make(chan map[string]net.IP, 1024)
	proxySyncChan := make(chan event.GenericEvent)
	overlaySyncChan := make(chan event.GenericEvent)
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
	datapathManager.InitializeDatapath(stopCtx.Done())

	var mgr manager.Manager
	if opts.IsEnableCNI() {
		// in the cni scenario, cni initialization must precede ovsdb monitor initialization
		mgr = initK8sCtrlManager(config, stopCtx.Done())
		initCNI(datapathManager, mgr, proxySyncChan, overlaySyncChan)
		startMonitor(datapathManager, config, ofportIPMonitorChan, stopCtx.Done())
	} else {
		// In the virtualization scenario, k8sCtrl manager initializer reply on ovsdbmonitor initialization to connect to kube-apiserver
		startMonitor(datapathManager, config, ofportIPMonitorChan, stopCtx.Done())
		mgr = initK8sCtrlManager(config, stopCtx.Done())
	}

	// add health check handler
	loadModuleHealthz := evehealthz.NewLoadModuleHealthz(constants.AlgNeedModules)
	err = mgr.AddMetricsExtraHandler(constants.HealthCheckPath, healthz.CheckHandler{Checker: loadModuleHealthz.Check})
	if err != nil {
		klog.Fatalf("failed to add health check handler: %s", err)
	}

	proxyCache, err := startManager(stopCtx, mgr, datapathManager, proxySyncChan, overlaySyncChan)
	if err != nil {
		klog.Fatalf("error %v when start controller manager.", err)
	}

	rpcServer := rpcserver.Initialize(datapathManager, mgr.GetClient(), opts.IsEnableCNI(), proxyCache)
	go rpcServer.Run(stopCtx.Done())

	if err := resourceUpdate(stopCtx, mgr, datapathManager); err != nil {
		klog.Fatalf("resource update failed when start everoute-agent, err: %v", err)
	}

	<-stopCtx.Done()
}

func initCNI(datapathManager *datapath.DpManager, mgr manager.Manager, proxySyncChan chan event.GenericEvent, overlaySyncChan chan event.GenericEvent) {
	if opts.IsEnableOverlay() {
		overlayReplayFunc := func() {
			overlaySyncChan <- ersource.NewReplayEvent()
		}
		datapathManager.SetOverlaySyncFunc(overlayReplayFunc)
	}
	if opts.IsEnableProxy() {
		proxySyncFunc := func() {
			proxySyncChan <- ersource.NewReplayEvent()
		}
		datapathManager.SetProxySyncFunc(proxySyncFunc)
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

func startMonitor(datapathManager *datapath.DpManager, config *rest.Config, ofportIPMonitorChan chan map[string]net.IP, stopChan <-chan struct{}) {
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

	clientset := clientset.NewForConfigOrDie(config)
	agentmonitor := monitor.NewAgentMonitor(clientset, ovsdbMonitor, ofportIPMonitorChan)

	go ovsdbMonitor.Run(stopChan)
	go agentmonitor.Run(stopChan)
}

func startManager(ctx context.Context, mgr manager.Manager, datapathManager *datapath.DpManager, proxySyncChan chan event.GenericEvent,
	overlaySyncChan chan event.GenericEvent) (*ctrlProxy.Cache, error) {
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
		if err = proxy.SetupRouteAndIPtables(mgr, datapathManager, ctx.Done()); err != nil {
			klog.Fatalf("unable to setup route and iptables controller: %v", err)
		}
	}

	if opts.IsEnableOverlay() {
		uplinkBridgeOverlay := datapathManager.GetUplinkBridgeOverlay()
		if err = (&overlay.Reconciler{
			Client:    mgr.GetClient(),
			Scheme:    mgr.GetScheme(),
			UplinkBr:  uplinkBridgeOverlay,
			LocalNode: datapathManager.Info.NodeName,
			SyncChan:  overlaySyncChan,
		}).SetupWithManager(mgr); err != nil {
			klog.Fatalf("unable to create overlay related controller: %v", err)
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
		if err := mgr.Start(ctx); err != nil {
			klog.Fatalf("error while start manager: %s", err.Error())
		}
	}()

	return proxyCache, nil
}

func resourceUpdate(ctx context.Context, mgr manager.Manager, datapathManager *datapath.DpManager) error {
	mgr.GetCache().WaitForCacheSync(ctx)

	if opts.IsEnableOverlay() {
		err := wait.PollImmediate(5*time.Second, time.Minute, func() (bool, error) {
			err := updateGwEndpoint(mgr.GetClient(), datapathManager)
			return err == nil, nil
		})
		if err == nil {
			klog.Info("Success create or update gw-ep endpoint")
		}
		return err
	}
	return nil
}

func updateGwEndpoint(k8sClient client.Client, datapathManager *datapath.DpManager) error {
	ctx := context.Background()
	ns := os.Getenv(constants.NamespaceNameENV)
	if ns == "" {
		return fmt.Errorf("can't get agent namespace from env to create gw-ep endpoint in overlay mode")
	}
	epName := utils.GetGwEndpointName(datapathManager.Info.NodeName)

	ep := v1alpha1.Endpoint{}
	epReq := coretypes.NamespacedName{
		Namespace: ns,
		Name:      epName,
	}
	err := k8sClient.Get(ctx, epReq, &ep)
	if err != nil {
		if k8serrors.IsNotFound(err) {
			ep = v1alpha1.Endpoint{
				ObjectMeta: metav1.ObjectMeta{
					Name:      epName,
					Namespace: ns,
				},
				Spec: v1alpha1.EndpointSpec{
					Type: v1alpha1.EndpointStatic,
					Reference: v1alpha1.EndpointReference{
						ExternalIDName:  "gw-ep",
						ExternalIDValue: datapathManager.Info.NodeName,
					},
				},
			}
			if err := k8sClient.Create(ctx, &ep); err != nil {
				klog.Errorf("Failed to create gw-ep endpoint: %v", err)
				return err
			}
		} else {
			klog.Errorf("Failed to get gw-ep endpoint: %v", err)
			return err
		}
	}

	if ep.Spec.Type != v1alpha1.EndpointStatic {
		ep.Spec.Type = v1alpha1.EndpointStatic
		if err := k8sClient.Update(ctx, &ep); err != nil {
			klog.Errorf("Failed to update gw-ep endpoint: %v", err)
			return err
		}
	}

	if len(ep.Status.Agents) != 1 || ep.Status.Agents[0] != datapathManager.Info.NodeName ||
		len(ep.Status.IPs) != 1 || string(ep.Status.IPs[0]) != (datapathManager.Info.GatewayIP).String() {
		ep.Status.Agents = []string{datapathManager.Info.NodeName}
		ep.Status.IPs = []types.IPAddress{types.IPAddress(datapathManager.Info.GatewayIP.String())}
		if err := k8sClient.Status().Update(ctx, &ep); err != nil {
			klog.Errorf("Failed to update gw-ep endpoint status: %v", err)
			return err
		}
	}

	return nil
}
