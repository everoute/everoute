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

	"github.com/contiv/libOpenflow/protocol"
	corev1 "k8s.io/api/core/v1"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/util/flowcontrol"
	"k8s.io/klog"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	"github.com/everoute/everoute/pkg/agent/cniserver"
	activeprobectrl "github.com/everoute/everoute/pkg/agent/controller/activeprobe"
	"github.com/everoute/everoute/pkg/agent/controller/policy"
	"github.com/everoute/everoute/pkg/agent/datapath"
	"github.com/everoute/everoute/pkg/agent/proxy"
	clientsetscheme "github.com/everoute/everoute/pkg/client/clientset_generated/clientset/scheme"
	"github.com/everoute/everoute/pkg/constants"
	"github.com/everoute/everoute/pkg/exporter"
	"github.com/everoute/everoute/pkg/monitor"
	"github.com/everoute/everoute/pkg/utils"
)

var (
	enableCNI      bool
	enableExporter bool
	metricsAddr    string
	kafkaHosts     string
)

func init() {
	utilruntime.Must(corev1.AddToScheme(clientsetscheme.Scheme))
}

func main() {
	flag.BoolVar(&enableCNI, "enable-cni", false, "Enable CNI in agent.")
	flag.BoolVar(&enableExporter, "enable-exporter", false, "Enable Exporter in agent.")
	flag.StringVar(&metricsAddr, "metrics-addr", "0", "The address the metric endpoint binds to.")
	flag.StringVar(&kafkaHosts, "kafka-host", "192.168.24.37:30991", "Kafka hosts")
	klog.InitFlags(nil)
	flag.Parse()
	defer klog.Flush()

	// Init everoute datapathManager: init bridge chain config and default flow
	stopChan := ctrl.SetupSignalHandler()
	ofPortIPAddrMoniotorChan := make(chan map[string]net.IP, 1024)

	// arp channel from datapath to exporter
	var arpChan chan protocol.ARP
	var exp *exporter.Exporter
	if enableExporter {
		exp = exporter.NewExporter(exporter.NewKafkaUploader(kafkaHosts, utils.CurrentAgentName(), stopChan))
		arpChan = exp.AgentArpChan
	}

	// TODO Update vds which is managed by everoute agent from datapathConfig.
	datapathConfig, err := datapath.GetDatapathConfig()
	if err != nil {
		klog.Fatalf("Failed to get datapath config. error: %v. ", err)
	}
	datapathManager := datapath.NewDatapathManager(datapathConfig, arpChan, ofPortIPAddrMoniotorChan)
	datapathManager.InitializeDatapath(stopChan)

	if enableExporter {
		go exp.StartExporter(datapathManager, stopChan)
	}

	config := ctrl.GetConfigOrDie()
	config.RateLimiter = flowcontrol.NewTokenBucketRateLimiter(constants.ControllerRuntimeQPS, constants.ControllerRuntimeBurst)
	mgr, err := ctrl.NewManager(config, ctrl.Options{
		Scheme:             clientsetscheme.Scheme,
		MetricsBindAddress: metricsAddr,
		Port:               9443,
	})
	if err != nil {
		klog.Fatalf("unable to create manager: %s", err.Error())
	}

	k8sClient := mgr.GetClient()

	if enableCNI {
		datapath.SetAgentConf(datapathManager, mgr.GetAPIReader())
		// cni server
		cniServer := cniserver.Initialize(k8sClient, datapathManager)
		go cniServer.Run(stopChan)
	}

	datapathManager.InitializeCNI()

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
		LocalEndpointUpdateFunc: func(newEndpoint, oldEndpoint datapath.Endpoint) {
			err := datapathManager.UpdateLocalEndpoint(&newEndpoint, &oldEndpoint)
			if err != nil {
				klog.Errorf("Failed to update local endpoint from %v to %v, error: %v", oldEndpoint, newEndpoint, err)
			}
		},
	})
	go agentmonitor.Run(stopChan)

	<-stopChan
	time.Sleep(time.Second * 5)
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

	// activeprobe controller
	if err = (&activeprobectrl.ActiveprobeController{
		K8sClient:          mgr.GetClient(),
		Scheme:             mgr.GetScheme(),
		DatapathManager:    datapathManager,
		RunningActiveprobe: make(map[uint8]string),
	}).SetupWithManager(mgr); err != nil {
		klog.Fatalf("unable to create active probe controller: %s", err.Error())
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
