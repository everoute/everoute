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

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/klog"
	ctrl "sigs.k8s.io/controller-runtime"

	agentv1alpha1 "github.com/smartxworks/lynx/pkg/apis/agent/v1alpha1"
	groupv1alpha1 "github.com/smartxworks/lynx/pkg/apis/group/v1alpha1"
	policyv1alpha1 "github.com/smartxworks/lynx/pkg/apis/policyrule/v1alpha1"
	securityv1alpha1 "github.com/smartxworks/lynx/pkg/apis/security/v1alpha1"
	endpointctrl "github.com/smartxworks/lynx/pkg/controller/endpoint"
	groupctrl "github.com/smartxworks/lynx/pkg/controller/group"
	policyctrl "github.com/smartxworks/lynx/pkg/controller/policy"
	"github.com/smartxworks/lynx/pkg/webhook"
)

var (
	scheme = runtime.NewScheme()
)

func init() {
	_ = agentv1alpha1.AddToScheme(scheme)
	_ = securityv1alpha1.AddToScheme(scheme)
	_ = groupv1alpha1.AddToScheme(scheme)
	_ = policyv1alpha1.AddToScheme(scheme)
}

func main() {
	var metricsAddr string
	var enableLeaderElection bool
	var tlsCertDir string
	var serverPort int

	flag.StringVar(&metricsAddr, "metrics-addr", "0", "The address the metric endpoint binds to.")
	flag.BoolVar(&enableLeaderElection, "enable-leader-election", true,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")
	flag.StringVar(&tlsCertDir, "tls-certs-dir", "/etc/ssl/certs", "The certs dir for lynx webhook use.")
	flag.IntVar(&serverPort, "port", 9443, "The port for the Lynx controller to serve on.")
	klog.InitFlags(nil)
	flag.Parse()

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:             scheme,
		MetricsBindAddress: metricsAddr,
		Port:               serverPort,
		LeaderElection:     enableLeaderElection,
		LeaderElectionID:   "24d5749e.lynx.smartx.com",
		CertDir:            tlsCertDir,
	})
	if err != nil {
		klog.Fatalf("unable to start manager: %s", err.Error())
	}

	// endpoint controller sync endpoint status from agentinfo.
	if err = (&endpointctrl.EndpointReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		klog.Fatalf("unable to create endpoint controller: %s", err.Error())
	}

	// group controller sync & manager group members.
	if err = (&groupctrl.GroupReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		klog.Fatalf("unable to create group controller: %s", err.Error())
	}

	if err = (&policyctrl.PolicyReconciler{
		Client:     mgr.GetClient(),
		Scheme:     mgr.GetScheme(),
		ReadClient: mgr.GetAPIReader(),
	}).SetupWithManager(mgr); err != nil {
		klog.Fatalf("unable to create policy controller: %s", err.Error())
	}

	// register validate handle
	if err = (&webhook.ValidateWebhook{
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		klog.Fatalf("unable to create crd validate webhook %s", err.Error())
	}

	klog.Info("starting manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		klog.Fatalf("error while running manager: %s", err.Error())
	}
}
