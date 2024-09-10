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

package register

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	corev1 "k8s.io/api/core/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	k8sinformers "k8s.io/client-go/informers"
	k8sclientset "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	"github.com/everoute/everoute/pkg/client/clientset_generated/clientset"
	"github.com/everoute/everoute/pkg/client/informers_generated/externalversions"
	msconst "github.com/everoute/everoute/pkg/constants/ms"
	"github.com/everoute/everoute/plugin/tower/pkg/client"
	"github.com/everoute/everoute/plugin/tower/pkg/controller/computecluster"
	"github.com/everoute/everoute/plugin/tower/pkg/controller/endpoint"
	"github.com/everoute/everoute/plugin/tower/pkg/controller/global"
	"github.com/everoute/everoute/plugin/tower/pkg/controller/policy"
	"github.com/everoute/everoute/plugin/tower/pkg/controller/secret"
	"github.com/everoute/everoute/plugin/tower/pkg/informer"
)

type Options struct {
	// will enable controller if "Enable" empty or true
	Enable       *bool
	Client       *client.Client
	ResyncPeriod time.Duration
	WorkerNumber uint
	Namespace    string
	PodNamespace string
	// which EverouteCluster should synchronize SecurityPolicy from
	EverouteCluster string
	SharedFactory   informer.SharedInformerFactory
}

// InitFlags set and load options from flagset.
func InitFlags(opts *Options, flagset *flag.FlagSet, flagPrefix string) {
	if flagset == nil {
		flagset = flag.CommandLine
	}
	if opts.Enable == nil {
		opts.Enable = new(bool)
	}
	if opts.Client == nil {
		opts.Client = &client.Client{UserInfo: &client.UserInfo{}}
	} else if opts.Client.UserInfo == nil {
		opts.Client.UserInfo = &client.UserInfo{}
	}
	var withPrefix = func(name string) string { return flagPrefix + name }

	flagset.BoolVar(opts.Enable, withPrefix("enable"), false, "If true, tower plugin will start (default false)")
	flagset.StringVar(&opts.Client.URL, withPrefix("endpoint"), os.Getenv("TOWER_ENDPOINT"), "Tower connection address")
	flagset.StringVar(&opts.Client.UserInfo.Username, withPrefix("username"), os.Getenv("TOWER_USERNAME"), "Tower user name for authenticate")
	flagset.BoolVar(&opts.Client.AllowInsecure, withPrefix("allow-insecure"), true, "Tower allow-insecure for authenticate")
	flagset.StringVar(&opts.Client.UserInfo.Source, withPrefix("usersource"), os.Getenv("TOWER_USERSOURCE"), "Tower user source for authenticate")
	flagset.StringVar(&opts.Client.UserInfo.Password, withPrefix("password"), os.Getenv("TOWER_PASSWORD"), "Tower user password for authenticate")
	flagset.StringVar(&opts.Client.TokenFile, withPrefix("token-file"), msconst.DefaultTowerTokenFile, "The file to write cloudPlatform token")
	flagset.StringVar(&opts.Namespace, withPrefix("namespace"), "tower-space", "Namespace which endpoint and security policy should create in")
	flagset.StringVar(&opts.PodNamespace, withPrefix("pod-namespace"), "sks-sync-object", "Namespace which pod endpoint and security policy in")
	flagset.StringVar(&opts.EverouteCluster, withPrefix("everoute-cluster"), "", "Which EverouteCluster should synchronize SecurityPolicy from")
	flagset.UintVar(&opts.WorkerNumber, withPrefix("worker-number"), 10, "Controller worker number")
	flagset.DurationVar(&opts.ResyncPeriod, withPrefix("resync-period"), 10*time.Hour, "Controller resync period")
}

// AddToManager allow you register controller to Manager.
func AddToManager(opts *Options, mgr manager.Manager) error {
	if opts.Enable != nil && !*opts.Enable {
		return nil
	}

	if opts.EverouteCluster == "" {
		return fmt.Errorf("must specify one EverouteCluster")
	}

	towerMgr := newTowerAPIServerMgr(opts)
	if mgr == nil {
		return fmt.Errorf("failed to new cloudPlatform k8s apiServer manager")
	}

	crdClient, err := clientset.NewForConfig(mgr.GetConfig())
	if err != nil {
		return err
	}

	k8sClient, err := k8sclientset.NewForConfig(mgr.GetConfig())
	if err != nil {
		return err
	}
	k8sFactory := k8sinformers.NewSharedInformerFactoryWithOptions(k8sClient, opts.ResyncPeriod, k8sinformers.WithNamespace(opts.Namespace))
	if opts.SharedFactory == nil {
		opts.SharedFactory = informer.NewSharedInformerFactory(opts.Client, opts.ResyncPeriod)
	}
	// cache endpoints and security policies in the namespace
	crdFactory := externalversions.NewSharedInformerFactoryWithOptions(crdClient, opts.ResyncPeriod)
	endpointController := endpoint.New(opts.SharedFactory, crdFactory, crdClient, opts.ResyncPeriod, opts.Namespace)
	policyController := policy.New(opts.SharedFactory, crdFactory, crdClient, opts.ResyncPeriod, opts.Namespace, opts.PodNamespace, opts.EverouteCluster)
	globalController := global.New(opts.SharedFactory, crdFactory, crdClient, opts.ResyncPeriod, opts.EverouteCluster)
	elfController := &computecluster.Controller{EverouteClusterID: opts.EverouteCluster, ConfigMapNamespace: opts.Namespace}
	if err := elfController.Setup(opts.SharedFactory, k8sFactory, k8sClient); err != nil {
		return err
	}

	if err := setupSecretManager(mgr, towerMgr, opts.Namespace); err != nil {
		return err
	}
	err = mgr.Add(manager.RunnableFunc(func(ctx context.Context) error {
		opts.SharedFactory.Start(ctx.Done())
		crdFactory.Start(ctx.Done())
		k8sFactory.Start(ctx.Done())
		go func() {
			err := towerMgr.Start(ctx)
			if err != nil {
				klog.Fatalf("Failed to start cloudPlatform k8s apiServer manager: %s", err)
			}
		}()

		go endpointController.Run(opts.WorkerNumber, ctx.Done())
		go policyController.Run(opts.WorkerNumber, ctx.Done())
		go globalController.Run(opts.WorkerNumber, ctx.Done())
		go elfController.Run(ctx)

		<-ctx.Done()
		return nil
	}))

	return err
}

func newTowerAPIServerMgr(opt *Options) ctrl.Manager {
	//nolint:all
	ctx, _ := context.WithTimeout(context.Background(), time.Minute)
	token, err := opt.Client.Auth(ctx.Done())
	if err != nil {
		klog.Errorf("Failed to get cloudPlatform token: %s", err)
		return nil
	}
	cfg := &rest.Config{}
	cfg.Host = opt.Client.URL + "/k8s"
	cfg.TLSClientConfig.Insecure = true
	cfg.BearerToken = token
	cfg.BearerTokenFile = opt.Client.TokenFile
	scheme := runtime.NewScheme()
	utilruntime.Must(corev1.AddToScheme(scheme))

	mgr, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme: scheme,
	})
	if err != nil {
		klog.Errorf("Failed to new cloudPlatform k8s apiserver manager: %s", err)
		return nil
	}
	return mgr
}

func setupSecretManager(erMgr, towerMgr ctrl.Manager, towerSpace string) error {
	secretChan := make(chan event.GenericEvent, 1)
	if err := (&secret.Watch{
		Queue:               secretChan,
		K8sMPKubeconfigName: msconst.K8sMPKubeconfigName,
		K8sMPKubeconfigNs:   towerSpace,
	}).SetupWithManager(erMgr, "networkCluster"); err != nil {
		return err
	}
	if err := (&secret.Watch{
		Queue:               secretChan,
		K8sMPKubeconfigName: msconst.K8sMPKubeconfigNameInCloudPlatform,
		K8sMPKubeconfigNs:   msconst.K8sMPKubeconfigNsInCloudPlatform,
	}).SetupWithManager(towerMgr, "cloudPlatform"); err != nil {
		return err
	}

	err := (&secret.Process{
		ERCli:     erMgr.GetClient(),
		TowerCli:  towerMgr.GetClient(),
		Namespace: towerSpace,
	}).SetupWithManager(erMgr, secretChan, erMgr.GetCache(), towerMgr.GetCache())
	return err
}
