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

package register

import (
	"flag"
	"fmt"
	"time"

	"sigs.k8s.io/controller-runtime/pkg/manager"

	"github.com/smartxworks/lynx/pkg/client/clientset_generated/clientset"
	"github.com/smartxworks/lynx/pkg/client/informers_generated/externalversions"
	"github.com/smartxworks/lynx/plugin/tower/pkg/client"
	"github.com/smartxworks/lynx/plugin/tower/pkg/controller/endpoint"
	"github.com/smartxworks/lynx/plugin/tower/pkg/controller/policy"
	"github.com/smartxworks/lynx/plugin/tower/pkg/informer"
)

type Options struct {
	// will enable controller if "Enable" empty or true
	Enable       *bool
	Client       *client.Client
	ResyncPeriod time.Duration
	WorkerNumber uint
	Namespace    string
	// which EverouteCluster should synchronize SecurityPolicy from
	EverouteCluster string
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
	flagset.StringVar(&opts.Client.URL, withPrefix("address"), "", "Tower connection address")
	flagset.StringVar(&opts.Client.UserInfo.Username, withPrefix("username"), "", "Tower user name for authenticate")
	flagset.StringVar(&opts.Client.UserInfo.Source, withPrefix("usersource"), "", "Tower user source for authenticate")
	flagset.StringVar(&opts.Client.UserInfo.Password, withPrefix("password"), "", "Tower user password for authenticate")
	flagset.StringVar(&opts.Namespace, withPrefix("namespace"), "tower-space", "Namespace which endpoint and security policy should create in")
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

	crdClient, err := clientset.NewForConfig(mgr.GetConfig())
	if err != nil {
		return err
	}

	towerFactory := informer.NewSharedInformerFactory(opts.Client, opts.ResyncPeriod)
	// cache endpoints and security policies in the namespace
	crdFactory := externalversions.NewSharedInformerFactoryWithOptions(crdClient, opts.ResyncPeriod, externalversions.WithNamespace(opts.Namespace))
	endpointController := endpoint.New(towerFactory, crdFactory, crdClient, opts.ResyncPeriod, opts.Namespace)
	policyController := policy.New(towerFactory, crdFactory, crdClient, opts.ResyncPeriod, opts.Namespace, opts.EverouteCluster)

	err = mgr.Add(manager.RunnableFunc(func(stopChan <-chan struct{}) error {
		towerFactory.Start(stopChan)
		crdFactory.Start(stopChan)

		go endpointController.Run(opts.WorkerNumber, stopChan)
		go policyController.Run(opts.WorkerNumber, stopChan)

		<-stopChan
		return nil
	}))

	return err
}
