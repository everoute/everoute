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

	"k8s.io/klog"

	"github.com/smartxworks/lynx/pkg/client/clientset_generated/clientset"
	"github.com/smartxworks/lynx/pkg/client/informers_generated/externalversions"
	"github.com/smartxworks/lynx/plugin/tower/pkg/controller"
	"github.com/smartxworks/lynx/plugin/tower/pkg/informer"
)

func main() {
	var kubeconfig string
	var configfile string
	var options = &Options{}

	klog.InitFlags(nil)
	flag.StringVar(&kubeconfig, "kubeconfig", "", "kubeconfig for connection with apiserver")
	flag.StringVar(&configfile, "configfile", "", "configfile for connection with tower and other config")
	flag.Parse()

	err := options.LoadFromFile(kubeconfig, configfile)
	if err != nil {
		klog.Fatalf("unexpected error while load config: %s", err)
	}

	if err := run(options); err != nil {
		klog.Fatalf("unexpected error while run tower plugin: %s", err)
	}
}

// todo: add leader election for tower plugin
func run(options *Options) error {
	var stopCh = make(chan struct{})
	defer close(stopCh)

	crdClient, err := clientset.NewForConfig(options.KubeConfig)
	if err != nil {
		return err
	}

	resyncPeriod := options.Config.Controller.Resync
	towerFactory := informer.NewSharedInformerFactory(options.Config.Client, resyncPeriod)
	crdFactory := externalversions.NewSharedInformerFactory(crdClient, resyncPeriod)

	endpointController := controller.New(towerFactory, crdFactory, crdClient, resyncPeriod, options.Config.Controller.Namespace)

	towerFactory.Start(stopCh)
	crdFactory.Start(stopCh)

	endpointController.Run(options.Config.Controller.Workers, stopCh)
	return nil
}
