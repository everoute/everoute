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

package controller_test

import (
	"testing"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/envtest/printer"

	"github.com/smartxworks/lynx/pkg/client/clientset_generated/clientset"
	"github.com/smartxworks/lynx/pkg/client/clientset_generated/clientset/fake"
	"github.com/smartxworks/lynx/pkg/client/informers_generated/externalversions"
	"github.com/smartxworks/lynx/plugin/tower/pkg/controller"
	"github.com/smartxworks/lynx/plugin/tower/pkg/informer"
	fakeserver "github.com/smartxworks/lynx/plugin/tower/pkg/server/fake"
)

var (
	crdClient clientset.Interface
	server    *fakeserver.Server
	namespace = metav1.NamespaceDefault
	stopCh    = make(chan struct{})
)

const (
	timeout  = time.Second * 10
	interval = time.Millisecond * 250
)

func TestEndpointController(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecsWithDefaultAndCustomReporters(t, "EndpointController Suite", []Reporter{printer.NewlineReporter{}})
}

var _ = BeforeSuite(func() {
	By("create fake server and fake client")
	server = fakeserver.NewServer()
	server.Serve()
	crdClient = fake.NewSimpleClientset()

	towerFactory := informer.NewSharedInformerFactory(server.NewClient(), 0)
	crdFactory := externalversions.NewSharedInformerFactory(crdClient, 0)

	By("create and start EndpointController")
	ctroller := controller.New(towerFactory, crdFactory, crdClient, 0, namespace)
	go ctroller.Run(10, stopCh)

	By("start towerFactory and crdFactory")
	towerFactory.Start(stopCh)
	crdFactory.Start(stopCh)

	By("wait for tower cache and crd cache sync")
	crdFactory.WaitForCacheSync(stopCh)
	towerFactory.WaitForCacheSync(stopCh)
}, 60)

var _ = AfterSuite(func() {
	By("tearing down the environment")
	close(stopCh)
})
