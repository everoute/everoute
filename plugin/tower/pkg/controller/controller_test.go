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

package controller

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/rand"

	"github.com/smartxworks/lynx/pkg/client/clientset_generated/clientset"
	"github.com/smartxworks/lynx/pkg/client/clientset_generated/clientset/fake"
	"github.com/smartxworks/lynx/pkg/client/informers_generated/externalversions"
	"github.com/smartxworks/lynx/plugin/tower/pkg/informer"
	"github.com/smartxworks/lynx/plugin/tower/pkg/schema"
	fakeserver "github.com/smartxworks/lynx/plugin/tower/pkg/server/fake"
)

var (
	crdClient clientset.Interface
	server    *fakeserver.Server
)

func TestMain(m *testing.M) {
	var stopCh = make(chan struct{})

	server = fakeserver.NewServer()
	server.Serve()

	crdClient = fake.NewSimpleClientset()
	towerFactory := informer.NewSharedInformerFactory(server.NewClient(), 0)
	crdFactory := externalversions.NewSharedInformerFactory(crdClient, 0)

	ctroller := New(towerFactory, crdFactory, crdClient, 0)
	go ctroller.Run(10, stopCh)

	towerFactory.Start(stopCh)
	crdFactory.Start(stopCh)

	os.Exit(m.Run())
}

func TestHandlerEndpoint(t *testing.T) {
	RegisterTestingT(t)
	numOfRandVM := 10000

	bgTime := time.Now()
	defer func() {
		fmt.Printf("Use time %s to process %d endpoints\n", time.Since(bgTime), numOfRandVM)
		server.TrackerFactory().ResetAll()
	}()

	for i := 0; i < numOfRandVM; i++ {
		server.TrackerFactory().VM().CreateOrUpdate(randVM())
	}

	Eventually(func() bool {
		epList, err := crdClient.SecurityV1alpha1().Endpoints().List(context.Background(), metav1.ListOptions{})
		return len(epList.Items) == numOfRandVM && err == nil
	}, time.Minute, 100*time.Millisecond).Should(BeTrue())
}

func randVM() *schema.VM {
	return &schema.VM{
		ObjectMeta: schema.ObjectMeta{
			ID: rand.String(20),
		},
		VMNics: []schema.VMNic{
			{
				ObjectMeta: schema.ObjectMeta{
					ID: rand.String(20),
				},
				InterfaceID: rand.String(20),
			},
		},
	}
}

func TestValidKubernetesLabel(t *testing.T) {
	testCases := []struct {
		labelKey    string
		labelValue  string
		expectValid bool
	}{
		{
			labelKey:    "中文标签",
			labelValue:  "value",
			expectValid: false,
		},
		{
			labelKey:    "key",
			labelValue:  "中文值",
			expectValid: false,
		},
		{
			labelKey:    "@invalid-char",
			labelValue:  "value",
			expectValid: false,
		},
		{
			labelKey:    "Key",
			labelValue:  "Value",
			expectValid: true,
		},
		{
			labelKey:    "key",
			labelValue:  "value",
			expectValid: true,
		},
	}

	for index, tc := range testCases {
		t.Run(fmt.Sprintf("case[%d]: key = %s, value = %s", index, tc.labelKey, tc.labelValue), func(t *testing.T) {
			isValidLabel := validKubernetesLabel(&schema.Label{
				Key:   tc.labelKey,
				Value: tc.labelValue,
			})
			if tc.expectValid != isValidLabel {
				t.Fatalf("key = %s, value = %s, expect valid %t but not", tc.labelKey, tc.labelValue, tc.expectValid)
			}
		})
	}
}
