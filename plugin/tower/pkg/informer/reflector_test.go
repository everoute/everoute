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

package informer

import (
	"fmt"
	"testing"
	"time"

	"k8s.io/client-go/tools/cache"

	"github.com/smartxworks/lynx/plugin/tower/pkg/client"
)

func TestReflector(t *testing.T) {
	var c = &client.Client{URL: "ws://tower.smartx.com:8800"}

	f := NewSharedInformerFactory(c, 10*time.Second)
	labelInformer := f.Label()

	display("A", labelInformer, 5*time.Second)
	display("B", labelInformer, 6*time.Second)

	f.Start(make(chan struct{}))

	select {}
}

func display(name string, informer cache.SharedIndexInformer, resync time.Duration) {

	informer.AddEventHandlerWithResyncPeriod(
		&cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				fmt.Println(name, obj)
			},
			UpdateFunc: func(_, obj interface{}) {
				fmt.Println(name, obj)
			},
			DeleteFunc: func(obj interface{}) {
				fmt.Println(name, obj)
			},
		},
		resync,
	)
}
