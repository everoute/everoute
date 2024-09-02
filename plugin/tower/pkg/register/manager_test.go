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
	"flag"
	"reflect"
	"testing"
	"time"

	msconst "github.com/everoute/everoute/pkg/constants/ms"
	"github.com/everoute/everoute/plugin/tower/pkg/client"
)

func TestInitFlags(t *testing.T) {
	var boolTrue = true
	var boolFalse = false

	testCases := map[string]struct {
		flagPrefix    string
		args          []string
		expectOptions *Options
	}{
		"should prase default options": {
			expectOptions: &Options{
				Enable:       &boolFalse,
				Client:       &client.Client{UserInfo: &client.UserInfo{}, AllowInsecure: true, TokenFile: msconst.DefaultTowerTokenFile},
				ResyncPeriod: 10 * time.Hour,
				WorkerNumber: 10,
				Namespace:    "tower-space",
				PodNamespace: "sks-sync-object",
			},
		},
		"should prase normal options with prefix": {
			flagPrefix: "plugins.tower.",
			args: []string{
				"--plugins.tower.enable=true",
				"--plugins.tower.endpoint=https://127.0.0.1:8800/api",
				"--plugins.tower.resync-period=1s",
				"--plugins.tower.worker-number=1",
				"--plugins.tower.allow-insecure=false",
				"--plugins.tower.namespace=test-namespace",
				"--plugins.tower.token-file=/tmp/test",
				"-plugins.tower.pod-namespace=test-pod",
			},
			expectOptions: &Options{
				Enable: &boolTrue,
				Client: &client.Client{
					URL:       "https://127.0.0.1:8800/api",
					UserInfo:  &client.UserInfo{},
					TokenFile: "/tmp/test",
				},
				ResyncPeriod: time.Second,
				WorkerNumber: 1,
				Namespace:    "test-namespace",
				PodNamespace: "test-pod",
			},
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			var opts Options
			var flagset flag.FlagSet

			InitFlags(&opts, &flagset, tc.flagPrefix)

			if err := flagset.Parse(tc.args); err != nil {
				t.Fatalf("unexpect error will parse flags: %s", err)
			}

			if !reflect.DeepEqual(&opts, tc.expectOptions) {
				t.Fatalf("expect parse options %+v from flags %+v, but got %+v", tc.expectOptions, tc.args, opts)
			}
		})
	}
}
