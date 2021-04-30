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
	"fmt"
	"testing"
	"time"

	. "github.com/onsi/gomega"

	"github.com/smartxworks/lynx/plugin/tower/pkg/client"
)

func TestOptions(t *testing.T) {
	RegisterTestingT(t)

	optionsCases := []struct {
		kubeconfig string
		configfile string

		expectCofig *Config
	}{
		{
			kubeconfig: "testdata/kubeconfig",
			configfile: "testdata/configfile",

			expectCofig: &Config{
				Client: &client.Client{
					URL:      "ws://tower.smartx.com",
					UserInfo: &client.UserInfo{Username: "admin", Password: "passwd", Source: "LDAP"},
				},
				Election: &LeaderElectionConfig{
					Enable:        true,
					Name:          "lynx.plugin.tower",
					Namespace:     "default",
					LeaseDuration: 60 * time.Second, // default LeaseDuration
					RenewDeadline: 15 * time.Second, // default RenewDeadline
					RetryPeriod:   5 * time.Second,  // default RetryPeriod
				},
				Controller: &ControllerConfig{
					Resync:  time.Hour,
					Workers: 10,
				},
			},
		},
	}

	for _, tt := range optionsCases {
		t.Run(fmt.Sprintf("test options load from config %s, %s", tt.configfile, tt.kubeconfig), func(t *testing.T) {
			options := &Options{}
			err := options.LoadFromFile(tt.kubeconfig, tt.configfile)
			if err != nil {
				t.Fatalf("expectCofig load from file: %s", err)
			}
			Expect(options.KubeConfig).ShouldNot(BeNil())
			Expect(options.Config).Should(Equal(tt.expectCofig))
		})
	}
}
