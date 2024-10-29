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

package globalpolicy

import (
	"github.com/everoute/everoute/pkg/client/clientset_generated/clientset"
	"github.com/everoute/everoute/tests/e2e/framework/config"
	"github.com/everoute/everoute/tests/e2e/framework/globalpolicy/kubernetes"
	"github.com/everoute/everoute/tests/e2e/framework/globalpolicy/tower"
	"github.com/everoute/everoute/tests/e2e/framework/model"
)

func NewProvider(config *config.GlobalPolicyConfig) model.GlobalPolicyProvider {
	switch {
	case config.Provider == nil, *config.Provider == "kubernetes", *config.Provider == "pod":
		crdClient := clientset.NewForConfigOrDie(config.KubeConfig)
		return kubernetes.NewProvider(crdClient)

	case *config.Provider == "tower":
		return tower.NewProvider(config.TowerClient, *config.EverouteClusterID)
	default:
		panic("unknown provider " + *config.Provider)
	}
}
