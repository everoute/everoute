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

package tower

import (
	"context"
	"fmt"

	rthttp "github.com/hashicorp/go-retryablehttp"

	securityv1alpha1 "github.com/everoute/everoute/pkg/apis/security/v1alpha1"
	"github.com/everoute/everoute/plugin/tower/pkg/client"
	"github.com/everoute/everoute/tests/e2e/framework/model"
)

type provider struct {
	towerClient       *client.Client
	everouteClusterID string
}

func NewProvider(towerClient *client.Client, everouteClusterID string) model.GlobalPolicyProvider {
	retryClient := rthttp.NewClient()
	retryClient.RetryMax = 10
	retryClient.Logger = nil
	towerClient.HTTPClient = retryClient.StandardClient()

	return &provider{
		towerClient:       towerClient,
		everouteClusterID: everouteClusterID,
	}
}

func (m *provider) Name() string {
	return "tower"
}

func (m *provider) SetDefaultAction(ctx context.Context, action securityv1alpha1.GlobalDefaultAction) error {
	var globalDefaultAction string

	switch action {
	case securityv1alpha1.GlobalDefaultActionAllow:
		globalDefaultAction = "ALLOW"
	case securityv1alpha1.GlobalDefaultActionDrop:
		globalDefaultAction = "DROP"
	}

	var request = client.Request{
		Query: fmt.Sprintf(`mutation {updateEverouteCluster(where: { id: "%s" } data: { global_default_action: %s }) {id}}`, m.everouteClusterID, globalDefaultAction),
	}

	resp, err := m.towerClient.Query(ctx, &request)
	if err != nil || len(resp.Errors) != 0 {
		return fmt.Errorf("mutation from tower: %s, resp: %+v", err, resp)
	}

	return nil
}
