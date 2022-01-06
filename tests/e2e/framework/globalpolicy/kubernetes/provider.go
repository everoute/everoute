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

package kubernetes

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	securityv1alpha1 "github.com/everoute/everoute/pkg/apis/security/v1alpha1"
	"github.com/everoute/everoute/pkg/client/clientset_generated/clientset"
	"github.com/everoute/everoute/tests/e2e/framework/model"
)

type provider struct {
	kubeClient clientset.Interface
}

func NewProvider(client clientset.Interface) model.GlobalPolicyProvider {
	return &provider{
		client,
	}
}

func (m *provider) Name() string {
	return "kubernetes"
}

func (m *provider) SetDefaultAction(ctx context.Context, action securityv1alpha1.GlobalDefaultAction) error {
	globalPolicyList, err := m.kubeClient.SecurityV1alpha1().GlobalPolicies().List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("get global policy: %s", err)
	}

	switch len(globalPolicyList.Items) {
	case 1:
		_, err = m.kubeClient.SecurityV1alpha1().GlobalPolicies().Patch(
			ctx,
			globalPolicyList.Items[0].Name,
			types.MergePatchType,
			[]byte(fmt.Sprintf(`{"spec":{"defaultAction":"%s"}}`, action)),
			metav1.PatchOptions{},
		)
		return err

	case 0:
		globalPolicy := new(securityv1alpha1.GlobalPolicy)
		globalPolicy.Name = "global-default-action"
		globalPolicy.Spec.DefaultAction = action
		_, err = m.kubeClient.SecurityV1alpha1().GlobalPolicies().Create(ctx, globalPolicy, metav1.CreateOptions{})
		return err

	default:
		return fmt.Errorf("multiple global policies found")
	}
}
