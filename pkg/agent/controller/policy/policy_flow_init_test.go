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

package policy

import (
	"context"
	"testing"

	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	policycache "github.com/everoute/everoute/pkg/agent/controller/policy/cache"
	clientsetscheme "github.com/everoute/everoute/pkg/client/clientset_generated/clientset/scheme"
)

func TestPolicyFlowInitCompletesWithEmptyResources(t *testing.T) {
	reconciler := newPolicyFlowInitTestReconciler(t)

	if err := reconciler.TryCompletePolicyFlowInit(context.Background()); err != nil {
		t.Fatalf("expected empty policy flow init to complete, got err %v", err)
	}
	if !reconciler.IsPolicyFlowInitDone() {
		t.Fatalf("policy flow init should be done")
	}
}

func newPolicyFlowInitTestReconciler(t *testing.T, initObjs ...runtime.Object) *Reconciler {
	t.Helper()

	scheme := runtime.NewScheme()
	if err := clientsetscheme.AddToScheme(scheme); err != nil {
		t.Fatalf("add everoute scheme: %v", err)
	}
	return &Reconciler{
		Client:          fake.NewClientBuilder().WithScheme(scheme).WithRuntimeObjects(initObjs...).Build(),
		ruleCache:       policycache.NewCompleteRuleCache(),
		globalRuleCache: policycache.NewGlobalRuleCache(),
		groupCache:      policycache.NewGroupCache(),
	}
}
