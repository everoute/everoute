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

package cases

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/klog"

	agentv1alpha1 "github.com/smartxworks/lynx/pkg/apis/agent/v1alpha1"
	groupv1alpha1 "github.com/smartxworks/lynx/pkg/apis/group/v1alpha1"
	policyrulev1alpha1 "github.com/smartxworks/lynx/pkg/apis/policyrule/v1alpha1"
	securityv1alpha1 "github.com/smartxworks/lynx/pkg/apis/security/v1alpha1"
	"github.com/smartxworks/lynx/tests/e2e/framework"
)

var (
	startTime time.Time

	ctx    context.Context
	e2eEnv *framework.Framework
)

func TestE2e(t *testing.T) {
	RegisterFailHandlerWithT(t, E2eFail)
	RunSpecsWithDefaultAndCustomReporters(t, "Lynx e2e Suite", []Reporter{})
}

var _ = BeforeSuite(func() {
	var err error
	startTime = time.Now()
	ctx = context.Background()

	e2eEnv, err = framework.NewFromKube(filepath.Join(os.Getenv("HOME"), ".kube", "config"))
	Expect(err).ToNot(HaveOccurred())

	// reset resource before start e2e
	Expect(e2eEnv.ResetResource(ctx)).ToNot(HaveOccurred())

	// Will random restart controller and agent when e2e. Skip restart controller when provider
	// is netns, because it may cause failed when create endpoint (failed to call webhook).
	restarter := e2eEnv.NodeManager().ServiceRestarter(10, 30, e2eEnv.EndpointManager().Name() == "netns")
	go restarter.Run(make(chan struct{}))
})

var _ = AfterSuite(func() {
	klog.Infof("complete all e2e test cases use %s", time.Since(startTime))
	klog.Infof("run e2e-reset.sh to clean test environment")
})

const (
	// default tier tier0, tier1, tier2
	tier0 = "tier0"
	tier1 = "tier1"
)

func E2eFail(message string, callerSkip ...int) {
	const splitLine = "------------------------\n"

	// Dump and print flows
	flows, err := e2eEnv.NodeManager().DumpFlowAll()
	if err == nil {
		raw, _ := json.Marshal(flows)
		fmt.Printf("%sDump Flows:\n%s\n\n", splitLine, string(raw))
	}

	// Dump and print kubernetes resources
	dumpAndPrintResource(splitLine,
		&securityv1alpha1.SecurityPolicyList{},
		&securityv1alpha1.GlobalPolicyList{},
		&securityv1alpha1.EndpointList{},
		&agentv1alpha1.AgentInfoList{},
		&groupv1alpha1.EndpointGroupList{},
		&groupv1alpha1.GroupMembersList{},
		&groupv1alpha1.GroupMembersPatchList{},
		&policyrulev1alpha1.PolicyRuleList{},
	)

	// Final call ginkgo Fail
	Fail(message, callerSkip...)
}

func dumpAndPrintResource(splitLine string, resources ...runtime.Object) {
	for _, resource := range resources {
		err := e2eEnv.KubeClient().List(ctx, resource)
		if err == nil {
			raw, _ := json.Marshal(resource)
			fmt.Printf("%sDump %T:\n%s\n\n", resource, splitLine, string(raw))
		}
	}
}
