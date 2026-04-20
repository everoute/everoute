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

package cases

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"k8s.io/klog/v2"
	"sigs.k8s.io/controller-runtime/pkg/client"

	agentv1alpha1 "github.com/everoute/everoute/pkg/apis/agent/v1alpha1"
	groupv1alpha1 "github.com/everoute/everoute/pkg/apis/group/v1alpha1"
	securityv1alpha1 "github.com/everoute/everoute/pkg/apis/security/v1alpha1"
	"github.com/everoute/everoute/tests/e2e/framework"
	"github.com/everoute/everoute/tests/e2e/framework/node"
)

var (
	startTime time.Time

	ctx              context.Context
	e2eEnv           *framework.Framework
	serviceRestarter *node.ServiceRestarter
)

const bypassPoliciesOnUpgradingFlowMark = "table=0, priority=350 "

func TestE2e(t *testing.T) {
	RegisterFailHandlerWithT(t, E2eFail)
	RunSpecs(t, "Everoute e2e Suite")
}

var _ = BeforeSuite(func() {
	var err error
	startTime = time.Now()
	ctx = context.Background()

	kubeconfig := filepath.Join(os.Getenv("HOME"), ".kube", "config")
	if _, statErr := os.Stat(kubeconfig); statErr != nil {
		kubeconfig = os.Getenv("KUBECONFIG")
	}
	e2eEnv, err = framework.NewFromKube(kubeconfig)
	Expect(err).ToNot(HaveOccurred())
	// reset resource before start e2e
	Expect(e2eEnv.ResetResource(ctx)).ToNot(HaveOccurred())

	By("wait bypass policies flow on upgrading removed")
	Eventually(func() error {
		flowMap, err := e2eEnv.NodeManager().DumpFlowAll()
		if err != nil {
			return err
		}
		for node, flows := range flowMap {
			for _, flow := range flows {
				if strings.Contains(flow, bypassPoliciesOnUpgradingFlowMark) {
					return fmt.Errorf("found bypass flow on node %s: %s", node, flow)
				}
			}
		}
		return nil
	}, 3*time.Minute, 5*time.Second).Should(Succeed())

	serviceRestarter = e2eEnv.NodeManager().ServiceRestarter(15, 20)
	serviceRestarter.RunAsync()
})

var _ = AfterSuite(func() {
	klog.Infof("complete all e2e test cases use %s", time.Since(startTime))
	klog.Infof("run e2e-reset.sh to clean test environment")
})

func E2eFail(message string, callerSkip ...int) {
	if e2eEnv == nil {
		// skip dump resources when e2eEnv uninitialized
		Fail(message, callerSkip...)
	}

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
	)

	// Final call ginkgo Fail
	Fail(message, callerSkip...)
}

func dumpAndPrintResource(splitLine string, resources ...client.ObjectList) {
	for _, resource := range resources {
		err := e2eEnv.KubeClient().List(ctx, resource, client.InNamespace(e2eEnv.Namespace()))
		if err == nil {
			raw, _ := json.Marshal(resource)
			fmt.Printf("%sDump %T:\n%s\n\n", splitLine, resource, string(raw))
		}
	}
}
