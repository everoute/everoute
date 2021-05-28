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
	"os"
	"path/filepath"
	"testing"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"k8s.io/klog"

	"github.com/smartxworks/lynx/pkg/apis/security/v1alpha1"
	"github.com/smartxworks/lynx/tests/e2e/framework"
)

var (
	startTime time.Time

	ctx    context.Context
	e2eEnv *framework.Framework
)

func TestE2e(t *testing.T) {
	RegisterFailHandlerWithT(t, Fail)
	RunSpecsWithDefaultAndCustomReporters(t, "Lynx e2e Suite", []Reporter{})
}

var _ = BeforeSuite(func() {
	var err error
	startTime = time.Now()
	ctx = context.Background()

	e2eEnv, err = framework.NewFromKube(filepath.Join(os.Getenv("HOME"), ".kube", "config"))
	Expect(err).ToNot(HaveOccurred())

	err = e2eEnv.SetupObjects(ctx, defaultTier(tier0), defaultTier(tier1), defaultTier(tier2))
	Expect(err).ToNot(HaveOccurred())

	// Will random restart controller and agent when e2e. Skip restart controller when provider
	// is netns, because it may cause failed when create endpoint (failed to call webhook).
	restarter := e2eEnv.NodeManager().ServiceRestarter(10, 30, e2eEnv.EndpointManager().Name() == "netns")
	go restarter.Run(make(chan struct{}))
})

var _ = AfterSuite(func() {
	err := e2eEnv.CleanObjects(ctx, defaultTier(tier0), defaultTier(tier1), defaultTier(tier2))
	Expect(err).ToNot(HaveOccurred())

	klog.Infof("complete all e2e test cases use %s", time.Since(startTime))
	klog.Infof("run e2e-reset.sh to clean test environment")
})

const (
	// default tier tier0, tier1, tier2
	tier0 = "tier0"
	tier1 = "tier1"
	tier2 = "tier2"
)

func defaultTier(name string) *v1alpha1.Tier {
	tier := &v1alpha1.Tier{}
	tier.Name = name
	tier.Spec.TierMode = v1alpha1.TierWhiteList

	switch name {
	case tier0:
		tier.Spec.Priority = 0
	case tier1:
		tier.Spec.Priority = 1
	case tier2:
		tier.Spec.Priority = 2
	default:
		klog.Fatalf("tier %s is not default tier", name)
	}

	return tier
}
