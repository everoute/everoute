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

package global_test

import (
	"context"
	"fmt"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/rand"

	"github.com/everoute/everoute/pkg/apis/security/v1alpha1"
	controller "github.com/everoute/everoute/plugin/tower/pkg/controller/global"
	"github.com/everoute/everoute/plugin/tower/pkg/controller/policy"
	"github.com/everoute/everoute/plugin/tower/pkg/schema"
	. "github.com/everoute/everoute/plugin/tower/pkg/utils/testing"
)

var _ = Describe("GlobalPolicyController", func() {
	var ctx context.Context

	BeforeEach(func() {
		ctx = context.Background()
	})
	AfterEach(func() {
		server.TrackerFactory().ResetAll()
		err := crdClient.SecurityV1alpha1().GlobalPolicies().DeleteCollection(ctx,
			metav1.DeleteOptions{},
			metav1.ListOptions{},
		)
		Expect(err).Should(Succeed())
	})

	Context("create everoute cluster with default allow", func() {
		var erCluster *schema.EverouteCluster

		BeforeEach(func() {
			erCluster = NewEverouteCluster(everouteCluster, schema.GlobalPolicyActionAllow)
			By(fmt.Sprintf("create everoute cluster: %+v", erCluster))
			server.TrackerFactory().EverouteCluster().CreateOrUpdate(erCluster)
		})
		It("should create default global policy", func() {
			assertMatchDefaultAction(ctx, v1alpha1.GlobalDefaultActionAllow)
			globalPolicy, err := crdClient.SecurityV1alpha1().GlobalPolicies().Get(ctx, controller.DefaultGlobalPolicyName, metav1.GetOptions{})
			Expect(err).ShouldNot(HaveOccurred())
			Expect(globalPolicy.Spec.Logging).ShouldNot(BeNil())
			Expect(globalPolicy.Spec.Logging.Enabled).Should(BeFalse())
			Expect(globalPolicy.Spec.Logging.Tags).Should(HaveLen(3))
			Expect(globalPolicy.Spec.Logging.Tags[policy.LoggingTagPolicyID]).Should(Equal(erCluster.ID))
			Expect(globalPolicy.Spec.Logging.Tags[policy.LoggingTagPolicyName]).Should(BeEmpty())
			Expect(globalPolicy.Spec.Logging.Tags[policy.LoggingTagPolicyType]).Should(Equal(policy.LoggingTagPolicyTypeGlobalPolicy))
		})

		When("update everoute cluster to default drop", func() {
			BeforeEach(func() {
				erCluster.GlobalDefaultAction = schema.GlobalPolicyActionDrop
				By(fmt.Sprintf("update everoute cluster %s to default drop", erCluster.ID))
				server.TrackerFactory().EverouteCluster().CreateOrUpdate(erCluster)
			})
			It("should update default global policy", func() {
				assertMatchDefaultAction(ctx, v1alpha1.GlobalDefaultActionDrop)
			})
		})

		When("enable everoute global policy logging", func() {
			BeforeEach(func() {
				erCluster.EnableLogging = true
				server.TrackerFactory().EverouteCluster().CreateOrUpdate(erCluster)
			})
			It("should update default global policy", func() {
				assertMatchEnabledLogging(ctx, true)
			})
		})
	})

	Context("create everoute cluster with default drop", func() {
		var erCluster *schema.EverouteCluster

		BeforeEach(func() {
			erCluster = NewEverouteCluster(everouteCluster, schema.GlobalPolicyActionDrop)
			By(fmt.Sprintf("create everoute cluster: %+v", erCluster))
			server.TrackerFactory().EverouteCluster().CreateOrUpdate(erCluster)
		})
		It("should create default global policy", func() {
			assertMatchDefaultAction(ctx, v1alpha1.GlobalDefaultActionDrop)
		})

		When("update everoute cluster to default allow", func() {
			BeforeEach(func() {
				erCluster.GlobalDefaultAction = schema.GlobalPolicyActionAllow
				By(fmt.Sprintf("update everoute cluster %s to default drop", erCluster.ID))
				server.TrackerFactory().EverouteCluster().CreateOrUpdate(erCluster)
			})
			It("should update default global policy", func() {
				assertMatchDefaultAction(ctx, v1alpha1.GlobalDefaultActionAllow)
			})
		})
	})

	When("create random global security policy", func() {
		var globalPolicy *v1alpha1.GlobalPolicy

		BeforeEach(func() {
			globalPolicy = new(v1alpha1.GlobalPolicy)
			globalPolicy.SetName(rand.String(10))

			By(fmt.Sprintf("create random global policy %+v", globalPolicy))
			_, err := crdClient.SecurityV1alpha1().GlobalPolicies().Create(context.Background(), globalPolicy, metav1.CreateOptions{})
			Expect(err).Should(Succeed())
		})
		It("should remove not default global policy", func() {
			Eventually(func() bool {
				_, err := crdClient.SecurityV1alpha1().GlobalPolicies().Get(context.Background(), globalPolicy.Name, metav1.GetOptions{})
				return errors.IsNotFound(err)
			}).Should(BeTrue())
		})
	})
})

func assertMatchDefaultAction(ctx context.Context, defaultAction v1alpha1.GlobalDefaultAction) {
	Eventually(func() bool {
		globalPolicy, err := crdClient.SecurityV1alpha1().GlobalPolicies().Get(ctx, controller.DefaultGlobalPolicyName, metav1.GetOptions{})
		if err != nil {
			return false
		}
		return globalPolicy.Spec.DefaultAction == defaultAction
	}, timeout, interval).Should(BeTrue())
}

func assertMatchEnabledLogging(ctx context.Context, enabledLogging bool) {
	Eventually(func() bool {
		globalPolicy, err := crdClient.SecurityV1alpha1().GlobalPolicies().Get(ctx, controller.DefaultGlobalPolicyName, metav1.GetOptions{})
		if err != nil || globalPolicy.Spec.Logging == nil {
			return false
		}
		return globalPolicy.Spec.Logging.Enabled == enabledLogging
	}, timeout, interval).Should(BeTrue())
}
