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
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/everoute/everoute/pkg/apis/security/v1alpha1"
	controller "github.com/everoute/everoute/plugin/tower/pkg/controller/global"
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
			assertMatchWhiteList(ctx, []*schema.EverouteCluster{erCluster}, nil, nil)
		})

		When("update everoute cluster to default drop", func() {
			BeforeEach(func() {
				erCluster.GlobalDefaultAction = schema.GlobalPolicyActionDrop
				By(fmt.Sprintf("update everoute cluster %s to default drop", erCluster.ID))
				server.TrackerFactory().EverouteCluster().CreateOrUpdate(erCluster)
			})
			It("should update default global policy", func() {
				assertMatchDefaultAction(ctx, v1alpha1.GlobalDefaultActionDrop)
				assertMatchWhiteList(ctx, []*schema.EverouteCluster{erCluster}, nil, nil)
			})
		})

		When("associate new elf cluster", func() {
			var elfCluster = rand.String(10)
			var host01, host02, host03 *schema.Host

			BeforeEach(func() {
				host01 = NewRandomHost(elfCluster)
				host02 = NewRandomHost(elfCluster)
				host03 = NewRandomHost(elfCluster)

				By(fmt.Sprintf("add host %v %v %v to elf cluster %s", host01, host02, host03, elfCluster))
				server.TrackerFactory().Host().CreateOrUpdate(host01)
				server.TrackerFactory().Host().CreateOrUpdate(host02)
				server.TrackerFactory().Host().CreateOrUpdate(host03)

				By(fmt.Sprintf("associate elf cluster %s to everoute cluster %s", elfCluster, erCluster.ID))
				erCluster.AgentELFClusters = append(erCluster.AgentELFClusters, schema.ObjectReference{ID: elfCluster})
				server.TrackerFactory().EverouteCluster().CreateOrUpdate(erCluster)
			})

			It("should add cluster hosts management ip to whitelist", func() {
				assertMatchWhiteList(ctx, []*schema.EverouteCluster{erCluster}, []*schema.Host{host01, host02, host03}, nil)
			})

			When("add new host to the elf cluster", func() {
				var host04 *schema.Host

				BeforeEach(func() {
					host04 = NewRandomHost(elfCluster)
					By(fmt.Sprintf("add host %v to elf cluster %s", host04, elfCluster))
					server.TrackerFactory().Host().CreateOrUpdate(host04)
				})
				It("should add new host management ip to whitelist", func() {
					assertMatchWhiteList(ctx, []*schema.EverouteCluster{erCluster}, []*schema.Host{host01, host02, host03, host04}, nil)
				})
			})
			When("remove host from the elf cluster", func() {
				BeforeEach(func() {
					By(fmt.Sprintf("remove host %s from elf cluster %s", host03, elfCluster))
					err := server.TrackerFactory().Host().Delete(host03.ID)
					Expect(err).Should(Succeed())
				})
				It("should remove host management ip from whitelist", func() {
					assertMatchWhiteList(ctx, []*schema.EverouteCluster{erCluster}, []*schema.Host{host01, host02}, nil)
				})
			})
			When("disassociate the elf cluster", func() {
				BeforeEach(func() {
					By(fmt.Sprintf("disassociate elf cluster %s from everoute cluster %s", elfCluster, erCluster.ID))
					erCluster.AgentELFClusters = nil
					server.TrackerFactory().EverouteCluster().CreateOrUpdate(erCluster)
				})
				It("should remove elf cluster hosts management ip from whitelist", func() {
					assertMatchWhiteList(ctx, []*schema.EverouteCluster{erCluster}, nil, nil)
				})
			})
		})

		When("create rand everoute cluster", func() {
			var randomERCluster *schema.EverouteCluster

			BeforeEach(func() {
				randomERCluster = NewEverouteCluster(rand.String(10), schema.GlobalPolicyActionAllow)
				By(fmt.Sprintf("create random everoute cluster %+v", randomERCluster))
				server.TrackerFactory().EverouteCluster().CreateOrUpdate(randomERCluster)
			})
			It("should add controllers ip to whitelist", func() {
				assertMatchWhiteList(ctx, []*schema.EverouteCluster{erCluster, randomERCluster}, nil, nil)
			})

			When("add new controller to the everoute cluster", func() {
				BeforeEach(func() {
					randomERCluster.ControllerInstances = append(
						randomERCluster.ControllerInstances,
						schema.EverouteControllerInstance{IPAddr: NewRandomIP().String()},
					)
					By(fmt.Sprintf("update random everoute cluster %+v", randomERCluster))
					server.TrackerFactory().EverouteCluster().CreateOrUpdate(randomERCluster)
				})
				It("should add new controller ip th whitelist", func() {
					assertMatchWhiteList(ctx, []*schema.EverouteCluster{erCluster, randomERCluster}, nil, nil)
				})
			})

			When("remove the everoute cluster", func() {
				BeforeEach(func() {
					By(fmt.Sprintf("remove random everoute cluster %s", randomERCluster.ID))
					err := server.TrackerFactory().EverouteCluster().Delete(randomERCluster.ID)
					Expect(err).Should(Succeed())
				})
				It("should remove all endpoints from whitelist", func() {
					assertMatchWhiteList(ctx, []*schema.EverouteCluster{erCluster}, nil, nil)
				})
			})
		})

		When("create systemEndpoints", func() {
			var randomSystemEndpoints *schema.SystemEndpoints

			BeforeEach(func() {
				randomSystemEndpoints = NewSystemEndpoints(4)
				By(fmt.Sprintf("create random systemEndpoints %+v", randomSystemEndpoints))
				server.TrackerFactory().SystemEndpoints().CreateOrUpdate(randomSystemEndpoints)
			})
			It("should add endpoints to whitelist", func() {
				assertMatchWhiteList(ctx, []*schema.EverouteCluster{erCluster}, nil, randomSystemEndpoints)
			})

			When("add new endpoint to systemEndpoints", func() {
				BeforeEach(func() {
					randomSystemEndpoints.IPPortEndpoints = append(
						randomSystemEndpoints.IPPortEndpoints,
						schema.IPPortSystemEndpoint{IP: NewRandomIP().String()},
					)
					By(fmt.Sprintf("update systemEndpoints to %+v", randomSystemEndpoints))
					server.TrackerFactory().SystemEndpoints().CreateOrUpdate(randomSystemEndpoints)
				})
				It("should add new endpoints th whitelist", func() {
					assertMatchWhiteList(ctx, []*schema.EverouteCluster{erCluster}, nil, randomSystemEndpoints)
				})
			})

			When("remove all endpoint for the systemEndpoints", func() {
				BeforeEach(func() {
					randomSystemEndpoints.IPPortEndpoints = nil
					By(fmt.Sprintf("remove all endpoint from systemEndpoints: %+v", randomSystemEndpoints))
					server.TrackerFactory().SystemEndpoints().CreateOrUpdate(randomSystemEndpoints)
				})
				It("should delete controllers ip from whitelist", func() {
					assertMatchWhiteList(ctx, []*schema.EverouteCluster{erCluster}, nil, randomSystemEndpoints)
				})
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
			assertMatchWhiteList(ctx, []*schema.EverouteCluster{erCluster}, nil, nil)
		})

		When("update everoute cluster to default allow", func() {
			BeforeEach(func() {
				erCluster.GlobalDefaultAction = schema.GlobalPolicyActionAllow
				By(fmt.Sprintf("update everoute cluster %s to default drop", erCluster.ID))
				server.TrackerFactory().EverouteCluster().CreateOrUpdate(erCluster)
			})
			It("should update default global policy", func() {
				assertMatchDefaultAction(ctx, v1alpha1.GlobalDefaultActionAllow)
				assertMatchWhiteList(ctx, []*schema.EverouteCluster{erCluster}, nil, nil)
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

func assertMatchWhiteList(ctx context.Context, erClusters []*schema.EverouteCluster, hosts []*schema.Host, systemEndpoints *schema.SystemEndpoints) {
	var whiteList = sets.NewString()

	for _, erCluster := range erClusters {
		for _, ins := range erCluster.ControllerInstances {
			whiteList.Insert(fmt.Sprintf("%s/32", ins.IPAddr))
		}
	}
	for _, host := range hosts {
		whiteList.Insert(fmt.Sprintf("%s/32", host.ManagementIP))
	}
	if systemEndpoints != nil {
		for _, ipPortEndpoint := range systemEndpoints.IPPortEndpoints {
			whiteList.Insert(fmt.Sprintf("%s/32", ipPortEndpoint.IP))
		}
	}

	Eventually(func() bool {
		globalPolicy, err := crdClient.SecurityV1alpha1().GlobalPolicies().Get(ctx, controller.DefaultGlobalPolicyName, metav1.GetOptions{})
		if err != nil {
			return false
		}
		currentWhiteList := sets.NewString()
		for _, ipBlock := range globalPolicy.Spec.Whitelist {
			currentWhiteList.Insert(ipBlock.CIDR)
		}
		return currentWhiteList.Equal(whiteList)
	}, timeout, interval).Should(BeTrue())
}
