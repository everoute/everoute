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
	"fmt"
	"net"
	"strconv"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apimachinery/pkg/util/rand"
	"sigs.k8s.io/controller-runtime/pkg/client"

	securityv1alpha1 "github.com/everoute/everoute/pkg/apis/security/v1alpha1"
	"github.com/everoute/everoute/tests/e2e/framework/matcher"
	"github.com/everoute/everoute/tests/e2e/framework/model"
)

var _ = Describe("SecurityPolicy", func() {
	AfterEach(func() {
		Expect(e2eEnv.ResetResource(ctx)).Should(Succeed())
	})

	// This case test policy with tcp and icmp can works. We setup three groups of vms (nginx/webserver/database), create
	// and verify policy allow connection: all sources to nginx, nginx to webservers, webserver to databases, and connect
	// between databases.
	//
	//        |---------|          |----------- |          |---------- |
	//  --->  |  nginx  |  <---->  | webservers |  <---->  | databases |
	//        | --------|          |----------- |          |---------- |
	//
	Context("environment with endpoints provide public http service [Feature:TCP] [Feature:ICMP]", func() {
		var nginx, server01, server02, db01, db02, client *model.Endpoint
		var nginxSelector, serverSelector, dbSelector *metav1.LabelSelector
		var nginxPort, serverPort, dbPort int

		BeforeEach(func() {
			nginxPort, serverPort, dbPort = 443, 443, 3306

			nginx = &model.Endpoint{Name: "nginx", TCPPort: nginxPort, Labels: map[string]string{"component": "nginx"}}
			server01 = &model.Endpoint{Name: "server01", TCPPort: serverPort, Labels: map[string]string{"component": "webserver"}}
			server02 = &model.Endpoint{Name: "server02", TCPPort: serverPort, Labels: map[string]string{"component": "webserver"}}
			db01 = &model.Endpoint{Name: "db01", TCPPort: dbPort, Labels: map[string]string{"component": "database"}}
			db02 = &model.Endpoint{Name: "db02", TCPPort: dbPort, Labels: map[string]string{"component": "database"}}
			client = &model.Endpoint{Name: "client"}

			nginxSelector = newSelector(map[string]string{"component": "nginx"})
			serverSelector = newSelector(map[string]string{"component": "webserver"})
			dbSelector = newSelector(map[string]string{"component": "database"})

			Expect(e2eEnv.EndpointManager().SetupMany(ctx, nginx, server01, server02, db01, db02, client)).Should(Succeed())
		})

		When("limits tcp packets between components", func() {
			var nginxPolicy, serverPolicy, dbPolicy *securityv1alpha1.SecurityPolicy

			BeforeEach(func() {
				nginxPolicy = newPolicy("nginx-policy", tier2, nginxSelector)
				addIngressRule(nginxPolicy, "TCP", nginxPort) // allow all connection with nginx port
				addEngressRule(nginxPolicy, "TCP", serverPort, serverSelector)

				serverPolicy = newPolicy("server-policy", tier2, serverSelector)
				addIngressRule(serverPolicy, "TCP", serverPort, nginxSelector)
				addEngressRule(serverPolicy, "TCP", dbPort, dbSelector)

				dbPolicy = newPolicy("db-policy", tier2, dbSelector)
				addIngressRule(dbPolicy, "TCP", dbPort, dbSelector, serverSelector)
				addEngressRule(dbPolicy, "TCP", dbPort, dbSelector)

				Expect(e2eEnv.SetupObjects(ctx, nginxPolicy, serverPolicy, dbPolicy)).Should(Succeed())
			})

			It("should allow normal packets and limits illegal packets", func() {
				assertFlowMatches(&SecurityModel{
					Policies:  []*securityv1alpha1.SecurityPolicy{nginxPolicy, serverPolicy, dbPolicy},
					Endpoints: []*model.Endpoint{nginx, server01, server02, db01, db02, client},
				})

				assertReachable([]*model.Endpoint{nginx}, []*model.Endpoint{db01, db02}, "TCP", false)
				assertReachable([]*model.Endpoint{client}, []*model.Endpoint{server01, server02, db01, db02}, "TCP", false)

				assertReachable([]*model.Endpoint{client}, []*model.Endpoint{nginx}, "TCP", true)
				assertReachable([]*model.Endpoint{nginx}, []*model.Endpoint{server01, server02}, "TCP", true)
				assertReachable([]*model.Endpoint{server01, server02, db01, db02}, []*model.Endpoint{db01, db02}, "TCP", true)
			})

			When("add endpoint into the database group", func() {
				var db03 *model.Endpoint

				BeforeEach(func() {
					db03 = &model.Endpoint{Name: "db03", TCPPort: 3306, Labels: map[string]string{"component": "database"}}
					Expect(e2eEnv.EndpointManager().SetupMany(ctx, db03)).Should(Succeed())
				})

				It("should allow normal packets and limits illegal packets for new member", func() {
					assertFlowMatches(&SecurityModel{
						Policies:  []*securityv1alpha1.SecurityPolicy{nginxPolicy, serverPolicy, dbPolicy},
						Endpoints: []*model.Endpoint{nginx, server01, server02, db01, db02, client},
					})

					// NOTE always success in this case, even if failed to add updated flow
					assertReachable([]*model.Endpoint{nginx, client}, []*model.Endpoint{db03}, "TCP", false)
					assertReachable([]*model.Endpoint{server01, server02, db01, db02}, []*model.Endpoint{db03}, "TCP", true)
				})
			})

			When("update endpoint ip addr in the nginx group", func() {
				BeforeEach(func() {
					Expect(e2eEnv.EndpointManager().RenewIPMany(ctx, nginx)).Should(Succeed())
				})

				It("should allow normal packets and limits illegal packets for update member", func() {
					assertFlowMatches(&SecurityModel{
						Policies:  []*securityv1alpha1.SecurityPolicy{nginxPolicy, serverPolicy, dbPolicy},
						Endpoints: []*model.Endpoint{nginx, server01, server02, db01, db02, client},
					})

					assertReachable([]*model.Endpoint{nginx}, []*model.Endpoint{db01, db02}, "TCP", false)
					assertReachable([]*model.Endpoint{nginx}, []*model.Endpoint{server01, server02}, "TCP", true)
				})
			})

			When("remove endpoint from the webserver group", func() {
				BeforeEach(func() {
					server02.Labels = map[string]string{}
					Expect(e2eEnv.EndpointManager().UpdateMany(ctx, server02)).Should(Succeed())
				})

				It("should limits illegal packets for remove member", func() {
					assertFlowMatches(&SecurityModel{
						Policies:  []*securityv1alpha1.SecurityPolicy{nginxPolicy, serverPolicy, dbPolicy},
						Endpoints: []*model.Endpoint{nginx, server01, server02, db01, db02, client},
					})

					assertReachable([]*model.Endpoint{server02}, []*model.Endpoint{server01, db01, db02}, "TCP", false)
				})
			})

			When("Migrate endpoint from one node to another node", func() {
				BeforeEach(func() {
					if len(e2eEnv.NodeManager().ListAgent()) <= 1 {
						Skip("Require at least two agent")
					}
					Expect(e2eEnv.EndpointManager().MigrateMany(ctx, server01)).Should(Succeed())
				})

				It("Should limit connections between webserver group and other groups", func() {
					assertFlowMatches(&SecurityModel{
						Policies:  []*securityv1alpha1.SecurityPolicy{nginxPolicy, serverPolicy, dbPolicy},
						Endpoints: []*model.Endpoint{nginx, server01, server02, db01, db02, client},
					})

					assertReachable([]*model.Endpoint{client}, []*model.Endpoint{server01, db01, db02}, "TCP", false)

					assertReachable([]*model.Endpoint{nginx}, []*model.Endpoint{server01}, "TCP", true)
					assertReachable([]*model.Endpoint{server01}, []*model.Endpoint{db01, db02}, "TCP", true)
				})
			})
		})

		When("limits icmp packets between components", func() {
			var icmpAllowPolicy, icmpDropPolicy *securityv1alpha1.SecurityPolicy

			BeforeEach(func() {
				icmpDropPolicy = newPolicy("icmp-drop-policy", tier2, serverSelector, dbSelector)
				addIngressRule(icmpDropPolicy, "TCP", 0) // allow all tcp packets

				icmpAllowPolicy = newPolicy("icmp-allow-policy", tier2, nginxSelector)
				addIngressRule(icmpAllowPolicy, "ICMP", 0) // allow all icmp packets

				Expect(e2eEnv.SetupObjects(ctx, icmpAllowPolicy, icmpDropPolicy)).Should(Succeed())
			})

			It("should allow normal packets and limits illegal packets", func() {
				assertFlowMatches(&SecurityModel{
					Policies:  []*securityv1alpha1.SecurityPolicy{icmpAllowPolicy, icmpDropPolicy},
					Endpoints: []*model.Endpoint{nginx, server01, server02, db01, db02, client},
				})

				assertReachable([]*model.Endpoint{client}, []*model.Endpoint{server01, server02, db01, db02}, "ICMP", false)
				assertReachable([]*model.Endpoint{client}, []*model.Endpoint{server01, server02, db01, db02}, "TCP", true)
				assertReachable([]*model.Endpoint{client}, []*model.Endpoint{nginx}, "ICMP", true)
			})
		})
	})

	Context("endpoint isolation [Feature:ISOLATION]", func() {
		var ep01, ep02, ep03, ep04 *model.Endpoint
		var forensicGroup *metav1.LabelSelector
		var forensicGroup2 *metav1.LabelSelector
		var tcpPort int

		BeforeEach(func() {
			if e2eEnv.EndpointManager().Name() == "tower" {
				Skip("isolation vm from tower need tower support")
			}
			tcpPort = 443

			ep01 = &model.Endpoint{Name: "ep01", TCPPort: tcpPort}
			ep02 = &model.Endpoint{Name: "ep02", TCPPort: tcpPort}
			ep03 = &model.Endpoint{Name: "ep03", TCPPort: tcpPort}
			ep04 = &model.Endpoint{Name: "ep04", TCPPort: tcpPort}

			forensicGroup = newSelector(map[string]string{"component": "forensic"})
			forensicGroup2 = newSelector(map[string]string{"component": "forensic2"})

			Expect(e2eEnv.EndpointManager().SetupMany(ctx, ep01, ep02, ep03, ep04)).Should(Succeed())
		})

		When("Isolate endpoint", func() {
			var isolationPolicy *securityv1alpha1.SecurityPolicy

			BeforeEach(func() {
				isolationPolicy = newPolicy("isolation-policy", tier0, ep01.Name)

				Expect(e2eEnv.SetupObjects(ctx, isolationPolicy)).Should(Succeed())
			})

			It("Isolated endpoint should not allow to communicate with all of endpoint", func() {
				securityModel := &SecurityModel{
					Policies:  []*securityv1alpha1.SecurityPolicy{isolationPolicy},
					Endpoints: []*model.Endpoint{ep01, ep02, ep03, ep04},
				}

				By("verify all agents has correct flows")
				assertFlowMatches(securityModel)

				By("verify reachable between endpoints")
				expectedTruthTable := securityModel.NewEmptyTruthTable(true)
				expectedTruthTable.SetAllFrom(ep01.Name, false)
				expectedTruthTable.SetAllTo(ep01.Name, false)
				assertMatchReachTable("TCP", tcpPort, expectedTruthTable)
			})
		})

		When("Forensic endpoint", func() {
			var forensicPolicy1 *securityv1alpha1.SecurityPolicy
			var forensicPolicy2 *securityv1alpha1.SecurityPolicy

			BeforeEach(func() {
				forensicPolicy1 = newPolicy("forensic-policy-ingress", tier1, ep01.Name)
				forensicPolicy1.Spec.PolicyTypes = []networkingv1.PolicyType{networkingv1.PolicyTypeIngress}
				addIngressRule(forensicPolicy1, "TCP", tcpPort, forensicGroup)

				forensicPolicy2 = newPolicy("forensic-policy-egress", tier0, ep01.Name)
				forensicPolicy2.Spec.PolicyTypes = []networkingv1.PolicyType{networkingv1.PolicyTypeEgress}

				// set ep02 as forensic endpoint
				ep02.Labels = map[string]string{"component": "forensic"}

				Expect(e2eEnv.EndpointManager().UpdateMany(ctx, ep02)).Should(Succeed())
				Expect(e2eEnv.SetupObjects(ctx, forensicPolicy1, forensicPolicy2)).Should(Succeed())
			})

			It("Isolated endpoint should not allow to communicate with all of endpoint except forensic defined allowed endpoint", func() {
				securityModel := &SecurityModel{
					Policies:  []*securityv1alpha1.SecurityPolicy{forensicPolicy1, forensicPolicy2},
					Endpoints: []*model.Endpoint{ep01, ep02, ep03, ep04},
				}

				By("verify all agents has correct flows")
				assertFlowMatches(securityModel)

				By("verify reachable between endpoints")
				expectedTruthTable := securityModel.NewEmptyTruthTable(true)
				expectedTruthTable.SetAllFrom(ep01.Name, false)
				expectedTruthTable.SetAllTo(ep01.Name, false)
				expectedTruthTable.Set(ep02.Name, ep01.Name, true)
				assertMatchReachTable("TCP", tcpPort, expectedTruthTable)
			})

			When("forensic update endpoint status after setup policy", func() {
				BeforeEach(func() {
					Expect(e2eEnv.EndpointManager().RenewIPMany(ctx, ep01)).Should(Succeed())
				})

				It("Isolated endpoint should not allow to communicate with all of endpoint except forensic defined allowed endpoint", func() {
					securityModel := &SecurityModel{
						Policies:  []*securityv1alpha1.SecurityPolicy{forensicPolicy1, forensicPolicy2},
						Endpoints: []*model.Endpoint{ep01, ep02, ep03, ep04},
					}

					By("verify all agents has correct flows")
					assertFlowMatches(securityModel)

					By("verify reachable between endpoints")
					expectedTruthTable := securityModel.NewEmptyTruthTable(true)
					expectedTruthTable.SetAllFrom(ep01.Name, false)
					expectedTruthTable.SetAllTo(ep01.Name, false)
					expectedTruthTable.Set(ep02.Name, ep01.Name, true)
					assertMatchReachTable("TCP", tcpPort, expectedTruthTable)
				})
			})
		})

		When("Isolate & Forensic endpoint", func() {
			var forensicPolicy1 *securityv1alpha1.SecurityPolicy
			var forensicPolicy2 *securityv1alpha1.SecurityPolicy
			var isolationPolicy *securityv1alpha1.SecurityPolicy
			BeforeEach(func() {
				forensicPolicy1 = newPolicy("forensic-policy-ingress", tier1, ep02.Name)
				forensicPolicy1.Spec.PolicyTypes = []networkingv1.PolicyType{networkingv1.PolicyTypeIngress}
				addIngressRule(forensicPolicy1, "TCP", tcpPort, forensicGroup)

				forensicPolicy2 = newPolicy("forensic-policy-egress", tier0, ep02.Name)
				forensicPolicy2.Spec.PolicyTypes = []networkingv1.PolicyType{networkingv1.PolicyTypeEgress}

				// set ep02 as forensic endpoint
				ep01.Labels = map[string]string{"component": "forensic"}

				Expect(e2eEnv.EndpointManager().UpdateMany(ctx, ep01)).Should(Succeed())
				Expect(e2eEnv.SetupObjects(ctx, forensicPolicy1, forensicPolicy2)).Should(Succeed())

				isolationPolicy = newPolicy("isolation-policy", tier0, ep01.Name)
				Expect(e2eEnv.SetupObjects(ctx, isolationPolicy)).Should(Succeed())
			})
			It("isolation policy should have higher priority than forensic policy", func() {
				securityModel := &SecurityModel{
					Policies:  []*securityv1alpha1.SecurityPolicy{forensicPolicy1, forensicPolicy2, isolationPolicy},
					Endpoints: []*model.Endpoint{ep01, ep02, ep03, ep04},
				}

				By("verify all agents has correct flows")
				assertFlowMatches(securityModel)

				By("verify reachable between endpoints")
				expectedTruthTable := securityModel.NewEmptyTruthTable(true)
				expectedTruthTable.SetAllFrom(ep01.Name, false)
				expectedTruthTable.SetAllTo(ep01.Name, false)
				expectedTruthTable.SetAllFrom(ep02.Name, false)
				expectedTruthTable.SetAllTo(ep02.Name, false)
				assertMatchReachTable("TCP", tcpPort, expectedTruthTable)

			})
			When("Isolate & Forensic endpoint", func() {
				var forensicPolicy3 *securityv1alpha1.SecurityPolicy
				var forensicPolicy4 *securityv1alpha1.SecurityPolicy
				BeforeEach(func() {
					forensicPolicy3 = newPolicy("forensic-policy2-ingress", tier1, ep03.Name)
					forensicPolicy3.Spec.PolicyTypes = []networkingv1.PolicyType{networkingv1.PolicyTypeIngress}
					addIngressRule(forensicPolicy3, "TCP", tcpPort, forensicGroup2)

					forensicPolicy4 = newPolicy("forensic-policy2-egress", tier0, ep03.Name)
					forensicPolicy4.Spec.PolicyTypes = []networkingv1.PolicyType{networkingv1.PolicyTypeEgress}

					// set ep02 as forensic endpoint
					ep02.Labels = map[string]string{"component": "forensic2"}

					Expect(e2eEnv.EndpointManager().UpdateMany(ctx, ep02)).Should(Succeed())
					Expect(e2eEnv.SetupObjects(ctx, forensicPolicy3, forensicPolicy4)).Should(Succeed())

				})
				It("forensic policy should have effect while cross assigned", func() {
					securityModel := &SecurityModel{
						Policies:  []*securityv1alpha1.SecurityPolicy{forensicPolicy1, forensicPolicy2, forensicPolicy3, forensicPolicy4},
						Endpoints: []*model.Endpoint{ep01, ep02, ep03, ep04},
					}

					By("verify all agents has correct flows")
					assertFlowMatches(securityModel)

					By("verify reachable between endpoints")
					expectedTruthTable := securityModel.NewEmptyTruthTable(true)
					expectedTruthTable.SetAllFrom(ep01.Name, false)
					expectedTruthTable.SetAllTo(ep01.Name, false)
					expectedTruthTable.SetAllFrom(ep02.Name, false)
					expectedTruthTable.SetAllTo(ep02.Name, false)
					expectedTruthTable.SetAllFrom(ep03.Name, false)
					expectedTruthTable.SetAllTo(ep03.Name, false)
					assertMatchReachTable("TCP", tcpPort, expectedTruthTable)

				})
			})
		})
	})

	// This case test policy with udp and ipblocks can works. We setup two peers ntp server and client in different cidr,
	// create and verify policy allow connect with ntp in its cidr.
	//
	//  |----------------|         |--------------- |    |---------------- |         |--------------- |
	//  | "10.0.0.0/28"  |  <--->  | ntp-production |    | ntp-development |  <--->  | "10.0.0.16/28" |
	//  | ---------------|         |--------------- |    |---------------- |         |--------------- |
	//
	Context("environment with endpoints provide internal udp service [Feature:UDP] [Feature:IPBlocks]", func() {
		var ntp01, ntp02, client01, client02 *model.Endpoint
		var ntpProductionSelector, ntpDevelopmentSelector *metav1.LabelSelector

		var ntpPort int
		var productionCidr, developmentCidr string

		BeforeEach(func() {
			ntpPort = 123
			productionCidr = "10.0.0.0/28"
			developmentCidr = "10.0.0.16/28"

			client01 = &model.Endpoint{Name: "ntp-client01", ExpectSubnet: productionCidr}
			client02 = &model.Endpoint{Name: "ntp-client02", ExpectSubnet: developmentCidr}
			ntp01 = &model.Endpoint{Name: "ntp01-server", ExpectSubnet: productionCidr, UDPPort: ntpPort, Labels: map[string]string{"component": "ntp", "env": "production"}}
			ntp02 = &model.Endpoint{Name: "ntp02-server", ExpectSubnet: developmentCidr, UDPPort: ntpPort, Labels: map[string]string{"component": "ntp", "env": "development"}}

			ntpProductionSelector = newSelector(map[string]string{"component": "ntp", "env": "production"})
			ntpDevelopmentSelector = newSelector(map[string]string{"component": "ntp", "env": "development"})

			Expect(e2eEnv.EndpointManager().SetupMany(ctx, ntp01, ntp02, client01, client02)).Should(Succeed())
		})

		When("limits udp packets by ipBlocks between server and client", func() {
			var ntpProductionPolicy, ntpDevelopmentPolicy *securityv1alpha1.SecurityPolicy

			BeforeEach(func() {
				ntpProductionPolicy = newPolicy("ntp-production-policy", tier2, ntpProductionSelector)
				addIngressRule(ntpProductionPolicy, "UDP", ntpPort, &networkingv1.IPBlock{CIDR: productionCidr})

				ntpDevelopmentPolicy = newPolicy("ntp-development-policy", tier2, ntpDevelopmentSelector)
				addIngressRule(ntpDevelopmentPolicy, "UDP", ntpPort, &networkingv1.IPBlock{CIDR: developmentCidr})

				Expect(e2eEnv.SetupObjects(ctx, ntpProductionPolicy, ntpDevelopmentPolicy)).Should(Succeed())
			})

			It("should allow normal packets and limits illegal packets", func() {
				By("verify agent has correct open flows")
				assertFlowMatches(&SecurityModel{
					Policies:  []*securityv1alpha1.SecurityPolicy{ntpProductionPolicy, ntpDevelopmentPolicy},
					Endpoints: []*model.Endpoint{ntp01, ntp02, client01, client02},
				})

				By("verify policy limits illegal packets")
				assertReachable([]*model.Endpoint{client01}, []*model.Endpoint{ntp02}, "UDP", false)
				assertReachable([]*model.Endpoint{client02}, []*model.Endpoint{ntp01}, "UDP", false)

				By("verify reachable between servers")
				assertReachable([]*model.Endpoint{ntp01}, []*model.Endpoint{ntp02}, "UDP", false)
				assertReachable([]*model.Endpoint{ntp02}, []*model.Endpoint{ntp01}, "UDP", false)

				By("verify reachable between server and client")
				assertReachable([]*model.Endpoint{client01}, []*model.Endpoint{ntp01}, "UDP", true)
				assertReachable([]*model.Endpoint{client02}, []*model.Endpoint{ntp02}, "UDP", true)
			})
		})
	})

	Context("Complicated securityPolicy definition that contains semanticly conflict policyrules", func() {
		var group1Endpoint1, group2Endpoint01, group3Endpoint01 *model.Endpoint
		var group1, group2, group3 *metav1.LabelSelector
		var epTCPPort int

		BeforeEach(func() {
			epTCPPort = 80

			group1Endpoint1 = &model.Endpoint{
				Name:    "group1-ep01",
				TCPPort: epTCPPort,
				Labels:  map[string]string{"group": "group1"},
			}
			group2Endpoint01 = &model.Endpoint{
				Name:    "group2-ep01",
				TCPPort: epTCPPort,
				Labels:  map[string]string{"group": "group2"},
			}
			group3Endpoint01 = &model.Endpoint{
				Name:    "group3-ep01",
				TCPPort: epTCPPort,
				Labels:  map[string]string{"group": "group3"},
			}

			group1 = newSelector(map[string]string{"group": "group1"})
			group2 = newSelector(map[string]string{"group": "group2"})
			group3 = newSelector(map[string]string{"group": "group3"})

			Expect(e2eEnv.EndpointManager().SetupMany(ctx, group1Endpoint1, group2Endpoint01, group3Endpoint01)).Should(Succeed())
		})

		When("Define securityPolicy without semanticly conflicts with any of securityPolicy already exists", func() {
			var securityPolicy1, securityPolicy2 *securityv1alpha1.SecurityPolicy

			BeforeEach(func() {
				securityPolicy1 = newPolicy("group1-policy", tier0, group1)
				addIngressRule(securityPolicy1, "TCP", epTCPPort, group2)
				securityPolicy1.Spec.SymmetricMode = true

				Expect(e2eEnv.SetupObjects(ctx, securityPolicy1)).Should(Succeed())
			})

			AfterEach(func() {
				Expect(e2eEnv.CleanObjects(ctx, securityPolicy1)).Should(Succeed())
			})

			It("should allow group2 to communicate with group1", func() {
				assertReachable([]*model.Endpoint{group2Endpoint01}, []*model.Endpoint{group1Endpoint1}, "TCP", true)
			})

			When("Define a securityPolicy which semanticly conflict with existing securityPolicy", func() {
				BeforeEach(func() {
					securityPolicy2 = newPolicy("group2-policy", tier0, group2)
					addEngressRule(securityPolicy2, "TCP", epTCPPort, group3)

					Expect(e2eEnv.SetupObjects(ctx, securityPolicy2)).Should(Succeed())
				})

				AfterEach(func() {
					Expect(e2eEnv.CleanObjects(ctx, securityPolicy2)).Should(Succeed())
				})

				It("should deny group2 to communicate with group1", func() {
					assertReachable([]*model.Endpoint{group2Endpoint01}, []*model.Endpoint{group1Endpoint1}, "TCP", true)
				})
			})
		})
	})

	// This case would setup endpoints in random vlan, and check reachable between them.
	Context("environment with endpoints from specify vlan [Feature:VLAN]", func() {
		var groupA, groupB *metav1.LabelSelector
		var endpointA, endpointB, endpointC *model.Endpoint
		var tcpPort, vlanID int

		BeforeEach(func() {
			tcpPort = rand.IntnRange(1000, 5000)
			vlanID = rand.IntnRange(0, 4095)

			endpointA = &model.Endpoint{Name: "ep.a", VID: vlanID, TCPPort: tcpPort, Labels: map[string]string{"group": "gx"}}
			endpointB = &model.Endpoint{Name: "ep.b", VID: vlanID, TCPPort: tcpPort, Labels: map[string]string{"group": "gy"}}
			endpointC = &model.Endpoint{Name: "ep.c", VID: vlanID, TCPPort: tcpPort, Labels: map[string]string{"group": "gz"}}

			groupA = newSelector(map[string]string{"group": "gx"})
			groupB = newSelector(map[string]string{"group": "gy"})

			Expect(e2eEnv.EndpointManager().SetupMany(ctx, endpointA, endpointB, endpointC)).Should(Succeed())
		})

		When("limits tcp packets between components", func() {
			var groupPolicy *securityv1alpha1.SecurityPolicy

			BeforeEach(func() {
				// allow traffic from groupA to groupB
				groupPolicy = newPolicy("group-policy", tier2, groupA)
				addEngressRule(groupPolicy, "TCP", tcpPort, groupB)
				Expect(e2eEnv.SetupObjects(ctx, groupPolicy)).Should(Succeed())
			})

			It("should allow normal packets and limits illegal packets", func() {
				securityModel := &SecurityModel{
					Policies:  []*securityv1alpha1.SecurityPolicy{groupPolicy},
					Endpoints: []*model.Endpoint{endpointA, endpointB, endpointC},
				}

				By("verify reachable between endpoints")
				expectedTruthTable := securityModel.NewEmptyTruthTable(true)
				expectedTruthTable.SetAllFrom(endpointA.Name, false)
				expectedTruthTable.SetAllTo(endpointA.Name, false)
				expectedTruthTable.Set(endpointA.Name, endpointB.Name, true)
				assertMatchReachTable("TCP", tcpPort, expectedTruthTable)
			})
		})
	})
})

var _ = Describe("GlobalPolicy", func() {
	AfterEach(func() {
		Expect(e2eEnv.ResetResource(ctx)).Should(Succeed())
	})

	Context("environment with global drop policy [Feature:GlobalPolicy]", func() {
		var endpointA, endpointB, endpointC *model.Endpoint
		var tcpPort int

		BeforeEach(func() {
			tcpPort = rand.IntnRange(1000, 5000)

			endpointA = &model.Endpoint{Name: "ep.a", TCPPort: tcpPort}
			endpointB = &model.Endpoint{Name: "ep.b", TCPPort: tcpPort}
			endpointC = &model.Endpoint{Name: "ep.c", TCPPort: tcpPort}

			Expect(e2eEnv.EndpointManager().SetupMany(ctx, endpointA, endpointB, endpointC)).Should(Succeed())
		})

		It("should allow all traffics between endpoints", func() {
			securityModel := &SecurityModel{
				Endpoints: []*model.Endpoint{endpointA, endpointB, endpointC},
			}
			By("verify reachable between endpoints")
			expectedTruthTable := securityModel.NewEmptyTruthTable(true)
			assertMatchReachTable("TCP", tcpPort, expectedTruthTable)
		})

		When("create global drop policy", func() {
			var globalPolicy *securityv1alpha1.GlobalPolicy

			BeforeEach(func() {
				// drop all traffics between endpoints
				globalPolicy = newGlobalPolicy(securityv1alpha1.GlobalDefaultActionDrop)
				Expect(e2eEnv.SetupObjects(ctx, globalPolicy)).Should(Succeed())
			})

			It("should limits all traffics between endpoints", func() {
				securityModel := &SecurityModel{
					Endpoints: []*model.Endpoint{endpointA, endpointB, endpointC},
				}
				By("verify reachable between endpoints")
				expectedTruthTable := securityModel.NewEmptyTruthTable(false)
				assertMatchReachTable("TCP", tcpPort, expectedTruthTable)
			})

			When("add endpointA and endpointB to whitelist", func() {
				BeforeEach(func() {
					updatePolicy := globalPolicy.DeepCopy()

					for _, ep := range []*model.Endpoint{endpointA, endpointB} {
						ip, _, err := net.ParseCIDR(ep.Status.IPAddr)
						Expect(err).Should(Succeed())
						ipCidr := fmt.Sprintf("%s/32", ip.String())
						updatePolicy.Spec.Whitelist = append(updatePolicy.Spec.Whitelist, networkingv1.IPBlock{CIDR: ipCidr})
					}

					Expect(e2eEnv.KubeClient().Patch(ctx, updatePolicy, client.MergeFrom(globalPolicy))).Should(Succeed())
				})

				It("should allow all traffics between endpointA and endpointB", func() {
					securityModel := &SecurityModel{
						Endpoints: []*model.Endpoint{endpointA, endpointB, endpointC},
					}
					By("verify reachable between endpoints")
					expectedTruthTable := securityModel.NewEmptyTruthTable(false)
					expectedTruthTable.Set(endpointA.Name, endpointB.Name, true)
					expectedTruthTable.Set(endpointB.Name, endpointA.Name, true)
					assertMatchReachTable("TCP", tcpPort, expectedTruthTable)
				})
			})
		})
	})
})

func newSelector(selector map[string]string) *metav1.LabelSelector {
	return &metav1.LabelSelector{
		MatchLabels: selector,
	}
}

func newPolicy(name, tier string, appliedPeers ...interface{}) *securityv1alpha1.SecurityPolicy {
	policy := &securityv1alpha1.SecurityPolicy{}
	policy.Name = name
	policy.Namespace = metav1.NamespaceDefault
	policy.Spec.Tier = tier
	policy.Spec.PolicyTypes = []networkingv1.PolicyType{
		networkingv1.PolicyTypeIngress,
		networkingv1.PolicyTypeEgress,
	}

	for _, appliedPeer := range appliedPeers {
		switch peer := appliedPeer.(type) {

		case *metav1.LabelSelector:
			policy.Spec.AppliedTo = append(policy.Spec.AppliedTo, securityv1alpha1.ApplyToPeer{
				EndpointSelector: peer,
			})

		case string:
			policy.Spec.AppliedTo = append(policy.Spec.AppliedTo, securityv1alpha1.ApplyToPeer{
				Endpoint: &peer,
			})

		default:
			panic(fmt.Sprintf("unsupport peer type %T", appliedPeer))
		}
	}

	return policy
}

func newGlobalPolicy(defaultAction securityv1alpha1.GlobalDefaultAction, whitelist ...string) *securityv1alpha1.GlobalPolicy {
	var policy securityv1alpha1.GlobalPolicy

	policy.Name = rand.String(6)
	policy.Spec.DefaultAction = defaultAction

	for _, cidr := range whitelist {
		policy.Spec.Whitelist = append(policy.Spec.Whitelist, networkingv1.IPBlock{
			CIDR: cidr,
		})
	}

	return &policy
}

func addIngressRule(policy *securityv1alpha1.SecurityPolicy, protocol string, port int, policyPeers ...interface{}) {
	ingressRule := &securityv1alpha1.Rule{
		Name: rand.String(20),
		Ports: []securityv1alpha1.SecurityPolicyPort{
			{
				Protocol:  securityv1alpha1.Protocol(protocol),
				PortRange: strconv.Itoa(port),
			},
		},
		From: getPolicyPeer(policyPeers...),
	}

	policy.Spec.IngressRules = append(policy.Spec.IngressRules, *ingressRule)
}

func addEngressRule(policy *securityv1alpha1.SecurityPolicy, protocol string, port int, policyPeers ...interface{}) {
	egressRule := &securityv1alpha1.Rule{
		Name: rand.String(20),
		Ports: []securityv1alpha1.SecurityPolicyPort{
			{
				Protocol:  securityv1alpha1.Protocol(protocol),
				PortRange: strconv.Itoa(port),
			},
		},
		To: getPolicyPeer(policyPeers...),
	}

	policy.Spec.EgressRules = append(policy.Spec.EgressRules, *egressRule)
}

func getPolicyPeer(policyPeers ...interface{}) []securityv1alpha1.SecurityPolicyPeer {
	var peerList []securityv1alpha1.SecurityPolicyPeer

	for _, policyPeer := range policyPeers {
		switch peer := policyPeer.(type) {

		case *metav1.LabelSelector:
			peerList = append(peerList, securityv1alpha1.SecurityPolicyPeer{
				EndpointSelector: peer,
			})

		case *types.NamespacedName:
			peerList = append(peerList, securityv1alpha1.SecurityPolicyPeer{
				Endpoint: &securityv1alpha1.NamespacedName{
					Name:      peer.Name,
					Namespace: peer.Namespace,
				},
			})

		case *networkingv1.IPBlock:
			peerList = append(peerList, securityv1alpha1.SecurityPolicyPeer{
				IPBlock: peer,
			})

		case *securityv1alpha1.SecurityPolicyPeer:
			peerList = append(peerList, *peer)

		default:
			panic(fmt.Sprintf("unsupport peer type %T", policyPeer))
		}
	}

	return peerList
}

func assertFlowMatches(securityModel *SecurityModel) {
	// todo: expectFlows should always not empty, check it first
	expectFlows := securityModel.ExpectedFlows()

	Eventually(func() map[string][]string {
		allFlows, err := e2eEnv.NodeManager().DumpFlowAll()
		Expect(err).Should(Succeed())
		return allFlows
	}, 2*e2eEnv.Timeout(), e2eEnv.Interval()).Should(matcher.ContainsFlow(expectFlows))
}

func assertReachable(sources []*model.Endpoint, destinations []*model.Endpoint, protocol string, expectReach bool) {
	Eventually(func() error {
		var errList []error

		for _, src := range sources {
			for _, dst := range destinations {
				var port int
				if protocol == "TCP" {
					port = dst.TCPPort
				}
				if protocol == "UDP" {
					port = dst.UDPPort
				}
				reach, err := e2eEnv.EndpointManager().Reachable(ctx, src.Name, dst.Name, protocol, port)
				Expect(err).Should(Succeed())

				if reach == expectReach {
					continue
				}
				errList = append(errList,
					fmt.Errorf("get reachable %t, want %t. src: %+v, dst: %+v, protocol: %s", reach, expectReach, src, dst, protocol),
				)
			}
		}
		return errors.NewAggregate(errList)
	}, 2*e2eEnv.Timeout(), e2eEnv.Interval()).Should(Succeed())
}

func assertMatchReachTable(protocol string, port int, expectedTruthTable *model.TruthTable) {
	Eventually(func() *model.TruthTable {
		ctx, cancel := context.WithTimeout(ctx, e2eEnv.Timeout())
		defer cancel()

		tt, err := e2eEnv.EndpointManager().ReachTruthTable(ctx, protocol, port)
		Expect(err).Should(Succeed())
		return tt
	}, 2*e2eEnv.Timeout(), e2eEnv.Interval()).Should(matcher.MatchTruthTable(expectedTruthTable, true))
}
