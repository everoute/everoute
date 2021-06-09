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
	"fmt"
	"strconv"
	"strings"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apimachinery/pkg/util/rand"

	groupv1alpha1 "github.com/smartxworks/lynx/pkg/apis/group/v1alpha1"
	securityv1alpha1 "github.com/smartxworks/lynx/pkg/apis/security/v1alpha1"
	"github.com/smartxworks/lynx/pkg/types"
	"github.com/smartxworks/lynx/tests/e2e/framework/matcher"
	"github.com/smartxworks/lynx/tests/e2e/framework/model"
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
		var nginxGroup, serverGroup, dbGroup *groupv1alpha1.EndpointGroup
		var nginxPort, serverPort, dbPort int

		BeforeEach(func() {
			nginxPort, serverPort, dbPort = 443, 443, 3306

			nginx = &model.Endpoint{Name: "nginx", TCPPort: nginxPort, Labels: map[string]string{"component": "nginx"}}
			server01 = &model.Endpoint{Name: "server01", TCPPort: serverPort, Labels: map[string]string{"component": "webserver"}}
			server02 = &model.Endpoint{Name: "server02", TCPPort: serverPort, Labels: map[string]string{"component": "webserver"}}
			db01 = &model.Endpoint{Name: "db01", TCPPort: dbPort, Labels: map[string]string{"component": "database"}}
			db02 = &model.Endpoint{Name: "db02", TCPPort: dbPort, Labels: map[string]string{"component": "database"}}
			client = &model.Endpoint{Name: "client"}

			nginxGroup = newGroup("nginx", map[string]string{"component": "nginx"})
			serverGroup = newGroup("webserver", map[string]string{"component": "webserver"})
			dbGroup = newGroup("database", map[string]string{"component": "database"})

			Expect(e2eEnv.EndpointManager().SetupMany(ctx, nginx, server01, server02, db01, db02, client)).Should(Succeed())
			Expect(e2eEnv.SetupObjects(ctx, nginxGroup, serverGroup, dbGroup)).Should(Succeed())
		})

		When("limits tcp packets between components", func() {
			var nginxPolicy, serverPolicy, dbPolicy *securityv1alpha1.SecurityPolicy

			BeforeEach(func() {
				nginxPolicy = newPolicy("nginx-policy", tier1, 50, []string{nginxGroup.Name}, nil)
				addIngressRule(nginxPolicy, "TCP", nginxPort) // allow all connection with nginx port
				addEngressRule(nginxPolicy, "TCP", serverPort, serverGroup.Name)

				serverPolicy = newPolicy("server-policy", tier1, 50, []string{serverGroup.Name}, nil)
				addIngressRule(serverPolicy, "TCP", serverPort, nginxGroup.Name)
				addEngressRule(serverPolicy, "TCP", dbPort, dbGroup.Name)

				dbPolicy = newPolicy("db-policy", tier1, 50, []string{dbGroup.Name}, nil)
				addIngressRule(dbPolicy, "TCP", dbPort, dbGroup.Name, serverGroup.Name)
				addEngressRule(dbPolicy, "TCP", dbPort, dbGroup.Name)

				Expect(e2eEnv.SetupObjects(ctx, nginxPolicy, serverPolicy, dbPolicy)).Should(Succeed())
			})

			It("should allow normal packets and limits illegal packets", func() {
				assertFlowMatches(&SecurityModel{
					Policies:  []*securityv1alpha1.SecurityPolicy{nginxPolicy, serverPolicy, dbPolicy},
					Groups:    []*groupv1alpha1.EndpointGroup{nginxGroup, serverGroup, dbGroup},
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
						Groups:    []*groupv1alpha1.EndpointGroup{nginxGroup, serverGroup, dbGroup},
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
						Groups:    []*groupv1alpha1.EndpointGroup{nginxGroup, serverGroup, dbGroup},
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
						Groups:    []*groupv1alpha1.EndpointGroup{nginxGroup, serverGroup, dbGroup},
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
						Groups:    []*groupv1alpha1.EndpointGroup{nginxGroup, serverGroup, dbGroup},
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
				icmpDropPolicy = newPolicy("icmp-drop-policy", tier1, 50, []string{serverGroup.Name, dbGroup.Name}, nil)
				addIngressRule(icmpDropPolicy, "TCP", 0) // allow all tcp packets

				icmpAllowPolicy = newPolicy("icmp-allow-policy", tier1, 50, []string{nginxGroup.Name}, nil)
				addIngressRule(icmpAllowPolicy, "ICMP", 0) // allow all icmp packets

				Expect(e2eEnv.SetupObjects(ctx, icmpAllowPolicy, icmpDropPolicy)).Should(Succeed())
			})

			It("should allow normal packets and limits illegal packets", func() {
				assertFlowMatches(&SecurityModel{
					Policies:  []*securityv1alpha1.SecurityPolicy{icmpAllowPolicy, icmpDropPolicy},
					Groups:    []*groupv1alpha1.EndpointGroup{nginxGroup, serverGroup, dbGroup},
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
		var forensicGroup *groupv1alpha1.EndpointGroup
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

			forensicGroup = newGroup("forensic", map[string]string{"component": "forensic"})

			Expect(e2eEnv.SetupObjects(ctx, forensicGroup)).Should(Succeed())
			Expect(e2eEnv.EndpointManager().SetupMany(ctx, ep01, ep02, ep03, ep04)).Should(Succeed())
		})

		When("Isolate endpoint", func() {
			var isolationPolicy *securityv1alpha1.SecurityPolicy

			BeforeEach(func() {
				isolationPolicy = newPolicy("isolation-policy", tier0, 50, nil, []string{ep01.Name})

				Expect(e2eEnv.SetupObjects(ctx, isolationPolicy)).Should(Succeed())
			})

			It("Isolated endpoint should not allow to communicate with all of endpoint", func() {
				securityModel := &SecurityModel{
					Policies:  []*securityv1alpha1.SecurityPolicy{isolationPolicy},
					Groups:    []*groupv1alpha1.EndpointGroup{forensicGroup},
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
			var forensicPolicy *securityv1alpha1.SecurityPolicy

			BeforeEach(func() {
				forensicPolicy = newPolicy("forensic-policy", tier0, 100, nil, []string{ep01.Name})
				addIngressRule(forensicPolicy, "TCP", tcpPort, forensicGroup.Name)

				// set ep02 as forensic endpoint
				ep02.Labels = map[string]string{"component": "forensic"}

				Expect(e2eEnv.EndpointManager().UpdateMany(ctx, ep02)).Should(Succeed())
				Expect(e2eEnv.SetupObjects(ctx, forensicPolicy)).Should(Succeed())
			})

			It("Isolated endpoint should not allow to communicate with all of endpoint except forensic defined allowed endpoint", func() {
				securityModel := &SecurityModel{
					Policies:  []*securityv1alpha1.SecurityPolicy{forensicPolicy},
					Groups:    []*groupv1alpha1.EndpointGroup{forensicGroup},
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
						Policies:  []*securityv1alpha1.SecurityPolicy{forensicPolicy},
						Groups:    []*groupv1alpha1.EndpointGroup{forensicGroup},
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
		var ntpProductionGroup, ntpDevelopmentGroup *groupv1alpha1.EndpointGroup

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

			ntpProductionGroup = newGroup("ntp-production", map[string]string{"component": "ntp", "env": "production"})
			ntpDevelopmentGroup = newGroup("ntp-development", map[string]string{"component": "ntp", "env": "development"})

			Expect(e2eEnv.EndpointManager().SetupMany(ctx, ntp01, ntp02, client01, client02)).Should(Succeed())
			Expect(e2eEnv.SetupObjects(ctx, ntpProductionGroup, ntpDevelopmentGroup)).Should(Succeed())
		})

		When("limits udp packets by ipBlocks between server and client", func() {
			var ntpProductionPolicy, ntpDevelopmentPolicy *securityv1alpha1.SecurityPolicy

			BeforeEach(func() {
				ntpProductionPolicy = newPolicy("ntp-production-policy", tier1, 50, []string{ntpProductionGroup.Name}, nil)
				addIngressRule(ntpProductionPolicy, "UDP", ntpPort, productionCidr)

				ntpDevelopmentPolicy = newPolicy("ntp-development-policy", tier1, 50, []string{ntpDevelopmentGroup.Name}, nil)
				addIngressRule(ntpDevelopmentPolicy, "UDP", ntpPort, developmentCidr)

				Expect(e2eEnv.SetupObjects(ctx, ntpProductionPolicy, ntpDevelopmentPolicy)).Should(Succeed())
			})

			It("should allow normal packets and limits illegal packets", func() {
				By("verify agent has correct open flows")
				assertFlowMatches(&SecurityModel{
					Policies:  []*securityv1alpha1.SecurityPolicy{ntpProductionPolicy, ntpDevelopmentPolicy},
					Groups:    []*groupv1alpha1.EndpointGroup{ntpProductionGroup, ntpDevelopmentGroup},
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
		var group1, group2, group3 *groupv1alpha1.EndpointGroup
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

			group1 = newGroup("group1", map[string]string{"group": "group1"})
			group2 = newGroup("group2", map[string]string{"group": "group2"})
			group3 = newGroup("group3", map[string]string{"group": "group3"})

			Expect(e2eEnv.EndpointManager().SetupMany(ctx, group1Endpoint1, group2Endpoint01, group3Endpoint01)).Should(Succeed())
			Expect(e2eEnv.SetupObjects(ctx, group1, group2, group3)).Should(Succeed())
		})

		AfterEach(func() {
			Expect(e2eEnv.EndpointManager().CleanMany(ctx, group1Endpoint1, group2Endpoint01, group3Endpoint01)).Should(Succeed())
			Expect(e2eEnv.CleanObjects(ctx, group1, group2, group3)).Should(Succeed())
		})

		When("Define securityPolicy without semanticly conflicts with any of securityPolicy already exists", func() {
			var securityPolicy1, securityPolicy2 *securityv1alpha1.SecurityPolicy

			BeforeEach(func() {
				securityPolicy1 = newPolicy("group1-policy", tier0, 50, []string{"group1"}, nil)
				addIngressRule(securityPolicy1, "TCP", epTCPPort, group2.Name)
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
					securityPolicy2 = newPolicy("group2-policy", tier0, 50, []string{"group2"}, nil)
					addEngressRule(securityPolicy2, "TCP", epTCPPort, group3.Name)

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
		var groupA, groupB, groupC *groupv1alpha1.EndpointGroup
		var endpointA, endpointB, endpointC *model.Endpoint
		var tcpPort, vlanID int

		BeforeEach(func() {
			tcpPort = rand.IntnRange(1000, 5000)
			vlanID = rand.IntnRange(0, 4095)

			endpointA = &model.Endpoint{Name: "ep.a", VID: vlanID, TCPPort: tcpPort, Labels: map[string]string{"group": "gx"}}
			endpointB = &model.Endpoint{Name: "ep.b", VID: vlanID, TCPPort: tcpPort, Labels: map[string]string{"group": "gy"}}
			endpointC = &model.Endpoint{Name: "ep.c", VID: vlanID, TCPPort: tcpPort, Labels: map[string]string{"group": "gz"}}

			groupA = newGroup("gx", map[string]string{"group": "gx"})
			groupB = newGroup("gy", map[string]string{"group": "gy"})
			groupC = newGroup("gz", map[string]string{"group": "gz"})

			Expect(e2eEnv.EndpointManager().SetupMany(ctx, endpointA, endpointB, endpointC)).Should(Succeed())
			Expect(e2eEnv.SetupObjects(ctx, groupA, groupB, groupC)).Should(Succeed())
		})

		When("limits tcp packets between components", func() {
			var groupPolicy *securityv1alpha1.SecurityPolicy

			BeforeEach(func() {
				// allow traffic from groupA to groupB
				groupPolicy = newPolicy("group-policy", tier1, 50, []string{groupA.Name}, nil)
				addEngressRule(groupPolicy, "TCP", tcpPort, groupB.Name)
				Expect(e2eEnv.SetupObjects(ctx, groupPolicy)).Should(Succeed())
			})

			It("should allow normal packets and limits illegal packets", func() {
				securityModel := &SecurityModel{
					Policies:  []*securityv1alpha1.SecurityPolicy{groupPolicy},
					Groups:    []*groupv1alpha1.EndpointGroup{groupA, groupB},
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

func newGroup(name string, selector map[string]string) *groupv1alpha1.EndpointGroup {
	group := &groupv1alpha1.EndpointGroup{}
	group.Name = name

	group.Spec.Selector = &metav1.LabelSelector{
		MatchLabels: selector,
	}

	return group
}

func newPolicy(name, tier string, priority int32, appliedGroup []string, endpoints []string) *securityv1alpha1.SecurityPolicy {
	policy := &securityv1alpha1.SecurityPolicy{}
	policy.Name = name

	policy.Spec = securityv1alpha1.SecurityPolicySpec{
		Tier:     tier,
		Priority: priority,
		AppliedTo: securityv1alpha1.AppliedTo{
			EndpointGroups: appliedGroup,
			Endpoints:      endpoints,
		},
	}

	return policy
}

func addIngressRule(policy *securityv1alpha1.SecurityPolicy, protocol string, port int, peers ...string) {
	ingressRule := &securityv1alpha1.Rule{
		Name: rand.String(20),
		Ports: []securityv1alpha1.SecurityPolicyPort{
			{
				Protocol:  securityv1alpha1.Protocol(protocol),
				PortRange: strconv.Itoa(port),
			},
		},
		From: getPeer(peers...),
	}

	policy.Spec.IngressRules = append(policy.Spec.IngressRules, *ingressRule)
}

func addEngressRule(policy *securityv1alpha1.SecurityPolicy, protocol string, port int, peers ...string) {
	egressRule := &securityv1alpha1.Rule{
		Name: rand.String(20),
		Ports: []securityv1alpha1.SecurityPolicyPort{
			{
				Protocol:  securityv1alpha1.Protocol(protocol),
				PortRange: strconv.Itoa(port),
			},
		},
		To: getPeer(peers...),
	}

	policy.Spec.EgressRules = append(policy.Spec.EgressRules, *egressRule)
}

// peer is group peer or cidr peer, format like: group01 or 10.0.0.0/24.
func getPeer(peers ...string) securityv1alpha1.SecurityPolicyPeer {
	var policyPeer securityv1alpha1.SecurityPolicyPeer

	for _, peer := range peers {
		if strings.Count(peer, "/") == 1 {
			prefixLen, _ := strconv.Atoi(strings.Split(peer, "/")[1])
			policyPeer.IPBlocks = append(policyPeer.IPBlocks, securityv1alpha1.IPBlock{
				IP:           types.IPAddress(strings.Split(peer, "/")[0]),
				PrefixLength: int32(prefixLen),
			})
		} else if peer != "" {
			policyPeer.EndpointGroups = append(policyPeer.EndpointGroups, peer)
		}
	}

	return policyPeer
}

func assertFlowMatches(securityModel *SecurityModel) {
	// todo: expectFlows should always not empty, check it first
	expectFlows := securityModel.ExpectedFlows()

	Eventually(func() map[string][]string {
		allFlows, err := e2eEnv.NodeManager().DumpFlowAll()
		Expect(err).Should(Succeed())
		return allFlows
	}, e2eEnv.Timeout(), e2eEnv.Interval()).Should(matcher.ContainsFlow(expectFlows))
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
	}, e2eEnv.Timeout(), e2eEnv.Interval()).Should(Succeed())
}

func assertMatchReachTable(protocol string, port int, expectedTruthTable *model.TruthTable) {
	Eventually(func() *model.TruthTable {
		tt, err := e2eEnv.EndpointManager().ReachTruthTable(ctx, protocol, port)
		Expect(err).Should(Succeed())
		return tt
	}, e2eEnv.Timeout(), e2eEnv.Interval()).Should(matcher.MatchTruthTable(expectedTruthTable, true))
}
