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
	"github.com/smartxworks/lynx/tests/e2e/framework"
)

var _ = Describe("SecurityPolicy", func() {

	// This case test policy with tcp and icmp can works. We setup three groups of vms (nginx/webserver/database), create
	// and verify policy allow connection: all sources to nginx, nginx to webservers, webserver to databases, and connect
	// between databases.
	//
	//        |---------|          |----------- |          |---------- |
	//  --->  |  nginx  |  <---->  | webservers |  <---->  | databases |
	//        | --------|          |----------- |          |---------- |
	//
	Context("environment with virtual machines provide public http service [Feature:TCP] [Feature:ICMP]", func() {
		var nginx, server01, server02, db01, db02, client *framework.VM
		var nginxGroup, serverGroup, dbGroup *groupv1alpha1.EndpointGroup
		var nginxPort, serverPort, dbPort int

		BeforeEach(func() {
			nginxPort, serverPort, dbPort = 443, 443, 3306

			nginx = &framework.VM{Name: "nginx", TCPPort: nginxPort, Labels: "component=nginx"}
			server01 = &framework.VM{Name: "server01", TCPPort: serverPort, Labels: "component=webserver"}
			server02 = &framework.VM{Name: "server02", TCPPort: serverPort, Labels: "component=webserver"}
			db01 = &framework.VM{Name: "db01", TCPPort: dbPort, Labels: "component=database"}
			db02 = &framework.VM{Name: "db02", TCPPort: dbPort, Labels: "component=database"}
			client = &framework.VM{Name: "client"}

			nginxGroup = newGroup("nginx", "component=nginx")
			serverGroup = newGroup("webserver", "component=webserver")
			dbGroup = newGroup("database", "component=database")

			Expect(e2eEnv.SetupVMs(nginx, server01, server02, db01, db02, client)).Should(Succeed())
			Expect(e2eEnv.SetupObjects(nginxGroup, serverGroup, dbGroup)).Should(Succeed())
		})

		AfterEach(func() {
			Expect(e2eEnv.CleanVMs(nginx, server01, server02, db01, db02, client)).Should(Succeed())
			Expect(e2eEnv.CleanObjects(nginxGroup, serverGroup, dbGroup)).Should(Succeed())
		})

		When("limits tcp packets between components", func() {
			var nginxPolicy, serverPolicy, dbPolicy *securityv1alpha1.SecurityPolicy

			BeforeEach(func() {
				nginxPolicy = newPolicy("nginx-policy", tier1, 50, nginxGroup.Name)
				addIngressRule(nginxPolicy, "TCP", nginxPort) // allow all connection with nginx port
				addEngressRule(nginxPolicy, "TCP", serverPort, serverGroup.Name)

				serverPolicy = newPolicy("server-policy", tier1, 50, serverGroup.Name)
				addIngressRule(serverPolicy, "TCP", serverPort, nginxGroup.Name)
				addEngressRule(serverPolicy, "TCP", dbPort, dbGroup.Name)

				dbPolicy = newPolicy("db-policy", tier1, 50, dbGroup.Name)
				addIngressRule(dbPolicy, "TCP", dbPort, dbGroup.Name, serverGroup.Name)
				addEngressRule(dbPolicy, "TCP", dbPort, dbGroup.Name)

				Expect(e2eEnv.SetupObjects(nginxPolicy, serverPolicy, dbPolicy)).Should(Succeed())
			})

			AfterEach(func() {
				Expect(e2eEnv.CleanObjects(nginxPolicy, serverPolicy, dbPolicy)).Should(Succeed())
			})

			It("should allow normal packets and limits illegal packets", func() {
				assertReachable([]*framework.VM{nginx}, []*framework.VM{db01, db02}, "TCP", false)
				assertReachable([]*framework.VM{client}, []*framework.VM{server01, server02, db01, db02}, "TCP", false)

				assertReachable([]*framework.VM{client}, []*framework.VM{nginx}, "TCP", true)
				assertReachable([]*framework.VM{nginx}, []*framework.VM{server01, server02}, "TCP", true)
				assertReachable([]*framework.VM{server01, server02, db01, db02}, []*framework.VM{db01, db02}, "TCP", true)
			})

			When("add virtual machine into the database group", func() {
				var db03 *framework.VM

				BeforeEach(func() {
					db03 = &framework.VM{Name: "db03", TCPPort: 3306, Labels: "component=database"}
					Expect(e2eEnv.SetupVMs(db03)).Should(Succeed())
				})

				AfterEach(func() {
					Expect(e2eEnv.CleanVMs(db03)).Should(Succeed())
				})

				It("should allow normal packets and limits illegal packets for new member", func() {
					assertReachable([]*framework.VM{nginx, client}, []*framework.VM{db03}, "TCP", false)
					assertReachable([]*framework.VM{server01, server02, db01, db02}, []*framework.VM{db03}, "TCP", true)
				})
			})

			When("update virtual machine ip address in the nginx group", func() {
				BeforeEach(func() {
					Expect(e2eEnv.UpdateVMRandIP(nginx)).Should(Succeed())
				})

				It("should allow normal packets and limits illegal packets for update member", func() {
					assertReachable([]*framework.VM{nginx}, []*framework.VM{db01, db02}, "TCP", false)
					assertReachable([]*framework.VM{nginx}, []*framework.VM{server01, server02}, "TCP", true)
				})
			})

			When("remove virtual machine from the webserver group", func() {
				BeforeEach(func() {
					Eventually(func() error {
						server02.Labels = ""
						return e2eEnv.UpdateVMLabels(server02)
					}, e2eEnv.Timeout(), e2eEnv.Interval()).Should(Succeed())
				})

				It("should limits illegal packets for remove member", func() {
					assertReachable([]*framework.VM{server02}, []*framework.VM{server01, db01, db02}, "TCP", false)
				})
			})
		})

		When("limits icmp packets between components", func() {
			var icmpAllowPolicy, icmpDropPolicy *securityv1alpha1.SecurityPolicy

			BeforeEach(func() {
				icmpDropPolicy = newPolicy("icmp-drop-policy", tier1, 50, serverGroup.Name, dbGroup.Name)
				icmpAllowPolicy = newPolicy("icmp-allow-policy", tier1, 50, nginxGroup.Name)
				addIngressRule(icmpAllowPolicy, "ICMP", 0) // allow all icmp packets

				Expect(e2eEnv.SetupObjects(icmpAllowPolicy, icmpDropPolicy)).Should(Succeed())
			})

			AfterEach(func() {
				Expect(e2eEnv.CleanObjects(icmpAllowPolicy, icmpDropPolicy)).Should(Succeed())
			})

			It("should allow normal packets and limits illegal packets", func() {
				assertReachable([]*framework.VM{client}, []*framework.VM{server01, server02, db01, db02}, "ICMP", false)
				assertReachable([]*framework.VM{client}, []*framework.VM{nginx}, "ICMP", true)
			})
		})

		// todo: isolate virtual machine
		XWhen("isolate virtual machine with viruses", func() {})
	})

	// This case test policy with udp and ipblocks can works. We setup two peers ntp server and client in different cidr,
	// create and verify policy allow connect with ntp in its cidr.
	//
	//  |----------------|         |--------------- |    |---------------- |         |--------------- |
	//  | "10.0.0.0/28"  |  <--->  | ntp-production |    | ntp-development |  <--->  | "10.0.0.16/28" |
	//  | ---------------|         |--------------- |    |---------------- |         |--------------- |
	//
	Context("environment with virtual machines provide internal udp service [Feature:UDP] [Feature:IPBlocks]", func() {
		var ntp01, ntp02, client01, client02 *framework.VM
		var ntpProduction, ntpDevelopment *groupv1alpha1.EndpointGroup

		var ntpPort int
		var productionCidr, developmentCidr string

		BeforeEach(func() {
			ntpPort = 123
			productionCidr = "10.0.0.0/28"
			developmentCidr = "10.0.0.16/28"

			client01 = &framework.VM{Name: "ntp-client01", ExpectCidr: productionCidr}
			client02 = &framework.VM{Name: "ntp-client02", ExpectCidr: developmentCidr}
			ntp01 = &framework.VM{Name: "ntp01-server", ExpectCidr: productionCidr, UDPPort: ntpPort, Labels: "component=ntp,env=production"}
			ntp02 = &framework.VM{Name: "ntp02-server", ExpectCidr: developmentCidr, UDPPort: ntpPort, Labels: "component=ntp,env=development"}

			ntpProduction = newGroup("ntp-production", "component=ntp,env=production")
			ntpDevelopment = newGroup("ntp-development", "component=ntp,env=development")

			Expect(e2eEnv.SetupVMs(ntp01, ntp02, client01, client02)).Should(Succeed())
			Expect(e2eEnv.SetupObjects(ntpProduction, ntpDevelopment)).Should(Succeed())
		})

		AfterEach(func() {
			Expect(e2eEnv.CleanVMs(ntp01, ntp02, client01, client02)).Should(Succeed())
			Expect(e2eEnv.CleanObjects(ntpProduction, ntpDevelopment)).Should(Succeed())
		})

		When("limits udp packets by ipBlocks between server and client", func() {
			var ntpProductionPolicy, ntpDevelopmentPolicy *securityv1alpha1.SecurityPolicy

			BeforeEach(func() {
				ntpProductionPolicy = newPolicy("ntp-production-policy", tier1, 50, ntpProduction.Name)
				addIngressRule(ntpProductionPolicy, "UDP", ntpPort, productionCidr)

				ntpDevelopmentPolicy = newPolicy("ntp-development-policy", tier1, 50, ntpDevelopment.Name)
				addIngressRule(ntpDevelopmentPolicy, "UDP", ntpPort, developmentCidr)

				Expect(e2eEnv.SetupObjects(ntpProductionPolicy, ntpDevelopmentPolicy)).Should(Succeed())
			})

			AfterEach(func() {
				Expect(e2eEnv.CleanObjects(ntpProductionPolicy, ntpDevelopmentPolicy)).Should(Succeed())
			})

			It("should allow normal packets and limits illegal packets", func() {
				By("verify policy limits illegal packets")
				assertReachable([]*framework.VM{client01}, []*framework.VM{ntp02}, "UDP", false)
				assertReachable([]*framework.VM{client02}, []*framework.VM{ntp01}, "UDP", false)

				By("verify reachable between servers")
				assertReachable([]*framework.VM{ntp01}, []*framework.VM{ntp02}, "UDP", false)
				assertReachable([]*framework.VM{ntp02}, []*framework.VM{ntp01}, "UDP", false)

				By("verify reachable between server and client")
				assertReachable([]*framework.VM{client01}, []*framework.VM{ntp01}, "UDP", true)
				assertReachable([]*framework.VM{client02}, []*framework.VM{ntp02}, "UDP", true)
			})
		})
	})
})

func newGroup(name string, labels string) *groupv1alpha1.EndpointGroup {
	group := &groupv1alpha1.EndpointGroup{}
	group.Name = name
	selector := framework.AsMapLables(labels)

	group.Spec.Selector = &metav1.LabelSelector{
		MatchLabels: selector,
	}

	return group
}

func newPolicy(name, tier string, priority int32, appliedGroup ...string) *securityv1alpha1.SecurityPolicy {
	policy := &securityv1alpha1.SecurityPolicy{}
	policy.Name = name

	policy.Spec = securityv1alpha1.SecurityPolicySpec{
		Tier:                    tier,
		Priority:                priority,
		AppliedToEndpointGroups: appliedGroup,
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

func assertReachable(sources []*framework.VM, destinations []*framework.VM, protocol string, expectReach bool) {
	Eventually(func() error {
		var errList []error

		for _, src := range sources {
			for _, dst := range destinations {
				reach, err := e2eEnv.Reachable(src, dst, protocol)
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
