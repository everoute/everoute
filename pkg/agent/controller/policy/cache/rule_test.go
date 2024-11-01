package cache

import (
	"fmt"
	"testing"

	"github.com/agiledragon/gomonkey/v2"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	securityv1alpha1 "github.com/everoute/everoute/pkg/apis/security/v1alpha1"
	"github.com/everoute/everoute/pkg/constants"
)

func TestResolveDstPort(t *testing.T) {
	tests := []struct {
		name       string
		port       RulePort
		namedPorts []securityv1alpha1.NamedPort
		expect     []RulePort
	}{
		{
			name: "the DstPortName is empty",
			port: RulePort{},
			namedPorts: []securityv1alpha1.NamedPort{
				{
					Name:     "ssh",
					Protocol: securityv1alpha1.ProtocolTCP,
					Port:     77,
				},
			},
			expect: make([]RulePort, 0),
		}, {
			name: "the DstPortName has one mapped port in namedPorts",
			port: RulePort{
				DstPortName: "ssh",
				Protocol:    securityv1alpha1.ProtocolUDP,
			},
			namedPorts: []securityv1alpha1.NamedPort{
				{
					Name:     "ssh",
					Protocol: securityv1alpha1.ProtocolUDP,
					Port:     77,
				}, {
					Name:     "http",
					Protocol: securityv1alpha1.ProtocolUDP,
					Port:     8080,
				},
			},
			expect: []RulePort{
				{
					DstPort:     77,
					DstPortMask: 0xffff,
					Protocol:    securityv1alpha1.ProtocolUDP,
				},
			},
		}, {
			name: "the DstPortName has multiply mapped port in namedPorts",
			port: RulePort{
				DstPortName: "ssh",
				Protocol:    securityv1alpha1.ProtocolTCP,
			},
			namedPorts: []securityv1alpha1.NamedPort{
				{
					Name:     "ssh",
					Protocol: securityv1alpha1.ProtocolTCP,
					Port:     77,
				}, {
					Name:     "ssh",
					Protocol: securityv1alpha1.ProtocolTCP,
					Port:     22,
				},
			},
			expect: []RulePort{
				{
					DstPort:     77,
					DstPortMask: 0xffff,
					Protocol:    securityv1alpha1.ProtocolTCP,
				}, {
					DstPort:     22,
					DstPortMask: 0xffff,
					Protocol:    securityv1alpha1.ProtocolTCP,
				},
			},
		}, {
			name: "the DstPortName has no mapped port for matched protocol failed",
			port: RulePort{
				DstPortName: "ssh",
				Protocol:    securityv1alpha1.ProtocolUDP,
			},
			namedPorts: []securityv1alpha1.NamedPort{
				{
					Name:     "ssh",
					Protocol: securityv1alpha1.ProtocolTCP,
					Port:     77,
				}, {
					Name:     "ssh",
					Protocol: securityv1alpha1.ProtocolTCP,
					Port:     22,
				},
			},
			expect: make([]RulePort, 0),
		}, {
			name: "the DstPortName has no mapped port for matched name failed",
			port: RulePort{
				DstPortName: "http",
				Protocol:    securityv1alpha1.ProtocolTCP,
			},
			namedPorts: []securityv1alpha1.NamedPort{
				{
					Name:     "ssh",
					Protocol: securityv1alpha1.ProtocolTCP,
					Port:     77,
				}, {
					Name:     "ssh",
					Protocol: securityv1alpha1.ProtocolTCP,
					Port:     22,
				},
			},
			expect: make([]RulePort, 0),
		}, {
			name: "param namedPorts is empty",
			port: RulePort{
				DstPortName: "http",
				Protocol:    securityv1alpha1.ProtocolTCP,
			},
			namedPorts: nil,
			expect:     make([]RulePort, 0),
		},
	}
	for _, item := range tests {
		res := resolveDstPort(item.port, item.namedPorts)
		if len(res) != len(item.expect) {
			t.Errorf("test %s failed, expect is %#v, but the res is %#v", item.name, item.expect, res)
		}
		for i, export := range item.expect {
			if export != res[i] {
				t.Errorf("test %s failed, expect is %#v, but the res is %#v", item.name, item.expect, res)
			}
		}
	}
}

func TestAppendIPBlockPorts(t *testing.T) {
	tests := []struct {
		name   string
		dst    []securityv1alpha1.NamedPort
		src    []securityv1alpha1.NamedPort
		expect []securityv1alpha1.NamedPort
	}{
		{
			name: "src is empty",
			dst: []securityv1alpha1.NamedPort{
				{
					Name:     "ssh",
					Protocol: securityv1alpha1.ProtocolTCP,
					Port:     78,
				},
			},
			src: []securityv1alpha1.NamedPort{},
			expect: []securityv1alpha1.NamedPort{
				{
					Name:     "ssh",
					Protocol: securityv1alpha1.ProtocolTCP,
					Port:     78,
				},
			},
		}, {
			name:   "dst is empty",
			dst:    []securityv1alpha1.NamedPort{},
			src:    []securityv1alpha1.NamedPort{},
			expect: make([]securityv1alpha1.NamedPort, 0),
		}, {
			name: "src is overlay with dst",
			dst: []securityv1alpha1.NamedPort{
				{
					Name:     "ssh",
					Protocol: securityv1alpha1.ProtocolTCP,
					Port:     78,
				}, {
					Name:     "http",
					Protocol: securityv1alpha1.ProtocolTCP,
					Port:     8080,
				}, {
					Name:     "service",
					Protocol: securityv1alpha1.ProtocolUDP,
					Port:     91,
				},
			},
			src: []securityv1alpha1.NamedPort{
				{
					Name:     "ssh",
					Protocol: securityv1alpha1.ProtocolTCP,
					Port:     22,
				}, {
					Name:     "http",
					Protocol: securityv1alpha1.ProtocolTCP,
					Port:     8080,
				}, {
					Name:     "service",
					Protocol: securityv1alpha1.ProtocolTCP,
					Port:     91,
				}, {
					Name:     "service2",
					Protocol: securityv1alpha1.ProtocolUDP,
					Port:     91,
				},
			},
			expect: []securityv1alpha1.NamedPort{
				{
					Name:     "ssh",
					Protocol: securityv1alpha1.ProtocolTCP,
					Port:     22,
				}, {
					Name:     "http",
					Protocol: securityv1alpha1.ProtocolTCP,
					Port:     8080,
				}, {
					Name:     "service",
					Protocol: securityv1alpha1.ProtocolTCP,
					Port:     91,
				}, {
					Name:     "service2",
					Protocol: securityv1alpha1.ProtocolUDP,
					Port:     91,
				}, {
					Name:     "ssh",
					Protocol: securityv1alpha1.ProtocolTCP,
					Port:     78,
				}, {
					Name:     "service",
					Protocol: securityv1alpha1.ProtocolUDP,
					Port:     91,
				},
			},
		},
	}
	for _, item := range tests {
		res := AppendIPBlockPorts(item.dst, item.src)
		if len(res) != len(item.expect) {
			t.Errorf("test %s failed, the expect is %#v, but the res is %#v", item.name, item.expect, res)
		}
		for i := range item.expect {
			find := false
			for j := range res {
				if item.expect[i] == res[j] {
					find = true
				}
			}
			if find == false {
				t.Errorf("test %s failed, the expect is %#v, but the res is %#v", item.name, item.expect, res)
			}
		}
	}
}

func TestPolicyRuleIsBlock(t *testing.T) {
	cases := []struct {
		name string
		arg  PolicyRule
		exp  bool
	}{
		{
			name: "block rule",
			arg: PolicyRule{
				Action:     RuleActionDrop,
				Tier:       constants.Tier2,
				IPProtocol: string(securityv1alpha1.ProtocolICMP),
				RuleType:   RuleTypeNormalRule,
			},
			exp: true,
		},
		{
			name: "other tier",
			arg: PolicyRule{
				Action:     RuleActionDrop,
				Tier:       constants.Tier1,
				IPProtocol: string(securityv1alpha1.ProtocolTCP),
				RuleType:   RuleTypeNormalRule,
			},
			exp: false,
		},
		{
			name: "default drop",
			arg: PolicyRule{
				Action:   RuleActionDrop,
				Tier:     constants.Tier2,
				RuleType: RuleTypeDefaultRule,
			},
			exp: false,
		},
		{
			name: "global default rule",
			arg: PolicyRule{
				Action:   RuleActionDrop,
				Tier:     constants.Tier2,
				RuleType: RuleTypeGlobalDefaultRule,
			},
			exp: false,
		},
		{
			name: "allow rule",
			arg: PolicyRule{
				Action:   RuleActionAllow,
				Tier:     constants.Tier2,
				RuleType: RuleTypeNormalRule,
			},
			exp: false,
		},
	}

	for i := range cases {
		res := cases[i].arg.IsBlock()
		if res != cases[i].exp {
			t.Errorf("test %s failed, exp is %v, real is %v", cases[i].name, cases[i].exp, res)
		}
	}
}

func TestRuleReverseForTCP(t *testing.T) {
	cases := []struct {
		name string
		rule PolicyRule
		exp  *PolicyRule
	}{
		{
			name: "without port",
			rule: PolicyRule{
				Name:            "default/test/normal/ingress.ingress1",
				Action:          RuleActionDrop,
				PriorityOffset:  30,
				RuleType:        RuleTypeNormalRule,
				Direction:       RuleDirectionIn,
				Tier:            constants.Tier2,
				EnforcementMode: "work",
				IPProtocol:      string(securityv1alpha1.ProtocolTCP),
				SrcIPAddr:       "192.168.1.1/31",
				DstIPAddr:       "0.0.0.0/32",
			},
			exp: &PolicyRule{
				Name:            "default/test/normal/ingress.ingress1.rev-ycpj5nwmp19cvivz0kxwbjkvulr395so",
				Action:          RuleActionDrop,
				PriorityOffset:  30,
				RuleType:        RuleTypeNormalRule,
				Direction:       RuleDirectionOut,
				Tier:            constants.Tier2,
				EnforcementMode: "work",
				IPProtocol:      string(securityv1alpha1.ProtocolTCP),
				DstIPAddr:       "192.168.1.1/31",
				SrcIPAddr:       "0.0.0.0/32",
			},
		},
		{
			name: "with dst port",
			rule: PolicyRule{
				Name:            "default/test/normal/egress.egress1",
				Action:          RuleActionDrop,
				PriorityOffset:  30,
				RuleType:        RuleTypeNormalRule,
				Direction:       RuleDirectionOut,
				Tier:            constants.Tier2,
				EnforcementMode: "monitor",
				IPProtocol:      string(securityv1alpha1.ProtocolTCP),
				SrcIPAddr:       "192.168.1.1/31",
				DstPort:         0xe,
				DstPortMask:     0xfffe,
			},
			exp: &PolicyRule{
				Name:            "default/test/normal/egress.egress1.rev-46mz6ug658rilqvqfrnvaftj3xbfm4wg",
				Action:          RuleActionDrop,
				PriorityOffset:  30,
				RuleType:        RuleTypeNormalRule,
				Direction:       RuleDirectionIn,
				Tier:            constants.Tier2,
				EnforcementMode: "monitor",
				IPProtocol:      string(securityv1alpha1.ProtocolTCP),
				DstIPAddr:       "192.168.1.1/31",
				SrcPort:         0xe,
				SrcPortMask:     0xfffe,
			},
		},
		{
			name: "with udp protocol",
			rule: PolicyRule{
				Name:            "default/test/normal/egress.egress1",
				Action:          RuleActionDrop,
				PriorityOffset:  30,
				RuleType:        RuleTypeNormalRule,
				Direction:       RuleDirectionOut,
				Tier:            constants.Tier2,
				EnforcementMode: "monitor",
				IPProtocol:      string(securityv1alpha1.ProtocolUDP),
				SrcIPAddr:       "192.168.1.1/31",
				DstIPAddr:       "0.0.0.0/32",
				DstPort:         0xe,
				DstPortMask:     0xfffe,
			},
			exp: nil,
		},
		{
			name: "without Protocol",
			rule: PolicyRule{
				Name:            "default/test/normal/egress.egress1",
				Action:          RuleActionDrop,
				PriorityOffset:  30,
				RuleType:        RuleTypeNormalRule,
				Direction:       RuleDirectionOut,
				Tier:            constants.Tier2,
				EnforcementMode: "work",
				SrcIPAddr:       "192.168.1.1/31",
				DstIPAddr:       "0.0.0.0/32",
				DstPort:         0xe,
				DstPortMask:     0xfffe,
			},
			exp: &PolicyRule{
				Name:            "default/test/normal/egress.egress1.rev-5oxwoabwts7k9a6qsw1evzkacpqmu36h",
				Action:          RuleActionDrop,
				PriorityOffset:  30,
				RuleType:        RuleTypeNormalRule,
				Direction:       RuleDirectionIn,
				Tier:            constants.Tier2,
				EnforcementMode: "work",
				IPProtocol:      string(securityv1alpha1.ProtocolTCP),
				DstIPAddr:       "192.168.1.1/31",
				SrcIPAddr:       "0.0.0.0/32",
				SrcPort:         0xe,
				SrcPortMask:     0xfffe,
			},
		},
	}

	for i := range cases {
		cases[i].rule.Name = fmt.Sprintf("%s-%s", cases[i].rule.Name, GenerateFlowKey(cases[i].rule))
		res := cases[i].rule.ReverseForTCP()
		if cases[i].exp == nil && res == nil {
			continue
		}
		if cases[i].exp == nil || res == nil {
			t.Errorf("test %s failed, exp is %v, real is %v", cases[i].name, cases[i].exp, res)
			continue
		}
		if *res != *cases[i].exp {
			t.Errorf("test %s failed, exp is %v, real is %v", cases[i].name, cases[i].exp, *res)
		}
	}
}

func TestRule(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "rule-test")
}

var _ = Describe("rule unit-test", func() {
	Context("getReverseRuleName", func() {
		It("rulename with symmetric", func() {
			srcName := "tower-space/tower.sp-clyzox2msqqcj0858pivnseku/normal/egress.egress1.0-au61wlhu50q00fi2mwfk2ctig31y9go4"
			srcFlowKey := "au61wlhu50q00fi2mwfk2ctig31y9go4"
			flowKey := "new1wlhu50q00fi2mwfk2ctig31y9go4"
			exp := "tower-space/tower.sp-clyzox2msqqcj0858pivnseku/normal/egress.egress1.0.rev-new1wlhu50q00fi2mwfk2ctig31y9go4"
			res := getReverseRuleName(srcName, srcFlowKey, flowKey)
			Expect(res).Should(Equal(exp))
		})
		It("rulename without symmetric", func() {
			srcName := "tower-space/tower.sp-clyzox2msqqcj0858pivnseku/normal/egress.egress1-au61wlhu50q00fi2mwfk2ctig31y9go4"
			srcFlowKey := "au61wlhu50q00fi2mwfk2ctig31y9go4"
			flowKey := "new1wlhu50q00fi2mwfk2ctig31y9go4"
			exp := "tower-space/tower.sp-clyzox2msqqcj0858pivnseku/normal/egress.egress1.rev-new1wlhu50q00fi2mwfk2ctig31y9go4"
			res := getReverseRuleName(srcName, srcFlowKey, flowKey)
			Expect(res).Should(Equal(exp))
		})
	})

	Context("ReverseForBlock", func() {
		pRule := PolicyRule{
			Name:            "policy1-ruleid1",
			PriorityOffset:  203,
			Tier:            "tier2",
			Action:          RuleActionDrop,
			Direction:       RuleDirectionIn,
			RuleType:        RuleTypeNormalRule,
			EnforcementMode: "work",
			IPProtocol:      "ICMP",
			SrcIPAddr:       "12.12.12.12/32",
			DstIPAddr:       "13.13.13.0/24",
		}
		expRuleTmp := PolicyRule{
			Name:            "policy1re-ruleblock",
			PriorityOffset:  203,
			Tier:            "tier2",
			Action:          RuleActionDrop,
			Direction:       RuleDirectionOut,
			RuleType:        RuleTypeNormalRule,
			EnforcementMode: "work",
			IPProtocol:      "ICMP",
			SrcIPAddr:       "13.13.13.0/24",
			DstIPAddr:       "12.12.12.12/32",
		}
		It("rule is allowlist", func() {
			oriRule := pRule.DeepCopy()
			oriRule.Action = RuleActionAllow
			res := oriRule.ReverseForBlock()
			Expect(res).Should(HaveLen(0))
		})
		It("rule is allowlist default drop", func() {
			oriRule := pRule.DeepCopy()
			oriRule.RuleType = RuleTypeDefaultRule
			res := oriRule.ReverseForBlock()
			Expect(res).Should(HaveLen(0))
		})
		It("rule is tier1 drop", func() {
			oriRule := pRule.DeepCopy()
			oriRule.Tier = "tier1"
			res := oriRule.ReverseForBlock()
			Expect(res).Should(HaveLen(0))
		})

		When("rule is blocklist", func() {
			It("protocol is icmp", func() {
				p1 := gomonkey.ApplyFuncSeq(getReverseRuleName, []gomonkey.OutputCell{
					{Times: 3, Values: gomonkey.Params{"policy1re-ruleblock"}},
				})
				defer p1.Reset()
				oriRule := pRule.DeepCopy()
				res := oriRule.ReverseForBlock()
				Expect(res).Should(HaveLen(3))
				expRule1 := expRuleTmp.DeepCopy()
				expRule1.DstPortMask = 0xffff
				expRule1.DstPort = 8
				Expect(res).Should(ContainElement(expRule1))
				expRule2 := expRule1.DeepCopy()
				expRule2.DstPort = 13
				Expect(res).Should(ContainElement(expRule2))
				expRule3 := expRule1.DeepCopy()
				expRule3.DstPort = 15
				Expect(res).Should(ContainElement(expRule3))
			})
			It("protocol is tcp", func() {
				oriRule := pRule.DeepCopy()
				oriRule.IPProtocol = "TCP"
				oriRule.DstPort = 32
				oriRule.DstPortMask = 0xffff
				p1 := gomonkey.ApplyFuncSeq(getReverseRuleName, []gomonkey.OutputCell{
					{Times: 1, Values: gomonkey.Params{"policy1re-ruleblock"}},
				})
				defer p1.Reset()
				res := oriRule.ReverseForBlock()
				Expect(res).Should(HaveLen(1))
				expRule1 := expRuleTmp.DeepCopy()
				expRule1.SrcPortMask = 0xffff
				expRule1.SrcPort = 32
				expRule1.IPProtocol = "TCP"
				Expect(res).Should(ContainElement(expRule1))
			})
			It("protocol is udp", func() {
				oriRule := pRule.DeepCopy()
				oriRule.IPProtocol = "UDP"
				oriRule.DstPort = 32
				oriRule.DstPortMask = 0xffff
				res := oriRule.ReverseForBlock()
				Expect(res).Should(HaveLen(0))
			})
			It("protocol is empty", func() {
				oriRule := pRule.DeepCopy()
				oriRule.IPProtocol = ""
				p1 := gomonkey.ApplyFuncSeq(getReverseRuleName, []gomonkey.OutputCell{
					{Times: 4, Values: gomonkey.Params{"policy1re-ruleblock"}},
				})
				defer p1.Reset()
				res := oriRule.ReverseForBlock()
				Expect(res).Should(HaveLen(4))
				expRule1 := expRuleTmp.DeepCopy()
				expRule1.IPProtocol = "TCP"
				Expect(res).Should(ContainElement(expRule1))
				expRule4 := expRuleTmp.DeepCopy()
				expRule4.DstPortMask = 0xffff
				expRule4.DstPort = 8
				Expect(res).Should(ContainElement(expRule4))
				expRule2 := expRuleTmp.DeepCopy()
				expRule2.DstPortMask = 0xffff
				expRule2.DstPort = 13
				Expect(res).Should(ContainElement(expRule2))
				expRule3 := expRuleTmp.DeepCopy()
				expRule3.DstPortMask = 0xffff
				expRule3.DstPort = 15
				Expect(res).Should(ContainElement(expRule3))

			})
		})
	})
})
