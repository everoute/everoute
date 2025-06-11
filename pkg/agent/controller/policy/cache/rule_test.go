package cache

import (
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"golang.org/x/sys/unix"

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

func TestRule(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "rule-test")
}

var _ = Describe("rule unit-test", func() {
	Context("generateflowkey", func() {
		var pRule, pRuleV6 PolicyRule
		var exp, expV6 string
		BeforeEach(func() {
			pRule = PolicyRule{
				Name:           "",
				Policy:         "",
				Action:         "",
				PriorityOffset: 30,
				Direction:      RuleDirectionIn,
				RuleType:       RuleTypeDefaultRule,
				Tier:           constants.Tier0,
				SrcIPAddr:      "1.1.1.0/24",
				DstIPAddr:      "13.13.13.24",
				SrcPort:        345,
				SrcPortMask:    0xffff,
				IPProtocol:     "ICMP",
				IPFamily:       unix.AF_INET,
				IcmpTypeEnable: true,
			}
			pRuleV6 = PolicyRule{
				Name:           "",
				Policy:         "",
				Action:         "",
				PriorityOffset: 30,
				Direction:      RuleDirectionIn,
				RuleType:       RuleTypeDefaultRule,
				Tier:           constants.Tier0,
				SrcIPAddr:      "fe80::0/16",
				DstIPAddr:      "fe80::dc13:10ff:fe24:8c7f/128",
				SrcPort:        345,
				SrcPortMask:    0xffff,
				IPProtocol:     "ICMP",
				IPFamily:       unix.AF_INET6,
				IcmpTypeEnable: false,
			}
			exp = GenerateFlowKey(pRule)
			expV6 = GenerateFlowKey(pRuleV6)
		})
		It("ignore skip Name field", func() {
			pRule2 := pRule.DeepCopy()
			pRule2.Name = "rule1"
			res2 := GenerateFlowKey(*pRule2)
			Expect(res2).Should(Equal(exp))

			pRule3 := pRuleV6.DeepCopy()
			pRule3.Name = "rule1"
			res3 := GenerateFlowKey(*pRule3)
			Expect(res3).Should(Equal(expV6))
		})
		It("ignore skip action", func() {
			pRule2 := pRule.DeepCopy()
			pRule2.Action = "allow"
			res2 := GenerateFlowKey(*pRule2)
			Expect(res2).Should(Equal(exp))
		})
		It("ignore skip Policy", func() {
			pRule2 := pRule.DeepCopy()
			pRule2.Policy = "ns1/name1"
			res2 := GenerateFlowKey(*pRule2)
			Expect(res2).Should(Equal(exp))
		})
	})
})
