package cache

import (
	"fmt"
	"testing"

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
				Name:            "default/test/normal/ingress.ingress1-ycpj5nwmp19cvivz0kxwbjkvulr395so",
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
				Name:            "default/test/normal/egress.egress1-46mz6ug658rilqvqfrnvaftj3xbfm4wg",
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
				Name:            "default/test/normal/egress.egress1-5oxwoabwts7k9a6qsw1evzkacpqmu36h",
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
