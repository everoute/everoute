package cache

import (
	"context"
	"os"
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"golang.org/x/sys/unix"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"

	groupv1alpha1 "github.com/everoute/everoute/pkg/apis/group/v1alpha1"
	securityv1alpha1 "github.com/everoute/everoute/pkg/apis/security/v1alpha1"
	"github.com/everoute/everoute/pkg/constants"
	"github.com/everoute/everoute/pkg/types"
	"github.com/everoute/everoute/pkg/utils"
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

func TestCompleteRuleHasLocalRule(t *testing.T) {
	if err := os.Setenv(constants.AgentNodeNameENV, "rule-cache-ut"); err != nil {
		t.Fatalf("Setenv() error = %v", err)
	}
	utils.InitCurrentAgentName()

	rule := &CompleteRule{}
	currentAgent := utils.CurrentAgentName()
	otherAgent := currentAgent + "-other"
	managedVDSes := sets.New("vds-1")

	tests := []struct {
		name     string
		ipBlock  *IPBlockItem
		expected bool
	}{
		{
			name:     "nil ipBlock should apply to all",
			ipBlock:  nil,
			expected: true,
		},
		{
			name: "current agent should apply",
			ipBlock: &IPBlockItem{
				AgentRef: sets.New(currentAgent),
				VDSRef:   sets.New[string](),
			},
			expected: true,
		},
		{
			name: "agent ref should take precedence over managed vds",
			ipBlock: &IPBlockItem{
				AgentRef: sets.New(otherAgent),
				VDSRef:   sets.New("vds-1"),
			},
			expected: false,
		},
		{
			name: "managed vds should apply when agent ref is empty",
			ipBlock: &IPBlockItem{
				AgentRef: sets.New[string](),
				VDSRef:   sets.New("vds-1"),
			},
			expected: true,
		},
		{
			name: "unmanaged vds should not apply when agent ref is empty",
			ipBlock: &IPBlockItem{
				AgentRef: sets.New[string](),
				VDSRef:   sets.New("vds-2"),
			},
			expected: false,
		},
		{
			name: "empty agent and vds refs should apply to all",
			ipBlock: &IPBlockItem{
				AgentRef: sets.New[string](),
				VDSRef:   sets.New[string](),
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := rule.hasLocalRule(tt.ipBlock, managedVDSes); got != tt.expected {
				t.Fatalf("expect %t, got %t", tt.expected, got)
			}
		})
	}
}

func TestEstimateCompleteRuleMatchesGeneratedRules(t *testing.T) {
	ctx := context.Background()
	groupCache := NewGroupCache()
	group := &groupv1alpha1.GroupMembers{
		ObjectMeta: metav1.ObjectMeta{Name: "dst-group"},
		GroupMembers: []groupv1alpha1.GroupMember{
			{
				IPs: []types.IPAddress{"10.0.0.2", "fe80::2"},
			},
			{
				IPs: []types.IPAddress{"10.0.0.3"},
				Ports: []securityv1alpha1.NamedPort{
					{Name: "web", Protocol: securityv1alpha1.ProtocolTCP, Port: 8080},
					{Name: "web", Protocol: securityv1alpha1.ProtocolUDP, Port: 8081},
				},
			},
		},
	}
	groupCache.UpdateGroupMembership(group)

	rule := &CompleteRule{
		RuleID:          "ns/policy/normal/ingress.rule1",
		Policy:          "ns/policy",
		Tier:            "tier2",
		EnforcementMode: "work",
		Action:          RuleActionAllow,
		Direction:       RuleDirectionIn,
		SrcIPs:          sets.New[string](""),
		DstGroups:       sets.New[string](group.Name),
		Ports: []RulePort{
			{Protocol: securityv1alpha1.ProtocolTCP, DstPort: 80, DstPortMask: 0xffff},
			{Protocol: securityv1alpha1.ProtocolTCP, DstPortName: "web"},
		},
	}

	estimate, err := rule.EstimateRuleCount(ctx, groupCache, sets.New[string]())
	if err != nil {
		t.Fatalf("estimate complete rule: %v", err)
	}
	generated := rule.ListRules(ctx, groupCache, sets.New[string]())
	if estimate != uint64(len(generated)) {
		t.Fatalf("expected estimate %d to match generated rule count %d: %#v", estimate, len(generated), generated)
	}
	if len(generated) == 0 {
		t.Fatal("expected generated rules to be non-empty")
	}
	for _, item := range generated {
		if item.IPFamily != unix.AF_INET && item.IPFamily != unix.AF_INET6 {
			t.Fatalf("unexpected generated rule IP family: %d", item.IPFamily)
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
