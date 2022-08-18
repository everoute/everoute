package cmd

import (
	"github.com/agiledragon/gomonkey/v2"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/everoute/everoute/pkg/apis/rpc/v1alpha1"
	"github.com/everoute/everoute/pkg/erctl"
)

var _ = Describe("Rule", func() {
	gomonkey.ApplyFunc(erctl.ConnectRule, func(bool) error {
		return nil
	})
	gomonkey.ApplyFunc(erctl.GetAllRules, func() ([]*erctl.Rule, error) {
		r1 := &v1alpha1.RuleEntry{
			EveroutePolicyRule: &v1alpha1.PolicyRule{
				DstIPAddr: "10.0.0.3",
				DstPort:   433,
			},
		}
		r2 := &v1alpha1.RuleEntry{
			EveroutePolicyRule: &v1alpha1.PolicyRule{
				DstIPAddr: "10.0.0.3",
				DstPort:   434,
			},
		}
		r3 := &v1alpha1.RuleEntry{
			EveroutePolicyRule: &v1alpha1.PolicyRule{
				SrcIPAddr: "10.0.0.3",
				DstPort:   433,
			},
		}
		rules := []*erctl.Rule{{RuleEntry: r1, Count: 1},
			{RuleEntry: r2, Count: 2}, {RuleEntry: r3, Count: 3}}
		return rules, nil
	})
	It("rule --dstport 434", func() {
		dstPort = "434"
		err := ruleCmd.RunE(ruleCmd, []string{})
		Expect(err).Should(Succeed())
	})
})
