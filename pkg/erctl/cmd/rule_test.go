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
	gomonkey.ApplyFunc(erctl.GetAllRules, func(uint32) (erctl.RuleRecv, error) {
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
		return &erctl.OnceRecv{
			Rules: &v1alpha1.RuleEntries{
				RuleEntries: []*v1alpha1.RuleEntry{r1, r2, r3},
			},
		}, nil
	})
	It("rule --dstport 434", func() {
		dstPort = "434"
		err := ruleCmd.RunE(ruleCmd, []string{})
		Expect(err).Should(Succeed())
	})
})
