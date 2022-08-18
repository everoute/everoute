package cmd

import (
	"bytes"
	"encoding/json"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/everoute/everoute/pkg/apis/rule/v1alpha1"
)

var _ = Describe("Show", func() {
	rules := make([]v1alpha1.RuleEntry, 2)
	BeforeEach(func() {
		rules[0].EveroutePolicyRule = &v1alpha1.PolicyRule{
			SrcPort:    6,
			SrcIPAddr:  "10.0.0.4",
			IPProtocol: 1,
		}
		rules[0].Tier = 2
		rules[1].EveroutePolicyRule = &v1alpha1.PolicyRule{
			SrcPort:   7,
			DstIPAddr: "10.0.0.4",
			DstPort:   433,
		}
		rules[1].Tier = 3
		rulebytes, _ := json.MarshalIndent(&rules, "", "\t")
		nextInput = bytes.NewBuffer(rulebytes)
	})
	It("only show tier", func() {
		showIntersection = []string{"tier", "EveroutePolicyRule.SrcPort"}
		err := showCmd.RunE(showCmd, []string{})
		Expect(err).Should(Succeed())
		Expect(nextInput.String()).To(Equal(`[
	{
		"everoutepolicyrule": {
			"srcport": 6
		},
		"tier": 2
	},
	{
		"everoutepolicyrule": {
			"srcport": 7
		},
		"tier": 3
	}
]
`))
		showIntersection = []string{}
		showDifference = []string{"everoutepolicyrule"}
		err = showCmd.RunE(showCmd, []string{})
		Expect(err).Should(Succeed())
		Expect(nextInput.String()).To(Equal(`[
	{
		"tier": 2
	},
	{
		"tier": 3
	}
]
`))
	})
})
