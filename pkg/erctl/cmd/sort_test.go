package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/everoute/everoute/pkg/apis/rpc/v1alpha1"
)

var _ = Describe("Sort", func() {
	rules := make([]v1alpha1.RuleEntry, 4)
	BeforeEach(func() {
		rules[0].EveroutePolicyRule = &v1alpha1.PolicyRule{
			SrcIPAddr: "192.168.0.1/32",
		}
		rules[1].EveroutePolicyRule = &v1alpha1.PolicyRule{
			DstPort: 8080,
		}
		rules[2].EveroutePolicyRule = &v1alpha1.PolicyRule{
			IPProtocol: 2,
		}
		rules[3].EveroutePolicyRule = &v1alpha1.PolicyRule{
			DstIPAddr: "10.0.0.0/10",
			DstPort:   433,
		}
		rulebytes, _ := json.MarshalIndent(&rules, "", "\t")
		nextInput = bytes.NewBuffer(rulebytes)
	})
	It("sort rules", func() {
		sortIntersection = []string{"EveroutePolicyRule.DstIPAddr=10.0.0.4", "EveroutePolicyRule.DstPort=433"}
		err := sortCmd.RunE(sortCmd, []string{})
		Expect(err).Should(Succeed())
		fmt.Println(nextInput)
	})
})
