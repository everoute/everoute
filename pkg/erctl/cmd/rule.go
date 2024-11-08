package cmd

import (
	"bytes"
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/everoute/everoute/pkg/erctl"
)

var (
	srcIP, dstIP, dstPort, protocol string
	showCTflows                     bool
)

var ruleCmd = &cobra.Command{
	Use:   "rule",
	Short: "get RuleEntry from agent",
	Long: "use grpc to get rules, default get all\n" +
		"-f means get rule by flowids\n" +
		"-r means get rule by ruleids\n" +
		"sort rules by --srcip --dstip --dstport --protocol",
	RunE: func(_ *cobra.Command, _ []string) (err error) {
		err = erctl.ConnectRule(showCTflows)
		if err != nil {
			return err
		}

		var rules interface{}
		switch {
		case len(ruleIDs) != 0:
			rules, err = erctl.GetRulesByName(ruleIDs)
		case len(flowIDs) != 0:
			rules, err = erctl.GetRulesByFlow(flowIDs)
		default:
			rules, err = erctl.GetAllRules()
		}
		if err != nil {
			return err
		}

		appendToSort()
		var out io.Writer
		if len(sortIntersection) != 0 {
			nextInput = bytes.NewBuffer([]byte{})
			defer func() {
				err = sortCmd.RunE(sortCmd, []string{})
				if err != nil {
					return
				}
				result := nextInput.String()
				nextInput = nil
				out, err = setOutput()
				if err != nil {
					return
				}
				fmt.Fprintln(out, result)
			}()
		}

		out, err = setOutput()
		if err != nil {
			return err
		}
		err = printz(out, rules)
		return err
	},
}

func init() {
	getCmd.AddCommand(ruleCmd)
	ruleCmd.Flags().Int64SliceVarP(&flowIDs, "flow", "f", []int64{}, "specify flowIDs")
	ruleCmd.Flags().StringVar(&srcIP, "srcip", "", "specify source ip")
	ruleCmd.Flags().StringVar(&dstIP, "dstip", "", "specify destination ip")
	ruleCmd.Flags().StringVar(&dstPort, "dstport", "", "specify destination port")
	ruleCmd.Flags().StringVar(&protocol, "protocol", "", "specify protocol")
	ruleCmd.Flags().BoolVar(&showCTflows, "ctflows", false, "use to show ctflows")
}

func appendToSort() {
	if srcIP != "" {
		sortIntersection = append(sortIntersection, "EveroutePolicyRule.SrcIPAddr="+srcIP)
	}
	if dstIP != "" {
		sortIntersection = append(sortIntersection, "EveroutePolicyRule.DstIPAddr="+dstIP)
	}
	if dstPort != "" {
		sortIntersection = append(sortIntersection, "EveroutePolicyRule.DstPort="+dstPort)
	}
	if protocol != "" {
		sortIntersection = append(sortIntersection, "EveroutePolicyRule.IPProtocol="+protocol)
	}
}
