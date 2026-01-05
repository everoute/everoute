package cmd

import (
	"bytes"
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/everoute/everoute/pkg/constants"
	"github.com/everoute/everoute/pkg/erctl"
)

var (
	srcIP, dstIP, dstPort, protocol string
	showCTflows                     bool
	batchSize                       uint32
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

		var recv erctl.RuleRecv
		switch {
		case len(ruleIDs) != 0:
			recv, err = erctl.GetRulesByName(ruleIDs)
		case len(flowIDs) != 0:
			recv, err = erctl.GetRulesByFlow(flowIDs)
		default:
			recv, err = erctl.GetAllRules(batchSize)
		}
		if err != nil {
			return err
		}
		if recv == nil {
			return fmt.Errorf("no rules received")
		}

		appendToSort()
		for {
			rules, isLast, err := erctl.GetBatchRules(recv)
			if err != nil {
				return err
			}
			if len(rules) != 0 {
				var out io.Writer
				nextInput = nil
				if len(sortIntersection) != 0 {
					nextInput = bytes.NewBuffer([]byte{})
				}
				out, err = setOutput()
				if err != nil {
					return err
				}
				err = printz(out, rules)
				if err != nil {
					return err
				}
				if nextInput != nil {
					err = sortCmd.RunE(sortCmd, []string{})
					if err != nil {
						return err
					}
					result := nextInput.String()
					nextInput = nil
					out, err = setOutput()
					if err != nil {
						return err
					}
					if result != "[]\n" {
						fmt.Fprintln(out, result)
					}

				}
			}
			if isLast {
				return nil
			}
		}
	},
}

func init() {
	getCmd.AddCommand(ruleCmd)
	ruleCmd.Flags().Int64SliceVarP(&flowIDs, "flow", "f", []int64{}, "specify flowIDs")
	ruleCmd.Flags().StringSliceVarP(&ruleIDs, "rule", "r", []string{}, "specify ruleIDs")
	ruleCmd.Flags().StringVar(&srcIP, "srcip", "", "specify source ip")
	ruleCmd.Flags().StringVar(&dstIP, "dstip", "", "specify destination ip")
	ruleCmd.Flags().StringVar(&dstPort, "dstport", "", "specify destination port")
	ruleCmd.Flags().StringVar(&protocol, "protocol", "", "specify protocol")
	ruleCmd.Flags().BoolVar(&showCTflows, "ctflows", false, "use to show ctflows")
	ruleCmd.Flags().Uint32Var(&batchSize, "batchsize", constants.DefaultRPCBatchSize, "specify rpc batch size, only effective when get all rules")
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
