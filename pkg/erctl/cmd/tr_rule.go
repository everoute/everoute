package cmd

import (
	"bytes"
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/everoute/everoute/pkg/erctl"
)

var (
	TRFlowIDs []int64
	TRRuleIDs []string
)

var trRuleCmd = &cobra.Command{
	Use:   "tr-rule",
	Short: "get tr rule from agent",
	Long: "use grpc to get tr rules, default get all\n" +
		"-f means get tr rule by flowids\n" +
		"-r means get tr rule by ruleids\n",
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
	getCmd.AddCommand(trRuleCmd)
	trRuleCmd.Flags().Int64SliceVarP(&TRFlowIDs, "flow", "f", []int64{}, "specify tr flowIDs")
	trRuleCmd.Flags().StringSliceVarP(&TRRuleIDs, "rule", "r", []string{}, "specify tr rule ns/name")
}
