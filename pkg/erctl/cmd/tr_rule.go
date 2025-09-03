package cmd

import (
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
		case len(TRRuleIDs) != 0:
			rules, err = erctl.GetTRRulesByKeys(TRRuleIDs)
		case len(TRFlowIDs) != 0:
			rules, err = erctl.GetTRRulesByFlowIDs(TRFlowIDs)
		default:
			return fmt.Errorf("must provide flowids or ruleids")
		}
		if err != nil {
			return err
		}

		var out io.Writer
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
