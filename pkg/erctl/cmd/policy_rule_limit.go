package cmd

import (
	"fmt"
	"strconv"

	"github.com/spf13/cobra"

	"github.com/everoute/everoute/pkg/erctl"
)

var policyRuleLimitCmd = &cobra.Command{
	Use:   "policy-rule-limit",
	Short: "Manage policy rule estimate limit on agent",
}

var getPolicyRuleLimitCmd = &cobra.Command{
	Use:   "get",
	Short: "Get current policy rule estimate limit from agent",
	Args:  cobra.NoArgs,
	RunE: func(_ *cobra.Command, _ []string) error {
		if err := erctl.ConnectClient(); err != nil {
			return err
		}
		limit, err := erctl.GetPolicyRuleEstimateLimit()
		if err != nil {
			return err
		}
		fmt.Printf("current: %d\n", limit)
		return nil
	},
}

var setPolicyRuleLimitCmd = &cobra.Command{
	Use:   "set [limit]",
	Short: "Set policy rule estimate limit on agent (0 disables the limit)",
	Args:  cobra.ExactArgs(1),
	RunE: func(_ *cobra.Command, args []string) error {
		limit, err := strconv.ParseUint(args[0], 10, 64)
		if err != nil {
			return err
		}
		if err := erctl.ConnectClient(); err != nil {
			return err
		}
		prev, cur, err := erctl.SetPolicyRuleEstimateLimit(limit)
		if err != nil {
			return err
		}
		fmt.Printf("prev: %d, current: %d\n", prev, cur)
		return nil
	},
}

func init() {
	policyRuleLimitCmd.AddCommand(getPolicyRuleLimitCmd)
	policyRuleLimitCmd.AddCommand(setPolicyRuleLimitCmd)
	rootCmd.AddCommand(policyRuleLimitCmd)
}
