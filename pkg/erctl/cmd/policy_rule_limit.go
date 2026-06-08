package cmd

import (
	"fmt"
	"strconv"

	"github.com/spf13/cobra"

	"github.com/everoute/everoute/pkg/erctl"
)

const (
	policyGuardMemory = "memory"
	policyGuardRule   = "rule"
)

var policyGuardCmd = &cobra.Command{
	Use:   "policy-guard",
	Short: "Manage policy admission guards on agent",
}

var policyGuardMemoryCmd = &cobra.Command{
	Use:   "memory",
	Short: "Manage policy memory guard",
}

var policyGuardRuleCmd = &cobra.Command{
	Use:   "rule",
	Short: "Manage policy rule estimate guard",
}

var policyGuardRuleLimitCmd = &cobra.Command{
	Use:   "rule-limit",
	Short: "Manage policy rule estimate limit",
}

var policyGuardMemoryLimitCmd = &cobra.Command{
	Use:   "memory-limit",
	Short: "Manage policy memory guard limit",
}

var setPolicyMemoryLimitCmd = &cobra.Command{
	Use:   "set [limit]",
	Short: "Set policy memory guard limit on agent in bytes (0 disables the limit)",
	Args:  cobra.ExactArgs(1),
	RunE: func(_ *cobra.Command, args []string) error {
		limit, err := strconv.ParseUint(args[0], 10, 64)
		if err != nil {
			return err
		}
		if err := erctl.ConnectClient(); err != nil {
			return err
		}
		prev, cur, err := erctl.SetPolicyMemoryLimit(limit)
		if err != nil {
			return err
		}
		fmt.Printf("prev: %d, current: %d\n", prev, cur)
		return nil
	},
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

func newPolicyGuardEnableCmd(guard string) *cobra.Command {
	return &cobra.Command{
		Use:   "enable",
		Short: fmt.Sprintf("Enable policy %s guard", guard),
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			return setPolicyGuardEnabled(guard, true)
		},
	}
}

func newPolicyGuardDisableCmd(guard string) *cobra.Command {
	return &cobra.Command{
		Use:   "disable",
		Short: fmt.Sprintf("Disable policy %s guard", guard),
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			return setPolicyGuardEnabled(guard, false)
		},
	}
}

func newPolicyGuardStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Get policy guard status",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			return printPolicyGuardStatus()
		},
	}
}

func setPolicyGuardEnabled(guard string, enabled bool) error {
	if err := erctl.ConnectClient(); err != nil {
		return err
	}
	prev, cur, err := erctl.SetPolicyGuardEnabled(guard, enabled)
	if err != nil {
		return err
	}
	fmt.Printf("guard: %s, prev: %t, current: %t\n", guard, prev, cur)
	return nil
}

func printPolicyGuardStatus() error {
	if err := erctl.ConnectClient(); err != nil {
		return err
	}
	status, err := erctl.GetPolicyGuardStatus()
	if err != nil {
		return err
	}
	fmt.Println("memory:")
	fmt.Printf("  enabled: %t\n", status.GetMemoryEnabled())
	fmt.Printf("  breaker-open: %t\n", status.GetMemoryBreakerOpen())
	fmt.Printf("  limit: %d\n", status.GetMemoryLimit())
	fmt.Printf("  open-threshold: %d\n", status.GetMemoryOpenThreshold())
	fmt.Printf("  recover-threshold: %d\n", status.GetMemoryRecoverThreshold())
	fmt.Println("rule:")
	fmt.Printf("  enabled: %t\n", status.GetRuleEnabled())
	fmt.Printf("  rule-limit: %d\n", status.GetRuleEstimateLimit())
	return nil
}

func init() {
	policyGuardMemoryCmd.AddCommand(newPolicyGuardEnableCmd(policyGuardMemory))
	policyGuardMemoryCmd.AddCommand(newPolicyGuardDisableCmd(policyGuardMemory))
	policyGuardRuleCmd.AddCommand(newPolicyGuardEnableCmd(policyGuardRule))
	policyGuardRuleCmd.AddCommand(newPolicyGuardDisableCmd(policyGuardRule))
	policyGuardMemoryLimitCmd.AddCommand(setPolicyMemoryLimitCmd)
	policyGuardRuleLimitCmd.AddCommand(getPolicyRuleLimitCmd)
	policyGuardRuleLimitCmd.AddCommand(setPolicyRuleLimitCmd)
	policyGuardCmd.AddCommand(policyGuardMemoryCmd)
	policyGuardCmd.AddCommand(policyGuardRuleCmd)
	policyGuardCmd.AddCommand(policyGuardMemoryLimitCmd)
	policyGuardCmd.AddCommand(policyGuardRuleLimitCmd)
	policyGuardCmd.AddCommand(newPolicyGuardStatusCmd())
	rootCmd.AddCommand(policyGuardCmd)
}
