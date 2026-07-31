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

var policyGuardMemoryThresholdCmd = &cobra.Command{
	Use:   "memory-threshold",
	Short: "Manage policy memory guard threshold",
}

var (
	connectPolicyGuardClient      = erctl.ConnectClient
	getPolicyGuardStatus          = erctl.GetPolicyGuardStatus
	setPolicyMemoryThresholdRPC   = erctl.SetPolicyMemoryThreshold
	setPolicyRuleEstimateLimitRPC = erctl.SetPolicyRuleEstimateLimit
	setPolicyGuardEnabledRPC      = erctl.SetPolicyGuardEnabled
)

var setPolicyMemoryThresholdCmd = &cobra.Command{
	Use:   "set [threshold]",
	Short: "Set policy memory guard threshold on agent in bytes (0 disables the threshold)",
	Args:  cobra.ExactArgs(1),
	RunE: func(_ *cobra.Command, args []string) error {
		threshold, err := strconv.ParseUint(args[0], 10, 64)
		if err != nil {
			return err
		}
		if err := connectPolicyGuardClient(); err != nil {
			return err
		}
		res, err := setPolicyMemoryThresholdRPC(threshold)
		if err != nil {
			return err
		}
		if isSkipResult(res.GetResult()) {
			printPolicyGuardSkipped(fmt.Sprintf("memory-threshold set %d", threshold), resultReason(res.GetResult()))
			return nil
		}
		fmt.Printf("prev: %d, current: %d\n", res.GetPrevThreshold(), res.GetCurrentThreshold())
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
		if err := connectPolicyGuardClient(); err != nil {
			return err
		}
		res, err := setPolicyRuleEstimateLimitRPC(limit)
		if err != nil {
			return err
		}
		if isSkipResult(res.GetResult()) {
			printPolicyGuardSkipped(fmt.Sprintf("rule-limit set %d", limit), resultReason(res.GetResult()))
			return nil
		}
		fmt.Printf("prev: %d, current: %d\n", res.GetPrevLimit(), res.GetCurrentLimit())
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
	if err := connectPolicyGuardClient(); err != nil {
		return err
	}
	res, err := setPolicyGuardEnabledRPC(guard, enabled)
	if err != nil {
		return err
	}
	if isSkipResult(res.GetResult()) {
		action := "disable"
		if enabled {
			action = "enable"
		}
		printPolicyGuardSkipped(fmt.Sprintf("%s %s", guard, action), resultReason(res.GetResult()))
		return nil
	}
	fmt.Printf("guard: %s, prev: %t, current: %t\n", guard, res.GetPrevEnabled(), res.GetCurrentEnabled())
	return nil
}

func printPolicyGuardStatus() error {
	if err := connectPolicyGuardClient(); err != nil {
		return err
	}
	status, err := getPolicyGuardStatus()
	if err != nil {
		return err
	}
	if isSkipResult(status.GetResult()) {
		fmt.Println("policy guard: unavailable")
		fmt.Printf("reason: %s\n", resultReason(status.GetResult()))
		return nil
	}
	fmt.Println("memory:")
	fmt.Printf("  enabled: %t\n", status.GetMemoryEnabled())
	fmt.Printf("  breaker-open: %t\n", status.GetMemoryBreakerOpen())
	fmt.Printf("  threshold: %d\n", status.GetMemoryThreshold())
	fmt.Println("rule:")
	fmt.Printf("  enabled: %t\n", status.GetRuleEnabled())
	fmt.Printf("  rule-limit: %d\n", status.GetRuleEstimateLimit())
	return nil
}

func printPolicyGuardSkipped(action, reason string) {
	fmt.Printf("policy guard %s: skipped\n", action)
	fmt.Printf("reason: %s\n", reason)
}

func init() {
	policyGuardMemoryCmd.AddCommand(newPolicyGuardEnableCmd(policyGuardMemory))
	policyGuardMemoryCmd.AddCommand(newPolicyGuardDisableCmd(policyGuardMemory))
	policyGuardRuleCmd.AddCommand(newPolicyGuardEnableCmd(policyGuardRule))
	policyGuardRuleCmd.AddCommand(newPolicyGuardDisableCmd(policyGuardRule))
	policyGuardMemoryThresholdCmd.AddCommand(setPolicyMemoryThresholdCmd)
	policyGuardRuleLimitCmd.AddCommand(setPolicyRuleLimitCmd)
	policyGuardCmd.AddCommand(policyGuardMemoryCmd)
	policyGuardCmd.AddCommand(policyGuardRuleCmd)
	policyGuardCmd.AddCommand(policyGuardMemoryThresholdCmd)
	policyGuardCmd.AddCommand(policyGuardRuleLimitCmd)
	policyGuardCmd.AddCommand(newPolicyGuardStatusCmd())
	rootCmd.AddCommand(policyGuardCmd)
}
