package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/everoute/everoute/pkg/apis/rpc/v1alpha1"
	"github.com/everoute/everoute/pkg/erctl"
)

var flowRoundCmd = &cobra.Command{
	Use:   "flow-round",
	Short: "Manage agent flow round runtime state",
}

var (
	connectFlowRoundClient        = erctl.ConnectClient
	getFlowRoundStatusRPC         = erctl.GetFlowRoundStatus
	skipGlobalPolicyWaitNormalRPC = erctl.SkipGlobalPolicyWaitNormal
	cleanupPreviousRoundRPC       = erctl.CleanupPreviousRound
)

var flowRoundStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Get flow round status from agent",
	Args:  cobra.NoArgs,
	RunE: func(_ *cobra.Command, _ []string) error {
		return printFlowRoundStatusFromAgent()
	},
}

var skipGlobalPolicyWaitNormalCmd = &cobra.Command{
	Use:   "skip-global-policy-wait-normal",
	Short: "Allow GlobalPolicy to proceed without waiting for normal policy in current agent runtime",
	Args:  cobra.NoArgs,
	RunE: func(_ *cobra.Command, _ []string) error {
		if err := connectFlowRoundClient(); err != nil {
			return err
		}
		status, err := skipGlobalPolicyWaitNormalRPC()
		if err != nil {
			return err
		}
		if isSkipResult(status.GetResult()) {
			printFlowRoundSkipped("skip-global-policy-wait-normal", resultReason(status.GetResult()))
			return nil
		}
		fmt.Println("skip global policy wait normal requested")
		printFlowRoundStatus(status)
		return nil
	},
}

var cleanupPreviousRoundCmd = &cobra.Command{
	Use:   "cleanup-previous-round",
	Short: "Trigger previous round cleanup without waiting for startup flow sync or clean delay",
	Args:  cobra.NoArgs,
	RunE: func(_ *cobra.Command, _ []string) error {
		if err := connectFlowRoundClient(); err != nil {
			return err
		}
		status, err := cleanupPreviousRoundRPC()
		if err != nil {
			return err
		}
		if isSkipResult(status.GetResult()) {
			printFlowRoundSkipped("cleanup-previous-round", resultReason(status.GetResult()))
			return nil
		}
		fmt.Println("previous round cleanup requested")
		printFlowRoundStatus(status)
		return nil
	},
}

func printFlowRoundStatusFromAgent() error {
	if err := connectFlowRoundClient(); err != nil {
		return err
	}
	status, err := getFlowRoundStatusRPC()
	if err != nil {
		return err
	}
	if isSkipResult(status.GetResult()) {
		fmt.Println("flow round: unavailable")
		fmt.Printf("reason: %s\n", resultReason(status.GetResult()))
		return nil
	}
	printFlowRoundStatus(status)
	return nil
}

func printFlowRoundSkipped(action, reason string) {
	fmt.Printf("flow round %s: skipped\n", action)
	fmt.Printf("reason: %s\n", reason)
}

func printFlowRoundStatus(status *v1alpha1.FlowRoundStatus) {
	fmt.Printf("normalPolicyDone: %t\n", status.GetNormalPolicyDone())
	fmt.Printf("globalPolicyDone: %t\n", status.GetGlobalPolicyDone())
	fmt.Printf("trafficRedirectDone: %t\n", status.GetTrafficRedirectDone())
	fmt.Printf("globalPolicyWaitNormalSkipped: %t\n", status.GetGlobalPolicyWaitNormalSkipped())
	fmt.Printf("manualCleanupRequested: %t\n", status.GetManualCleanupRequested())

	vdsStatuses := status.GetVDSStatuses()
	if len(vdsStatuses) == 0 {
		return
	}

	fmt.Println("vdsStatuses:")
	for _, vdsStatus := range vdsStatuses {
		fmt.Printf("- vdsID: %s\n", vdsStatus.GetVDSID())
		fmt.Printf("  bridge: %s\n", vdsStatus.GetBridge())
		fmt.Printf("  previousRound: %d\n", vdsStatus.GetPreviousRound())
		fmt.Printf("  currentRound: %d\n", vdsStatus.GetCurrentRound())
		fmt.Printf("  previousDatapathVersion: %s\n", vdsStatus.GetPreviousDatapathVersion())
		fmt.Printf("  currentDatapathVersion: %s\n", vdsStatus.GetCurrentDatapathVersion())
	}
}

func init() {
	flowRoundCmd.AddCommand(flowRoundStatusCmd)
	flowRoundCmd.AddCommand(skipGlobalPolicyWaitNormalCmd)
	flowRoundCmd.AddCommand(cleanupPreviousRoundCmd)
	rootCmd.AddCommand(flowRoundCmd)
}
