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
		if err := erctl.ConnectClient(); err != nil {
			return err
		}
		status, err := erctl.SkipGlobalPolicyWaitNormal()
		if err != nil {
			return err
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
		if err := erctl.ConnectClient(); err != nil {
			return err
		}
		status, err := erctl.CleanupPreviousRound()
		if err != nil {
			return err
		}
		fmt.Println("previous round cleanup requested")
		printFlowRoundStatus(status)
		return nil
	},
}

func printFlowRoundStatusFromAgent() error {
	if err := erctl.ConnectClient(); err != nil {
		return err
	}
	status, err := erctl.GetFlowRoundStatus()
	if err != nil {
		return err
	}
	printFlowRoundStatus(status)
	return nil
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
