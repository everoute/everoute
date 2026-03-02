package cmd

import (
	"fmt"
	"strconv"

	"github.com/spf13/cobra"

	"github.com/everoute/everoute/pkg/erctl"
)

var getGOMemLimitCmd = &cobra.Command{
	Use:   "get-gomemlimit",
	Short: "Get current Go runtime memory limit from agent",
	Args:  cobra.NoArgs,
	RunE: func(_ *cobra.Command, _ []string) error {
		if err := erctl.ConnectClient(); err != nil {
			return err
		}
		limit, err := erctl.GetGOMemLimit()
		if err != nil {
			return err
		}
		fmt.Printf("current gomemlimit: %d\n", limit)
		return nil
	},
}

var setGOMemLimitCmd = &cobra.Command{
	Use:   "set-gomemlimit [limit]",
	Short: "Set Go runtime memory limit on agent (must be > 0)",
	Args:  cobra.ExactArgs(1),
	RunE: func(_ *cobra.Command, args []string) error {
		limit, err := strconv.ParseInt(args[0], 10, 64)
		if err != nil {
			return err
		}
		if limit <= 0 {
			return fmt.Errorf("limit must be > 0")
		}
		if err := erctl.ConnectClient(); err != nil {
			return err
		}
		prev, cur, err := erctl.SetGOMemLimit(limit)
		if err != nil {
			return err
		}
		fmt.Printf("prev: %d, current: %d\n", prev, cur)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(getGOMemLimitCmd)
	rootCmd.AddCommand(setGOMemLimitCmd)
}
