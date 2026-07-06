package cmd

import (
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/everoute/everoute/pkg/erctl"
)

var cleanCmd = &cobra.Command{
	Use:   "clean",
	Short: "clean datapath resources",
}

var cleanPreviousRoundFlowCmd = &cobra.Command{
	Use:   "previous-round-flow",
	Short: "delete previous round flows from datapath",
	RunE: func(_ *cobra.Command, _ []string) error {
		if err := erctl.ConnectClient(); err != nil {
			return err
		}
		res, err := erctl.DeletePreviousRoundFlows()
		output, err1 := setOutput()
		if err1 != nil {
			return fmt.Errorf("output:%v\n%v", err1, err)
		}
		if err == nil {
			_, err1 = io.WriteString(output, res.GetMessage()+"\n")
		}
		if err1 != nil || err != nil {
			return fmt.Errorf("print:%v\n%v", err1, err)
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(cleanCmd)
	cleanCmd.AddCommand(cleanPreviousRoundFlowCmd)
}
