package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/everoute/everoute/pkg/erctl"
)

var (
	bridge []string
	dp     bool
)

var flowCmd = &cobra.Command{
	Use:   "flow",
	Short: "get all vds's flows",
	Long:  `use grpc to get all ChainBridge name, so get all bridge flows`,
	RunE: func(_ *cobra.Command, _ []string) error {
		err := erctl.ConnectFlow()
		if err != nil {
			return err
		}
		bridges := []string{}
		if len(bridge) != 0 {
			bridges = append(bridges, bridge...)
		}
		flows, err := erctl.GetFlows(dp, bridges...)
		output, err1 := setOutput()
		if err1 != nil {
			return fmt.Errorf("output:%v\n%v", err1, err)
		}
		err1 = printz(output, flows)
		if err1 != nil || err != nil {
			return fmt.Errorf("print:%v\n%v", err1, err)
		}
		return nil
	},
}

func init() {
	getCmd.AddCommand(flowCmd)
	flowCmd.Flags().StringSliceVar(&bridge, "bridge", []string{}, "bridge's name")
	flowCmd.Flags().BoolVar(&dp, "dp", false, "use to show dpctl dump")
}
