package cmd

import (
	"fmt"
	"github.com/everoute/everoute/pkg/erctl"

	"github.com/spf13/cobra"
)

var (
	vds, bridge []string
	dp          bool
)

var flowCmd = &cobra.Command{
	Use:   "flow",
	Short: "get all vds's flows",
	Long:  `use grpc to get all ChainBridge name, so get all bridge flows`,
	RunE: func(cmd *cobra.Command, args []string) error {
		err := erctl.ConnectFlow()
		if err != nil {
			return err
		}
		bridges := []string{}
		if len(vds) != 0 {
			bridges = append(bridges, erctl.VdsName2BridgeName(vds...)...)
		}
		if len(bridge) != 0 {
			bridges = append(bridges, bridge...)
		}
		flows, err := erctl.GetFlows(dp, bridges...)
		output, err1 := setOutput()
		if err1 != nil {
			return fmt.Errorf("output:%v\n%v", err1, err)
		}
		err1 = print(output, flows)
		if err1 != nil || err != nil {
			return fmt.Errorf("print:%v\n%v", err1, err)
		}
		return nil
	},
}

func init() {
	getCmd.AddCommand(flowCmd)
	flowCmd.Flags().StringSliceVar(&vds, "vds", []string{}, "vds's name (4 bridges)")
	flowCmd.Flags().StringSliceVar(&bridge, "bridge", []string{}, "bridge's name")
	flowCmd.Flags().BoolVar(&dp, "dp", false, "use to show dpctl dump")
}
