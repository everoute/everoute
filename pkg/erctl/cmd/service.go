package cmd

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/everoute/everoute/pkg/erctl"
)

var svcNs string

var svcCmd = &cobra.Command{
	Use:     "service",
	Aliases: []string{"svc"},
	Short: "get service related flows and cache in local agent by service name and namespace\n" +
		"-n svc-namespace, default value is 'default'",
	Example: "erctl get svc [svcname] -n [nsname]",
	Args:    cobra.ExactArgs(1),
	RunE: func(_ *cobra.Command, args []string) error {
		out, err := setOutput()
		if err != nil {
			return err
		}
		svcName := args[0]
		svcID := svcNs + "/" + svcName

		err = erctl.ConnectClient()
		if err != nil {
			return err
		}
		svcInfo, err := erctl.GetSvcInfoBySvcID(svcID)
		if err != nil {
			return err
		}

		err = erctl.ConnectFlow()
		if err != nil {
			return err
		}
		for i := range svcInfo.SvcGroup {
			gpID := svcInfo.SvcGroup[i].GroupID
			gpInfo, err := erctl.GetOvsPipeline("-nat", erctl.GroupType, strconv.Itoa(int(gpID)))
			if err == nil {
				svcInfo.SvcGroup[i].Info = strings.Join(gpInfo, "\n")
			} else {
				svcInfo.SvcGroup[i].Info = err.Error()
			}
		}
		for i := range svcInfo.SvcFlow.DnatFlows {
			filter := fmt.Sprintf("cookie=%s/-1", strconv.Itoa(int(svcInfo.SvcFlow.DnatFlows[i].FlowID)))
			flowInfo, err := erctl.GetOvsPipeline("-nat", erctl.FlowType, filter)
			if err == nil {
				svcInfo.SvcFlow.DnatFlows[i].Info = strings.Join(flowInfo, "\n")
			} else {
				svcInfo.SvcFlow.DnatFlows[i].Info = err.Error()
			}
		}
		for i := range svcInfo.SvcFlow.LBFlows {
			filter := fmt.Sprintf("cookie=%s/-1", strconv.Itoa(int(svcInfo.SvcFlow.LBFlows[i].FlowID)))
			flowInfo, err := erctl.GetOvsPipeline("-nat", erctl.FlowType, filter)
			if err == nil {
				svcInfo.SvcFlow.LBFlows[i].Info = strings.Join(flowInfo, "\n")
			} else {
				svcInfo.SvcFlow.LBFlows[i].Info = err.Error()
			}
		}
		for i := range svcInfo.SvcFlow.SessionAffinityFlows {
			filter := fmt.Sprintf("cookie=%s/-1", strconv.Itoa(int(svcInfo.SvcFlow.SessionAffinityFlows[i].FlowID)))
			flowInfo, err := erctl.GetOvsPipeline("-nat", erctl.FlowType, filter)
			if err == nil {
				svcInfo.SvcFlow.SessionAffinityFlows[i].Info = strings.Join(flowInfo, "\n")
			} else {
				svcInfo.SvcFlow.SessionAffinityFlows[i].Info = err.Error()
			}
		}
		err = printz(out, svcInfo)
		return err
	},
}

func init() {
	getCmd.AddCommand(svcCmd)
	svcCmd.Flags().StringVarP(&svcNs, "namespace", "n", "default", "-n svc-namespace")
}
