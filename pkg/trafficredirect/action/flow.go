package action

import (
	"fmt"

	"k8s.io/klog/v2"

	"github.com/everoute/everoute/pkg/constants/tr"
)

func DelTRNicFlows(ovsbr string) error {
	policyBr := getPolicyBridgeName(ovsbr)
	cmd := fmt.Sprintf("ovs-ofctl del-flows %s cookie=%#x/%#x", policyBr, tr.FlowIDForTRNicMatch, tr.FlowIDForTRNicMask)
	_, err := excuteCommand(cmd)
	if err != nil {
		klog.Errorf("Failed to del policy bridge %s tr nic flows: %s", policyBr, err)
		return err
	}
	klog.Infof("Success to del policy bridge %s tr nic flows", policyBr)
	return nil
}

func DelTRHealthyFlows(ovsbr string) error {
	policyBr := getPolicyBridgeName(ovsbr)
	cmd := fmt.Sprintf("ovs-ofctl del-flows %s cookie=%#x/%#x", policyBr, tr.FlowIDForHealthyMatch, tr.FlowIDForHealthyMask)
	_, err := excuteCommand(cmd)
	if err != nil {
		klog.Errorf("Failed to del policy bridge %s tr healthy flows: %s", policyBr, err)
		return err
	}
	klog.Infof("Success to del policy bridge %s tr healthy flows", policyBr)
	return nil
}
