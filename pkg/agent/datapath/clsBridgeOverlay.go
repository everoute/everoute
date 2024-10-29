package datapath

import (
	"fmt"

	"github.com/contiv/ofnet/ofctrl"
	klog "k8s.io/klog/v2"
)

type ClsBridgeOverlay struct {
	BaseBridge
}

func newClsBridgeOverlay(brName string, datapathManager *DpManager) *ClsBridgeOverlay {
	if !datapathManager.IsEnableOverlay() {
		klog.Fatalf("Can't new overlay cls bridge when disable overlay")
	}
	clsBridge := new(ClsBridgeOverlay)
	clsBridge.name = fmt.Sprintf("%s-cls", brName)
	clsBridge.datapathManager = datapathManager
	clsBridge.ovsBrName = brName

	return clsBridge
}

func (c *ClsBridgeOverlay) BridgeInitCNI() {
	sw := c.OfSwitch
	defaultTable := sw.DefaultTable()

	fromPolicy, _ := defaultTable.NewFlow(ofctrl.FlowMatch{
		Priority:  NORMAL_MATCH_FLOW_PRIORITY,
		InputPort: c.datapathManager.BridgeChainPortMap[c.ovsBrName][ClsToPolicySuffix],
	})
	uplinkOutport, _ := sw.OutputPort(c.datapathManager.BridgeChainPortMap[c.ovsBrName][ClsToUplinkSuffix])
	if err := fromPolicy.Next(uplinkOutport); err != nil {
		klog.Fatalf("Failed to install table 0 policy to uplink flow, err: %v", err)
	}

	fromUplink, _ := defaultTable.NewFlow(ofctrl.FlowMatch{
		Priority:  NORMAL_MATCH_FLOW_PRIORITY,
		InputPort: c.datapathManager.BridgeChainPortMap[c.ovsBrName][ClsToUplinkSuffix],
	})
	policyOutport, _ := sw.OutputPort(c.datapathManager.BridgeChainPortMap[c.ovsBrName][ClsToPolicySuffix])
	if err := fromUplink.Next(policyOutport); err != nil {
		klog.Fatalf("Failed to install table 0 uplink to policy flow, err: %v", err)
	}
}
