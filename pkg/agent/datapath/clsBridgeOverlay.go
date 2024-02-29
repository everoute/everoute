package datapath

import (
	"fmt"

	"github.com/contiv/ofnet/ofctrl"
	log "github.com/sirupsen/logrus"
)

type ClsBridgeOverlay struct {
	BaseBridge
}

func newClsBridgeOverlay(brName string, datapathManager *DpManager) *ClsBridgeOverlay {
	if !datapathManager.IsEnableOverlay() {
		log.Fatalf("Can't new overlay cls bridge when disable overlay")
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
		log.Fatalf("Failed to install table 0 policy to uplink flow, err: %v", err)
	}

	fromUplink, _ := defaultTable.NewFlow(ofctrl.FlowMatch{
		Priority:  NORMAL_MATCH_FLOW_PRIORITY,
		InputPort: c.datapathManager.BridgeChainPortMap[c.ovsBrName][ClsToUplinkSuffix],
	})
	policyOutport, _ := sw.OutputPort(c.datapathManager.BridgeChainPortMap[c.ovsBrName][ClsToPolicySuffix])
	if err := fromUplink.Next(policyOutport); err != nil {
		log.Fatalf("Failed to install table 0 uplink to policy flow, err: %v", err)
	}
}
