/*
Copyright 2021 The Everoute Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package datapath

import (
	"fmt"

	"github.com/contiv/libOpenflow/openflow13"
	"github.com/contiv/ofnet/ofctrl"
	log "github.com/sirupsen/logrus"
)

type UplinkBridge struct {
	BaseBridge

	defaultTable *ofctrl.Table
}

func NewUplinkBridge(brName string, datapathManager *DpManager) Bridge {
	if datapathManager.IsEnableOverlay() {
		return newUplinkBridgeOverlay(brName, datapathManager)
	}
	return newUplinkBridge(brName, datapathManager)
}

func newUplinkBridge(brName string, datapathManager *DpManager) *UplinkBridge {
	uplinkBridge := new(UplinkBridge)
	uplinkBridge.name = fmt.Sprintf("%s-uplink", brName)
	uplinkBridge.datapathManager = datapathManager
	return uplinkBridge
}

func (u *UplinkBridge) PacketRcvd(_ *ofctrl.OFSwitch, _ *ofctrl.PacketIn) {
}

func (u *UplinkBridge) MultipartReply(_ *ofctrl.OFSwitch, _ *openflow13.MultipartReply) {
}

func (u *UplinkBridge) BridgeInit() {
	sw := u.OfSwitch
	u.defaultTable = sw.DefaultTable()

	defaultTableDefaultFlow, _ := u.defaultTable.NewFlow(ofctrl.FlowMatch{
		Priority: DEFAULT_FLOW_MISS_PRIORITY,
	})

	// http://jira.smartx.com/browse/ER-1128
	// Mark packet source bridge with 0x3(uplink bridge)
	markPacketSourceBridgeAction, err := ofctrl.NewNXLoadAction("nxm_nx_pkt_mark", 0x3, openflow13.NewNXRange(17, 18))
	if err != nil {
		log.Fatalf("Failed to create source action, error: %v", err)
	}
	if err := defaultTableDefaultFlow.AddAction(markPacketSourceBridgeAction); err != nil {
		log.Fatalf("failed to install uplink default table default flow, error: %v", err)
	}

	// Mark Inport
	markInportAction, err := ofctrl.NewNXMoveAction(16, 0, 0, "nxm_of_in_port", "nxm_nx_pkt_mark", false)
	if err != nil {
		log.Fatalf("Failed to create mark inport action, error: %v", err)
	}
	if err := defaultTableDefaultFlow.AddAction(markInportAction); err != nil {
		log.Fatalf("failed to install uplink default table default flow, error: %v", err)
	}

	if err := defaultTableDefaultFlow.Next(sw.NormalLookup()); err != nil {
		log.Fatalf("failed to install uplink default table default flow, error: %v", err)
	}
}

func (u *UplinkBridge) BridgeReset() {
}

func (u *UplinkBridge) AddLocalEndpoint(_ *Endpoint) error {
	return nil
}

func (u *UplinkBridge) RemoveLocalEndpoint(_ *Endpoint) error {
	return nil
}

func (u *UplinkBridge) AddVNFInstance() error {
	return nil
}

func (u *UplinkBridge) RemoveVNFInstance() error {
	return nil
}

func (u *UplinkBridge) AddSFCRule() error {
	return nil
}

func (u *UplinkBridge) RemoveSFCRule() error {
	return nil
}

func (u *UplinkBridge) BridgeInitCNI() {

}
