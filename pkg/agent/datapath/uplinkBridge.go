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

	log "github.com/Sirupsen/logrus"
	"github.com/contiv/libOpenflow/openflow13"
	"github.com/contiv/ofnet/ofctrl"
)

type UplinkBridge struct {
	BaseBridge

	defaultTable *ofctrl.Table
}

func NewUplinkBridge(brName string, datapathManager *DpManager) *UplinkBridge {
	uplinkBridge := new(UplinkBridge)
	uplinkBridge.name = fmt.Sprintf("%s-uplink", brName)
	uplinkBridge.datapathManager = datapathManager
	return uplinkBridge
}

func (u *UplinkBridge) PacketRcvd(sw *ofctrl.OFSwitch, pkt *ofctrl.PacketIn) {
}

func (u *UplinkBridge) MultipartReply(sw *ofctrl.OFSwitch, rep *openflow13.MultipartReply) {
}

func (u *UplinkBridge) BridgeInit() {
	sw := u.OfSwitch
	u.defaultTable = sw.DefaultTable()

	defaultTableDefaultFlow, _ := u.defaultTable.NewFlow(ofctrl.FlowMatch{
		Priority: DEFAULT_FLOW_MISS_PRIORITY,
	})
	if err := defaultTableDefaultFlow.Next(sw.NormalLookup()); err != nil {
		log.Fatalf("failed to install uplink default table default flow, error: %v", err)
	}
}

func (u *UplinkBridge) BridgeReset() {
}

func (u *UplinkBridge) AddLocalEndpoint(endpoint *Endpoint) error {
	return nil
}

func (u *UplinkBridge) RemoveLocalEndpoint(endpoint *Endpoint) error {
	return nil
}

func (u *UplinkBridge) AddMicroSegmentRule(rule *EveroutePolicyRule, direction uint8, tier uint8, mode string) (*FlowEntry, error) {
	return nil, nil
}

func (u *UplinkBridge) RemoveMicroSegmentRule(rule *EveroutePolicyRule) error {
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
