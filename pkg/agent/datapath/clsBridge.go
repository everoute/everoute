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
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/contiv/libOpenflow/openflow13"
	"github.com/contiv/ofnet/ofctrl"

	"github.com/everoute/everoute/pkg/constants"
)

//nolint
const (
	CLSBRIDGE_LEARNING_TABLE_ID   = 0
	CLSBRIDGE_FORWARDING_TABLE_ID = 2
	CLSBRIDGE_OUTPUT_TABLE_ID     = 3
)

//nolint
const (
	BROADCAST_MAC_ADDRESS_MASK = "01:00:00:00:00:00"
)

type ClsBridge struct {
	name            string
	OfSwitch        *ofctrl.OFSwitch
	datapathManager *DpManager

	clsBridgeLearningTable   *ofctrl.Table
	clsBridgeForwardingTable *ofctrl.Table
	clsBridgeOutputTable     *ofctrl.Table

	clsSwitchStatusMutex sync.RWMutex
	isClsSwitchConnected bool
}

func NewClsBridge(brName string, datapathManager *DpManager) *ClsBridge {
	clsBridge := new(ClsBridge)
	clsBridge.name = fmt.Sprintf("%s-cls", brName)
	clsBridge.datapathManager = datapathManager

	return clsBridge
}

func (c *ClsBridge) SwitchConnected(sw *ofctrl.OFSwitch) {
	log.Infof("Switch %s connected", c.name)

	c.OfSwitch = sw

	c.clsSwitchStatusMutex.Lock()
	c.isClsSwitchConnected = true
	c.clsSwitchStatusMutex.Unlock()
}

func (c *ClsBridge) SwitchDisconnected(sw *ofctrl.OFSwitch) {
	log.Infof("Switch %s disconnected", c.name)

	c.clsSwitchStatusMutex.Lock()
	c.isClsSwitchConnected = false
	c.clsSwitchStatusMutex.Unlock()

	c.OfSwitch = nil
}

func (c *ClsBridge) IsSwitchConnected() bool {
	c.clsSwitchStatusMutex.Lock()
	defer c.clsSwitchStatusMutex.Unlock()

	return c.isClsSwitchConnected
}

func (c *ClsBridge) WaitForSwitchConnection() {
	for i := 0; i < 20; i++ {
		time.Sleep(1 * time.Second)
		c.clsSwitchStatusMutex.Lock()
		if c.isClsSwitchConnected {
			c.clsSwitchStatusMutex.Unlock()
			return
		}
		c.clsSwitchStatusMutex.Unlock()
	}

	log.Fatalf("OVS switch %s Failed to connect", c.name)
}

func (c *ClsBridge) PacketRcvd(sw *ofctrl.OFSwitch, pkt *ofctrl.PacketIn) {
}

func (c *ClsBridge) MultipartReply(sw *ofctrl.OFSwitch, rep *openflow13.MultipartReply) {
}

func (c *ClsBridge) InitVlanMacLearningAction(learnAction *ofctrl.LearnAction, learnedDstField string, learnedDstFieldBit uint16, learnedSrcValue uint16) error {
	learnDstMatchField1 := &ofctrl.LearnField{
		Name:  "nxm_of_vlan_tci",
		Start: 0,
	}
	learnSrcMatchField1 := &ofctrl.LearnField{
		Name:  "nxm_of_vlan_tci",
		Start: 0,
	}
	learnDstMatchField2 := &ofctrl.LearnField{
		Name:  "nxm_of_eth_dst",
		Start: 0,
	}
	learnSrcMatchField2 := &ofctrl.LearnField{
		Name:  "nxm_of_eth_src",
		Start: 0,
	}
	err := learnAction.AddLearnedMatch(learnDstMatchField1, 16, learnSrcMatchField1, nil)
	if err != nil {
		return fmt.Errorf("failed to initialize learn action, AddLearnedMatch nxm_of_vlan_tci failure, error: %v", err)
	}
	err = learnAction.AddLearnedMatch(learnDstMatchField2, 48, learnSrcMatchField2, nil)
	if err != nil {
		return fmt.Errorf("failed to initialize learn action, AddLearnedMatch nxm_of_eth_dst failure, error: %v", err)
	}
	srcValue := make([]byte, 2)
	binary.BigEndian.PutUint16(srcValue, learnedSrcValue)
	err = learnAction.AddLearnedLoadAction(&ofctrl.LearnField{Name: learnedDstField, Start: 0}, learnedDstFieldBit, nil, srcValue)
	if err != nil {
		return fmt.Errorf("failed to initialize learn action, AddLearnedLoadAction: load:0xclsBridgeToPolicyBridgeOfPort->NXM_OF_REG0[] failure, error: %v", err)
	}
	return nil
}

func (c *ClsBridge) initLearningTable(sw *ofctrl.OFSwitch) error {
	localBrName := strings.TrimSuffix(c.name, "-cls")
	// clsBridge fromLocalLearningFlow
	fromLocalLearningFlow, _ := c.clsBridgeLearningTable.NewFlow(ofctrl.FlowMatch{
		Priority:  NORMAL_MATCH_FLOW_PRIORITY,
		InputPort: uint32(c.datapathManager.BridgeChainPortMap[localBrName][ClsToPolicySuffix]),
	})

	fromLocalLearnAction := ofctrl.NewLearnAction(CLSBRIDGE_FORWARDING_TABLE_ID, NORMAL_MATCH_FLOW_PRIORITY,
		ClsBridgeL2ForwardingTableIdleTimeout, ClsBridgeL2ForwardingTableHardTimeout, 0, 0, 0)
	err := c.InitVlanMacLearningAction(fromLocalLearnAction, "nxm_nx_reg0", 16, uint16(c.datapathManager.BridgeChainPortMap[localBrName][ClsToPolicySuffix]))
	if err != nil {
		return fmt.Errorf("failed to add from local learning flow, error: %v", err)
	}

	if err := fromLocalLearningFlow.Learn(fromLocalLearnAction); err != nil {
		return fmt.Errorf("failed to install from local learning flow for local bridge, error: %v", err)
	}
	var forwardingTable, outputTable uint8 = CLSBRIDGE_FORWARDING_TABLE_ID, CLSBRIDGE_OUTPUT_TABLE_ID
	if err := fromLocalLearningFlow.Resubmit(nil, &forwardingTable); err != nil {
		return fmt.Errorf("failed to install from local learning flow for local bridge, error: %v", err)
	}
	if err := fromLocalLearningFlow.Resubmit(nil, &outputTable); err != nil {
		return fmt.Errorf("failed to install from local learning flow for local bridge, error: %v", err)
	}
	if err := fromLocalLearningFlow.Next(ofctrl.NewEmptyElem()); err != nil {
		return fmt.Errorf("failed to install from local learning flow for local bridge, error: %v", err)
	}

	// clsBridge fromUplinkLearningFlow
	fromUplinkLearningFlow, _ := c.clsBridgeLearningTable.NewFlow(ofctrl.FlowMatch{
		Priority:  NORMAL_MATCH_FLOW_PRIORITY,
		InputPort: uint32(c.datapathManager.BridgeChainPortMap[localBrName][ClsToUplinkSuffix]),
	})
	fromUplinkLearnAction := ofctrl.NewLearnAction(uint8(CLSBRIDGE_FORWARDING_TABLE_ID), NORMAL_MATCH_FLOW_PRIORITY,
		ClsBridgeL2ForwardingTableIdleTimeout, ClsBridgeL2ForwardingTableHardTimeout, 0, 0, 0)
	err = c.InitVlanMacLearningAction(fromUplinkLearnAction, "nxm_nx_reg0", 16, uint16(c.datapathManager.BridgeChainPortMap[localBrName][ClsToUplinkSuffix]))
	if err != nil {
		return fmt.Errorf("failed to add from uplink learning flow, error: %v", err)
	}
	if err := fromUplinkLearningFlow.Learn(fromUplinkLearnAction); err != nil {
		return fmt.Errorf("failed to add from uplink learn flow learn action, error: %v", err)
	}
	outputPort, _ := sw.OutputPort(c.datapathManager.BridgeChainPortMap[localBrName][ClsToPolicySuffix])
	if err := fromUplinkLearningFlow.Next(outputPort); err != nil {
		return fmt.Errorf("failed to install from uplink learning flow, error: %v", err)
	}

	// clsBridgeLearningTable learningTableDefaultFlow
	learningTableDefaultFlow, _ := c.clsBridgeLearningTable.NewFlow(ofctrl.FlowMatch{
		Priority: DEFAULT_FLOW_MISS_PRIORITY,
	})
	if err := learningTableDefaultFlow.Next(sw.DropAction()); err != nil {
		return fmt.Errorf("failed to install cls bridge learning table default flow, error: %v", err)
	}

	return nil
}

func (c *ClsBridge) initForwardingTable() error {
	// clsBridgeForwardingTable broadcast flow
	broadcastMac, _ := net.ParseMAC(BROADCAST_MAC_ADDRESS_MASK)
	fromLocalBroadcastMarkFlow, _ := c.clsBridgeForwardingTable.NewFlow(ofctrl.FlowMatch{
		Priority:  MID_MATCH_FLOW_PRIORITY,
		MacDa:     &broadcastMac,
		MacDaMask: &broadcastMac,
	})
	if err := fromLocalBroadcastMarkFlow.LoadField("nxm_nx_reg0", 0, openflow13.NewNXRange(0, 15)); err != nil {
		return fmt.Errorf("failed to add from local broadcast mark flow, error: %v", err)
	}
	if err := fromLocalBroadcastMarkFlow.Next(ofctrl.NewEmptyElem()); err != nil {
		return fmt.Errorf("failed to install from local broadcast mark flow, error: %v", err)
	}

	// clsBridgeForwardingTable unlearnedFlow
	unlearnedFlow, _ := c.clsBridgeForwardingTable.NewFlow(ofctrl.FlowMatch{
		Priority: DEFAULT_FLOW_MISS_PRIORITY,
	})
	if err := unlearnedFlow.LoadField("nxm_nx_reg0", 0, openflow13.NewNXRange(0, 15)); err != nil {
		return fmt.Errorf("failed to add unlearned flow, error: %v", err)
	}
	if err := unlearnedFlow.Next(ofctrl.NewEmptyElem()); err != nil {
		return fmt.Errorf("failed to install unlearned flow, error: %v", err)
	}

	return nil
}

func (c *ClsBridge) initOuputTable(sw *ofctrl.OFSwitch) error {
	localBrName := strings.TrimSuffix(c.name, "-cls")
	// clsBridgeOutputTable floodingOutputFlow
	floodingOutputFlow, _ := c.clsBridgeOutputTable.NewFlow(ofctrl.FlowMatch{
		Priority: NORMAL_MATCH_FLOW_PRIORITY,
		Regs: []*ofctrl.NXRegister{
			{
				RegID: constants.OVSReg0,
				Data:  0,
				Range: openflow13.NewNXRange(0, 15),
			},
		},
	})

	outputAction1 := ofctrl.NewOutputAction("outputAction", uint32(openflow13.P_IN_PORT))
	outputAction2 := ofctrl.NewOutputAction("outputAction", c.datapathManager.BridgeChainPortMap[localBrName][ClsToUplinkSuffix])
	_ = floodingOutputFlow.Output(outputAction1)
	_ = floodingOutputFlow.Output(outputAction2)
	if err := floodingOutputFlow.Next(ofctrl.NewEmptyElem()); err != nil {
		return fmt.Errorf("failed to install cls bridge floodingOutputFlow, error: %v", err)
	}

	// clsBridge learnedLocalToLocalOutputFlow
	learnedLocalToLocalOutputFlow, _ := c.clsBridgeOutputTable.NewFlow(ofctrl.FlowMatch{
		Priority: NORMAL_MATCH_FLOW_PRIORITY,
		Regs: []*ofctrl.NXRegister{
			{
				RegID: constants.OVSReg0,
				Data:  uint32(c.datapathManager.BridgeChainPortMap[localBrName][ClsToPolicySuffix]),
				Range: openflow13.NewNXRange(0, 15),
			},
		},
	})
	outputPort, _ := sw.OutputPort(uint32(openflow13.P_IN_PORT))
	if err := learnedLocalToLocalOutputFlow.Next(outputPort); err != nil {
		return fmt.Errorf("failed to install cls bridge learnedLocalToLocalOutputFlow, error: %v", err)
	}

	// clsBridgeOutputTable learnedLocalToRemoteOuputFlow
	learnedLocalToRemoteOuputFlow, _ := c.clsBridgeOutputTable.NewFlow(ofctrl.FlowMatch{
		Priority: NORMAL_MATCH_FLOW_PRIORITY,
		Regs: []*ofctrl.NXRegister{
			{
				RegID: constants.OVSReg0,
				Data:  uint32(c.datapathManager.BridgeChainPortMap[localBrName][ClsToUplinkSuffix]),
				Range: openflow13.NewNXRange(0, 15),
			},
		},
	})
	outputPort, _ = sw.OutputPort(c.datapathManager.BridgeChainPortMap[localBrName][ClsToUplinkSuffix])
	if err := learnedLocalToRemoteOuputFlow.Next(outputPort); err != nil {
		return fmt.Errorf("failed to install cls bridge learnedLocalToRemoteOuputFlow, error: %v", err)
	}

	// clsBridgeOutputTable default flow
	outputTableDefaultFlow, _ := c.clsBridgeOutputTable.NewFlow(ofctrl.FlowMatch{
		Priority: DEFAULT_FLOW_MISS_PRIORITY,
	})
	if err := outputTableDefaultFlow.Next(sw.DropAction()); err != nil {
		return fmt.Errorf("failed to install cls bridge outputTableDefaultFlow, error: %v", err)
	}

	return nil
}

func (c *ClsBridge) BridgeInit() {
	sw := c.OfSwitch

	c.clsBridgeLearningTable = sw.DefaultTable()
	c.clsBridgeForwardingTable, _ = sw.NewTable(CLSBRIDGE_FORWARDING_TABLE_ID)
	c.clsBridgeOutputTable, _ = sw.NewTable(CLSBRIDGE_OUTPUT_TABLE_ID)

	if err := c.initLearningTable(sw); err != nil {
		log.Fatalf("Failed to init cls bridge learning table, error: %v", err)
	}
	if err := c.initForwardingTable(); err != nil {
		log.Fatalf("Failed to init cls bridge forwarding table, error: %v", err)
	}
	if err := c.initOuputTable(sw); err != nil {
		log.Fatalf("Failed to init cls bridge output table, error: %v", err)
	}
}

func (c *ClsBridge) BridgeReset() {
}

func (c *ClsBridge) AddLocalEndpoint(endpoint *Endpoint) error {
	return nil
}

func (c *ClsBridge) RemoveLocalEndpoint(endpoint *Endpoint) error {
	return nil
}

func (c *ClsBridge) AddMicroSegmentRule(rule *EveroutePolicyRule, direction uint8, tier uint8, mode string) (*FlowEntry, error) {
	return nil, nil
}

func (c *ClsBridge) RemoveMicroSegmentRule(rule *EveroutePolicyRule) error {
	return nil
}

func (c *ClsBridge) AddVNFInstance() error {
	return nil
}

func (c *ClsBridge) RemoveVNFInstance() error {
	return nil
}

func (c *ClsBridge) AddSFCRule() error {
	return nil
}

func (c *ClsBridge) RemoveSFCRule() error {
	return nil
}

func (c *ClsBridge) BridgeInitCNI() {
	hairpinFlow, _ := c.clsBridgeLearningTable.NewFlow(ofctrl.FlowMatch{
		Priority:  HIGH_MATCH_FLOW_PRIORITY,
		Ethertype: PROTOCOL_IP,
		IpDa:      &c.datapathManager.AgentInfo.LocalGwIP,
	})
	outputPort, _ := c.OfSwitch.OutputPort(uint32(openflow13.P_IN_PORT))
	if err := hairpinFlow.Next(outputPort); err != nil {
		log.Fatalf("failed to install cls flow for cni hairpin traffic, error: %v", err)
	}
}
