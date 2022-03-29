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

package exporter

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"strconv"
	"sync"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/contiv/libOpenflow/openflow13"
	"github.com/contiv/ofnet/ofctrl"
	"github.com/contiv/ofnet/ovsdbDriver"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/everoute/everoute/pkg/agent/datapath"
)

const (
	ovsVswitchdUnixDomainSockPath   string = "/var/run/openvswitch"
	ovsVswitchdUnixDomainSockSuffix string = "mgmt"

	openflowProtorolVersion10 string = "OpenFlow10"
	openflowProtorolVersion11 string = "OpenFlow11"
	openflowProtorolVersion12 string = "OpenFlow12"
	openflowProtorolVersion13 string = "OpenFlow13"
)

type SingleBridge struct {
	name              string
	OfSwitch          *ofctrl.OFSwitch
	singleBridgeMutex sync.Mutex
	controllerIDSets  sets.String

	singleBridgeInputTable    *ofctrl.Table
	singleBridgeCtStateTable  *ofctrl.Table
	singleBridgeCtCommitTable *ofctrl.Table

	singleSwitchStatusMutex sync.RWMutex
	isSingleSwitchConnected bool
}

func (s *SingleBridge) SwitchConnected(sw *ofctrl.OFSwitch) {
	log.Infof("Switch %s connected", s.name)

	s.OfSwitch = sw

	s.singleSwitchStatusMutex.Lock()
	s.isSingleSwitchConnected = true
	s.singleSwitchStatusMutex.Unlock()
}

// Switch disconnected from the controller
func (s *SingleBridge) SwitchDisconnected(sw *ofctrl.OFSwitch) {
	s.singleSwitchStatusMutex.Lock()
	s.isSingleSwitchConnected = false
	s.singleSwitchStatusMutex.Unlock()

	s.OfSwitch = nil
}

func (s *SingleBridge) IsSwitchConnected() bool {
	s.singleSwitchStatusMutex.Lock()
	defer s.singleSwitchStatusMutex.Unlock()

	return s.isSingleSwitchConnected
}

func (s *SingleBridge) WaitForSwitchConnection() {
	for i := 0; i < 20; i++ {
		time.Sleep(1 * time.Second)
		if s.IsSwitchConnected() {
			return
		}
	}

	log.Fatalf("OVS switch %s Failed to connect", s.name)
}

// Controller received a packet from the switch
func (s *SingleBridge) PacketRcvd(sw *ofctrl.OFSwitch, pkt *ofctrl.PacketIn) {

}

// Controller received a multi-part reply from the switch
func (s *SingleBridge) MultipartReply(sw *ofctrl.OFSwitch, rep *openflow13.MultipartReply) {

}

func (s *SingleBridge) GenerateControllerID() uint16 {
	s.singleBridgeMutex.Lock()
	defer s.singleBridgeMutex.Unlock()

	var ctrlID uint16
	for {
		err := binary.Read(rand.Reader, binary.LittleEndian, &ctrlID)
		if err != nil {
			log.Infof("get random ID from rand.Reader: %s", err)
			continue
		}
		if s.controllerIDSets.Has(strconv.Itoa(int(ctrlID))) {
			continue
		}
		s.controllerIDSets.Insert(strconv.Itoa(int(ctrlID)))
		return ctrlID
	}
}

func NewSingleBridge(brName string) *SingleBridge {
	singleBridge := new(SingleBridge)
	singleBridge.name = brName
	singleBridge.controllerIDSets = sets.NewString()

	singleBridgeController := ofctrl.NewControllerAsOFClient(singleBridge, singleBridge.GenerateControllerID())
	singleBridgeOvsDriver := ovsdbDriver.NewOvsDriverForExistBridge(brName)
	protocols := map[string][]string{
		"protocols": {
			openflowProtorolVersion10, openflowProtorolVersion11, openflowProtorolVersion12, openflowProtorolVersion13,
		},
	}
	if err := singleBridgeOvsDriver.UpdateBridge(protocols); err != nil {
		log.Fatalf("Failed to set policy bridge: %v protocols, error: %v", brName, err)
	}
	go singleBridgeController.Connect(fmt.Sprintf("%s/%s.%s", ovsVswitchdUnixDomainSockPath, singleBridge.name, ovsVswitchdUnixDomainSockSuffix))

	return singleBridge
}

func (s *SingleBridge) BridgeInit() {
	if !s.isSingleSwitchConnected {
		s.WaitForSwitchConnection()
	}
	sw := s.OfSwitch
	s.singleBridgeInputTable = sw.DefaultTable()
	s.singleBridgeCtStateTable, _ = sw.NewTable(datapath.CT_STATE_TABLE)
	s.singleBridgeCtCommitTable, _ = sw.NewTable(datapath.CT_COMMIT_TABLE)

	if err := s.initInputTable(sw); err != nil {
		log.Fatalf("Failed to init inputTable, error: %v", err)
	}
	if err := s.initCTFlow(sw); err != nil {
		log.Fatalf("Failed to init ct table, error: %v", err)
	}
}

func (s *SingleBridge) initInputTable(sw *ofctrl.OFSwitch) error {
	var ctStateTableID uint8 = datapath.CT_STATE_TABLE
	var policyConntrackZone uint16 = 65520
	ctAction := ofctrl.NewConntrackAction(false, false, &ctStateTableID, &policyConntrackZone)
	inputIPRedirectFlow, _ := s.singleBridgeInputTable.NewFlow(ofctrl.FlowMatch{
		Priority:  datapath.SingleBridgeInputHighPriority,
		Ethertype: datapath.PROTOCOL_IP,
	})
	_ = inputIPRedirectFlow.SetConntrack(ctAction)

	inputDefaultFlow, _ := s.singleBridgeInputTable.NewFlow(ofctrl.FlowMatch{
		Priority: datapath.SingleBridgeInputNormalPriority,
	})
	if err := inputDefaultFlow.Next(s.OfSwitch.NormalLookup()); err != nil {
		return fmt.Errorf("failed to install vlan input table default flow, error: %v", err)
	}
	return nil
}

func (s *SingleBridge) initCTFlow(sw *ofctrl.OFSwitch) error {
	var ctCommitTableID uint8 = datapath.CT_COMMIT_TABLE
	var policyConntrackZone uint16 = 65520
	ctInvState := openflow13.NewCTStates()
	ctInvState.SetInv()
	ctInvState.SetTrk()
	ctInvFlow, _ := s.singleBridgeCtStateTable.NewFlow(ofctrl.FlowMatch{
		Priority: datapath.SingleBridgeInputHighPriority,
		CtStates: ctInvState,
	})
	if err := ctInvFlow.Next(sw.DropAction()); err != nil {
		return fmt.Errorf("failed to install ct invalid state flow, error: %v", err)
	}

	ctTrkState := openflow13.NewCTStates()
	ctTrkState.SetNew()
	ctTrkState.SetTrk()
	ctCommitFlow, _ := s.singleBridgeCtStateTable.NewFlow(ofctrl.FlowMatch{
		Priority:  datapath.SingleBridgeInputHighPriority,
		Ethertype: datapath.PROTOCOL_IP,
		CtStates:  ctTrkState,
	})
	ctCommitAction := ofctrl.NewConntrackAction(true, false, &ctCommitTableID, &policyConntrackZone)
	_ = ctCommitFlow.SetConntrack(ctCommitAction)

	ctStateDefaultFlow, _ := s.singleBridgeCtStateTable.NewFlow(ofctrl.FlowMatch{
		Priority: datapath.SingleBridgeInputNormalPriority,
	})
	if err := ctStateDefaultFlow.Resubmit(nil, &s.singleBridgeCtCommitTable.TableId); err != nil {
		return fmt.Errorf("failed to install ct bypass flow 1, error: %v", err)
	}
	if err := ctStateDefaultFlow.Next(ofctrl.NewEmptyElem()); err != nil {
		return fmt.Errorf("failed to install ct bypass flow 1, error: %v", err)
	}

	ctCommitTableDefaultFlow, _ := s.singleBridgeCtCommitTable.NewFlow(ofctrl.FlowMatch{
		Priority: datapath.SingleBridgeInputNormalPriority,
	})
	if err := ctCommitTableDefaultFlow.Next(s.OfSwitch.NormalLookup()); err != nil {
		return fmt.Errorf("failed to install ct commit flow, error: %v", err)
	}

	return nil
}
