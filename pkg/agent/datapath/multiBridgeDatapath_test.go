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
	"net"
	"os"
	"testing"

	log "github.com/Sirupsen/logrus"
	"github.com/contiv/libOpenflow/openflow13"
	"github.com/contiv/libOpenflow/protocol"
	"github.com/contiv/ofnet/ofctrl"
)

var (
	datapathManager *DpManager
	datapathConfig  = Config{
		ManagedVDSMap: map[string]string{
			"ovsbr0": "ovsbr0",
		},
	}

	ep1IP = "10.0.1.11"
	ep1   = &Endpoint{
		PortNo:     11,
		MacAddrStr: "00:00:11:11:11:11",
		BridgeName: "ovsbr0",
		VlanID:     uint16(1),
	}

	rule1 = &EveroutePolicyRule{
		RuleID:     "rule1",
		IPProtocol: uint8(1),
		SrcIPAddr:  "10.100.100.1",
		DstIPAddr:  "10.100.100.2",
		Action:     "allow",
	}
	rule2 = &EveroutePolicyRule{
		RuleID:     "rule2",
		IPProtocol: uint8(17),
		SrcIPAddr:  "10.100.100.1/24",
		Action:     "deny",
	}
)

func TestMain(m *testing.M) {
	ipAddressChan := make(chan map[string][]net.IP, 100)
	if err := ExcuteCommand(SetupBridgeChain, "ovsbr0"); err != nil {
		log.Fatalf("Failed to setup bridgechain, error: %v", err)
	}

	datapathManager = NewDatapathManager(&datapathConfig, ipAddressChan)
	datapathManager.InitializeDatapath()

	exitCode := m.Run()
	_ = ExcuteCommand(CleanBridgeChain, "ovsbr0")
	os.Exit(exitCode)
}

func TestLocalEndpoint(t *testing.T) {
	t.Run("Test add local endpoint", func(t *testing.T) {
		if err := datapathManager.AddLocalEndpoint(ep1); err != nil {
			t.Errorf("Failed to add local endpoint %v, error: %v", ep1, err)
		}
		if ep, _ := datapathManager.localEndpointDB.Get(fmt.Sprintf("%s-%d", ep1.BridgeName, ep1.PortNo)); ep == nil {
			t.Errorf("Failed to add local endpoint, endpoint %v not found", ep1)
		}

		localBridge := datapathManager.BridgeChainMap["ovsbr0"][LOCAL_BRIDGE_KEYWORD].(*LocalBridge)
		injectArpReq(localBridge, ep1.PortNo, ep1.VlanID, ep1.MacAddrStr, "", ep1IP, "10.0.1.12")

		ep, _ := datapathManager.localEndpointDB.Get(fmt.Sprintf("%s-%d", ep1.BridgeName, ep1.PortNo))
		if ep.(*Endpoint).IPAddr.String() != ep1IP {
			t.Errorf("Failed to learning local endpoint ip address")
		}

		if err := datapathManager.RemoveLocalEndpoint(ep1); err != nil {
			t.Errorf("Failed to remove local endpoint %v, error: %v", ep1, err)
		}
		if ep, _ := datapathManager.localEndpointDB.Get(fmt.Sprintf("%s-%d", ep1.BridgeName, ep1.PortNo)); ep != nil {
			t.Errorf("Failed to remove local endpoint, endpoint %v in cache", ep1)
		}
	})
}

func TestERPolicyRule(t *testing.T) {
	t.Run("test ER policy rule", func(t *testing.T) {
		if err := datapathManager.AddEveroutePolicyRule(rule1, POLICY_DIRECTION_IN, POLICY_TIER1); err != nil {
			t.Errorf("Failed to add ER policy rule: %v, error: %v", rule1, err)
		}
		if _, ok := datapathManager.Rules[rule1.RuleID]; !ok {
			t.Errorf("Failed to add ER policy rule, not found %v in cache", rule1)
		}

		if err := datapathManager.RemoveEveroutePolicyRule(rule1); err != nil {
			t.Errorf("Failed to remove ER policy rule: %v, error: %v", rule1, err)
		}
		if _, ok := datapathManager.Rules[rule1.RuleID]; ok {
			t.Errorf("Failed to remove ER policy rule, rule %v in cache", rule1)
		}

		if err := datapathManager.AddEveroutePolicyRule(rule2, POLICY_DIRECTION_OUT, POLICY_TIER0); err != nil {
			t.Errorf("Failed to add ER policy rule: %v, error: %v", rule2, err)
		}
		if _, ok := datapathManager.Rules[rule2.RuleID]; !ok {
			t.Errorf("Failed to add ER policy rule, not found %v in cache", rule2)
		}
		if err := datapathManager.AddEveroutePolicyRule(rule2, POLICY_DIRECTION_OUT, POLICY_TIER0); err != nil {
			t.Errorf("Failed to add ER policy rule: %v, error: %v", rule2, err)
		}
	})
}

// injectArpReq injects an ARP request into ofnet
func injectArpReq(bridge *LocalBridge, inPort uint32, vlan uint16, macSrc, macDst, ipSrc, ipDst string) {
	if macDst == "" {
		macDst = "ff:ff:ff:ff:ff:ff"
	}

	// inject an ARP request from ep1 for ep2
	arpReq := openflow13.NewPacketIn()
	arpReq.Match.Type = openflow13.MatchType_OXM
	arpReq.Match.AddField(*openflow13.NewInPortField(inPort))
	arpReq.Data = *protocol.NewEthernet()
	arpReq.Data.Ethertype = protocol.ARP_MSG
	arpReq.Data.HWDst, _ = net.ParseMAC(macDst)
	arpReq.Data.HWSrc, _ = net.ParseMAC(macSrc)
	if vlan != 0 {
		arpReq.Data.VLANID.VID = vlan
	}
	arpPkt, _ := protocol.NewARP(protocol.Type_Request)
	arpPkt.HWSrc, _ = net.ParseMAC(macSrc)
	arpPkt.IPSrc = net.ParseIP(ipSrc)
	arpPkt.HWDst, _ = net.ParseMAC("00:00:00:00:00:00")
	arpPkt.IPDst = net.ParseIP(ipDst)

	arpReq.Data.Data = arpPkt
	pkt := ofctrl.PacketIn(*arpReq)
	bridge.PacketRcvd(bridge.OfSwitch, &pkt)
}
