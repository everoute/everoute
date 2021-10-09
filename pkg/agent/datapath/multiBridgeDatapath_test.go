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
	"os/exec"
	"testing"

	log "github.com/Sirupsen/logrus"
	"github.com/contiv/libOpenflow/openflow13"
	"github.com/contiv/libOpenflow/protocol"
	"github.com/contiv/ofnet/ofctrl"
)

const (
	setupBridgeChainCommand = `
		set -o errexit
		set -o pipefail
		set -o nounset
		set -o xtrace

        DEFAULT_BRIDGE="ovsbr0"
        LOCAL_TO_POLICY_OFPORT=101
        POLICY_TO_LOCAL_OFPORT=102
        POLICY_TO_CLS_OFPORT=201
        CLS_TO_POLICY_OFPORT=202
        CLS_TO_UPLINK_OFPORT=301
        UPLINK_TO_CLS_OFPORT=302

        LOCAL_TO_POLICY_PATCH="local-to-policy"
        POLICY_TO_LOCAL_PATCH="policy-to-local"
        POLICY_TO_CLS_PATCH="policy-to-cls"
        CLS_TO_POLICY_PATCH="cls-to-policy"
        CLS_TO_UPLINK_PATCH="cls-to-uplink"
        UPLINK_TO_CLS_PATCH="uplink-to-cls"

        echo "add uplink interface if not exists"
        ip link show ${UPLINK_IFACE} || ip link add ${UPLINK_IFACE} type bridge

        echo "add bridge chain and uplink port"
        ovs-vsctl add-br ${DEFAULT_BRIDGE} -- set bridge ${DEFAULT_BRIDGE} protocols=OpenFlow10,OpenFlow11,OpenFlow12,OpenFlow13
        ovs-vsctl add-br ${DEFAULT_BRIDGE}-policy -- set bridge ${DEFAULT_BRIDGE}-policy protocols=OpenFlow10,OpenFlow11,OpenFlow12,OpenFlow13
        ovs-vsctl add-br ${DEFAULT_BRIDGE}-cls -- set bridge ${DEFAULT_BRIDGE}-cls protocols=OpenFlow10,OpenFlow11,OpenFlow12,OpenFlow13
        ovs-vsctl add-br ${DEFAULT_BRIDGE}-uplink -- set bridge ${DEFAULT_BRIDGE}-uplink protocols=OpenFlow10,OpenFlow11,OpenFlow12,OpenFlow13

        ovs-vsctl \
            -- add-port $DEFAULT_BRIDGE $LOCAL_TO_POLICY_PATCH \
            -- set interface $LOCAL_TO_POLICY_PATCH type=patch options:peer=$POLICY_TO_LOCAL_PATCH ofport=$LOCAL_TO_POLICY_OFPORT \
            -- add-port ${DEFAULT_BRIDGE}-policy $POLICY_TO_LOCAL_PATCH \
            -- set interface $POLICY_TO_LOCAL_PATCH type=patch options:peer=$LOCAL_TO_POLICY_PATCH ofport=$POLICY_TO_LOCAL_OFPORT

        ovs-vsctl \
            -- add-port ${DEFAULT_BRIDGE}-policy $POLICY_TO_CLS_PATCH \
            -- set interface $POLICY_TO_CLS_PATCH type=patch options:peer=$CLS_TO_POLICY_PATCH ofport=$POLICY_TO_CLS_OFPORT\
            -- add-port ${DEFAULT_BRIDGE}-cls $CLS_TO_POLICY_PATCH \
            -- set interface $CLS_TO_POLICY_PATCH type=patch options:peer=$POLICY_TO_CLS_PATCH ofport=$CLS_TO_POLICY_OFPORT

        ovs-vsctl \
            -- add-port ${DEFAULT_BRIDGE}-uplink $UPLINK_TO_CLS_PATCH \
            -- set interface $UPLINK_TO_CLS_PATCH type=patch options:peer=$CLS_TO_UPLINK_PATCH ofport=$UPLINK_TO_CLS_OFPORT \
            -- add-port ${DEFAULT_BRIDGE}-cls $CLS_TO_UPLINK_PATCH \
            -- set interface $CLS_TO_UPLINK_PATCH type=patch options:peer=$UPLINK_TO_CLS_PATCH ofport=$CLS_TO_UPLINK_OFPORT

        ovs-vsctl add-port ${DEFAULT_BRIDGE}-uplink ${UPLINK_IFACE} -- set Port ${UPLINK_IFACE} external_ids=\
            uplink-port="true" -- set Interface ${UPLINK_IFACE} ofport=${OFPORT_NUM}
        ovs-ofctl add-flow ${DEFAULT_BRIDGE}-uplink "table=0,priority=10,actions=normal"
    `
	cleanBridgeChain = `
        DEFAULT_BRIDGE="ovsbr0"
        ovs-vsctl del-br ${DEFAULT_BRIDGE} && ovs-vsctl del-br ${DEFAULT_BRIDGE}-policy && ovs-vsctl del-br \
            ${DEFAULT_BRIDGE}-cls && ovs-vsctl del-br ${DEFAULT_BRIDGE}-uplink
    `
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
	if err := excuteCommand(setupBridgeChainCommand); err != nil {
		log.Fatalf("Failed to setup bridgechain, error: %v", err)
	}

	datapathManager = NewDatapathManager(&datapathConfig, ipAddressChan)
	datapathManager.InitializeDatapath()

	exitCode := m.Run()
	_ = excuteCommand(cleanBridgeChain)
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

func excuteCommand(cmdStr string) error {
	out, err := exec.Command("bash", "-s", cmdStr).CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to excute cmd: %v, error: %v", string(out), err)
	}

	return nil
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
