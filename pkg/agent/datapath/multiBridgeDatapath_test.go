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
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"
	"time"

	. "github.com/onsi/gomega"
	"github.com/samber/lo"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
	"k8s.io/apimachinery/pkg/util/rand"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"

	"github.com/everoute/everoute/pkg/apis/security/v1alpha1"
	"github.com/everoute/everoute/pkg/metrics"
	"github.com/everoute/everoute/pkg/types"
)

const (
	ovsctlScriptPath           = "/usr/share/openvswitch/scripts/ovs-ctl"
	ovsVswitchdRestartInterval = 1
	ifaceUUID                  = "10000000-0000-0000-0000-000000000000"
	iface2UUID                 = "20000000-0000-0000-0000-000000000000"
	TRNicInIfaceID             = "ddb7623c-fa17-4ad4-9bbb-d03d982c52bc"
	TRNicOutIfaceID            = "3a32fe96-072c-4c29-be38-edfe87aae0b0"
	TRNicInUUID                = "9a8393a3-ce1a-434d-816d-c419a996da23"
	TRNicOutUUID               = "6882f9c0-ce2f-43cd-8c8c-48c1fdf48028"
	TRNicInPortNO              = uint32(1)
	TRNicOutPortNO             = uint32(2)
)

const (
	timeout  = time.Second * 20
	interval = time.Millisecond * 500
)

var (
	ctx             = context.Background()
	datapathManager *DpManager
	datapathConfig  = DpManagerConfig{
		ManagedVDSMap: map[string]string{
			"ovsbr0": "ovsbr0",
		},
		MSVdsSet:         sets.New[string]("ovsbr0"),
		EnableIPLearning: true,
		TRConfig: map[string]VDSTRConfig{
			"ovsbr0": {
				NicIn:  TRNicInIfaceID,
				NicOut: TRNicOutIfaceID,
			},
		},
	}

	cniDpMgr  *DpManager
	cniBrName = "cnibr0"

	endpointIPChan = make(chan *types.EndpointIP, 1000)

	ovsBridgeList   = []string{"ovsbr0", "ovsbr0-policy", "ovsbr0-cls", "ovsbr0-uplink"}
	defaultFlowList []string

	ep1 = &Endpoint{
		InterfaceName: "ep1",
		InterfaceUUID: ifaceUUID,
		PortNo:        uint32(11),
		IPAddr:        net.ParseIP("10.10.1.7"),
		MacAddrStr:    "00:00:aa:aa:aa:aa",
		BridgeName:    "ovsbr0",
		VlanID:        uint16(1),
	}
	newep1 = &Endpoint{
		InterfaceName: "ep1",
		InterfaceUUID: ifaceUUID,
		PortNo:        uint32(12),
		IPAddr:        net.ParseIP("10.10.1.7"),
		MacAddrStr:    "00:00:aa:aa:aa:aa",
		BridgeName:    "ovsbr0",
		VlanID:        uint16(1),
	}
	ep2 = &Endpoint{
		InterfaceName: "ep2",
		InterfaceUUID: iface2UUID,
		PortNo:        uint32(22),
		MacAddrStr:    "00:00:aa:aa:aa:bb",
		BridgeName:    "ovsbr0",
		Trunk:         "0,1,2,3",
	}
	newep2 = &Endpoint{
		InterfaceName: "ep2",
		InterfaceUUID: iface2UUID,
		PortNo:        uint32(22),
		IPAddr:        net.ParseIP("10.10.1.8"),
		MacAddrStr:    "00:00:aa:aa:aa:bb",
		BridgeName:    "ovsbr0",
		VlanID:        uint16(1),
	}
	ep3 = &Endpoint{
		InterfaceName: "ep3",
		PortNo:        uint32(33),
		MacAddrStr:    "00:00:aa:aa:aa:cc",
		BridgeName:    "ovsbr0",
		Trunk:         "1,2,3",
	}

	rule1 = &EveroutePolicyRule{
		RuleID:     "rule1",
		Priority:   200,
		IPProtocol: unix.IPPROTO_ICMP,
		IPFamily:   unix.AF_INET,
		SrcIPAddr:  "10.100.100.1",
		DstIPAddr:  "10.100.100.2",
		Action:     "allow",
	}
	rule1V6 = &EveroutePolicyRule{
		RuleID:     "rule1v6",
		Priority:   200,
		IPProtocol: unix.IPPROTO_ICMPV6,
		IPFamily:   unix.AF_INET6,
		SrcIPAddr:  "2401::10:100:100:1",
		DstIPAddr:  "2401::10:100:100:2",
		Action:     "allow",
	}
	rule2 = &EveroutePolicyRule{
		RuleID:     "rule2",
		IPProtocol: uint8(17),
		IPFamily:   unix.AF_INET,
		SrcIPAddr:  "10.100.100.0/24",
		Action:     "deny",
	}
	rule3 = &EveroutePolicyRule{
		RuleID:     "rule3",
		IPProtocol: uint8(4),
		IPFamily:   unix.AF_INET,
		SrcIPAddr:  "10.100.100.0/24",
		DstIPAddr:  "10.23.1.90",
		Action:     "allow",
	}

	rule1Flow = `table=60, priority=200,icmp,nw_src=10.100.100.1,nw_dst=10.100.100.2 ` +
		`actions=load:0x->NXM_NX_XXREG0[60..87],load:0x->NXM_NX_XXREG0[0..3],goto_table:70`
	rule1v6Flow = `table=60, priority=200,icmp6,ipv6_src=2401::10:100:100:1,ipv6_dst=2401::10:100:100:2 ` +
		`actions=load:0x->NXM_NX_XXREG0[60..87],load:0x->NXM_NX_XXREG0[0..3],goto_table:70`
	rule2WorkModeFlow              = `table=20, priority=0,udp,nw_src=10.100.100.0/24 actions=load:0x->NXM_NX_XXREG0[60..87],load:0x->NXM_NX_XXREG0[0..3],load:0x->NXM_NX_XXREG0[5],load:0x->NXM_NX_XXREG0[127],load:0x20->NXM_NX_REG4[0..15],goto_table:70`
	ep1VlanInputFlow               = "table=0, priority=200,in_port=11 actions=push_vlan:0x8100,set_field:4097->vlan_vid,load:0x2->NXM_NX_PKT_MARK[17..18],load:0xb->NXM_NX_PKT_MARK[0..15],resubmit(,10),resubmit(,15)"
	ep1LocalToLocalFlow            = "table=5, priority=200,dl_vlan=1,dl_src=00:00:aa:aa:aa:aa actions=load:0xb->NXM_OF_IN_PORT[],load:0->NXM_OF_VLAN_TCI[0..12],NORMAL"
	ep2VlanInputFlow               = "table=0, priority=200,in_port=22,vlan_tci=0x1000/0x1000 actions=load:0x1->NXM_NX_REG3[0..1],load:0x2->NXM_NX_PKT_MARK[17..18],load:0x16->NXM_NX_PKT_MARK[0..15],resubmit(,1)"
	ep2VlanInputFlow1              = "table=0, priority=197,in_port=22 actions=load:0x2->NXM_NX_PKT_MARK[17..18],load:0x16->NXM_NX_PKT_MARK[0..15],resubmit(,10),resubmit(,15)"
	ep2VlanFilterFlow1             = "table=1, priority=200,in_port=22,dl_vlan=1 actions=resubmit(,10),resubmit(,15)"
	ep2VlanFilterFlow2             = "table=1, priority=200,in_port=22,vlan_tci=0x1002/0x1ffe actions=resubmit(,10),resubmit(,15)"
	vlanFilterDefaultFlow          = "table=1, priority=10 actions=drop"
	ep2LocalToLocalFlow            = "table=5, priority=200,dl_src=00:00:aa:aa:aa:bb actions=load:0x16->NXM_OF_IN_PORT[],NORMAL"
	newep2VlanInputFlow            = "table=0, priority=200,in_port=22 actions=push_vlan:0x8100,set_field:4097->vlan_vid,load:0x2->NXM_NX_PKT_MARK[17..18],load:0x16->NXM_NX_PKT_MARK[0..15],resubmit(,10),resubmit(,15)"
	newep2LocalToLocalFlow         = "table=5, priority=200,dl_vlan=1,dl_src=00:00:aa:aa:aa:bb actions=load:0x16->NXM_OF_IN_PORT[],load:0->NXM_OF_VLAN_TCI[0..12],NORMAL"
	fromLocalLearningFlow          = "table=10, priority=100 actions=learn(table=5,idle_timeout=300,hard_timeout=300,priority=203,NXM_OF_VLAN_TCI[0..11],NXM_OF_ETH_DST[]=NXM_OF_ETH_SRC[],load:0->NXM_OF_VLAN_TCI[0..12],output:NXM_OF_IN_PORT[])"
	fromLocalTrunkPortLearningFlow = "table=10, priority=103,reg3=0x1/0x3 actions=learn(table=5,idle_timeout=300,hard_timeout=300,priority=203,NXM_OF_VLAN_TCI[0..11],NXM_OF_ETH_DST[]=NXM_OF_ETH_SRC[],output:NXM_OF_IN_PORT[])"
	ep3VlanInputFlow1              = "table=0, priority=200,in_port=33 actions=load:0x1->NXM_NX_REG3[0..1],load:0x2->NXM_NX_PKT_MARK[17..18],load:0x21->NXM_NX_PKT_MARK[0..15],resubmit(,1)"
	ep3VlanFilterFlow1             = "table=1, priority=200,in_port=33,dl_vlan=1 actions=resubmit(,10),resubmit(,15)"
	ep3VlanFilterFlow2             = "table=1, priority=200,in_port=33,vlan_tci=0x1002/0x1ffe actions=resubmit(,10),resubmit(,15)"
	ctInputFlow                    = "table=0, priority=300,ip actions=move:NXM_OF_VLAN_TCI[0..11]->NXM_NX_REG4[16..27],load:0x8->NXM_NX_REG4[28..31],ct(table=1,zone=NXM_NX_REG4[16..31])"
	ctCommitFlow                   = "table=70, priority=200,ip,reg5=0x100/0x100 actions=ct(commit,table=71,zone=NXM_NX_REG4[16..31],exec(move:NXM_NX_XXREG0[126..127]->NXM_NX_CT_LABEL[126..127],move:NXM_NX_XXREG0[4..5]->NXM_NX_CT_LABEL[4..5],move:NXM_NX_XXREG0[32..87]->NXM_NX_CT_LABEL[32..87],move:NXM_NX_XXREG0[0..3]->NXM_NX_CT_LABEL[0..3],move:NXM_NX_PKT_MARK[17..18]->NXM_NX_CT_LABEL[88..89],move:NXM_NX_PKT_MARK[0..15]->NXM_NX_CT_LABEL[92..107],load:0->NXM_NX_CT_LABEL[90..91],load:0->NXM_NX_CT_LABEL[108..123],load:0x3->NXM_NX_CT_LABEL[124..125]))"
	ctDropMatchFlow                = "table=70, priority=300,ct_label=0x80000000000000000000000000000000/0x80000000000000000000000000000000,ip actions=load:0x20->NXM_NX_REG4[0..15],goto_table:71"
	ingressTier3MonitorDropFlow    = "table=59, priority=603,ct_label=0x40000000000000000000000000000000/0x40000000000000000000000000000000,ip actions=move:NXM_NX_CT_LABEL[0..3]->NXM_NX_XXREG0[0..3],move:NXM_NX_CT_LABEL[32..59]->NXM_NX_XXREG0[32..59],move:NXM_NX_CT_LABEL[126]->NXM_NX_XXREG0[126],goto_table:60"
	ingressTier3MonitorDefaultFlow = "table=59, priority=10 actions=move:NXM_NX_CT_LABEL[0..3]->NXM_NX_XXREG0[0..3],move:NXM_NX_CT_LABEL[32..59]->NXM_NX_XXREG0[32..59],move:NXM_NX_CT_LABEL[126]->NXM_NX_XXREG0[126],goto_table:60"

	policyCTStateTableFlows = []string{
		"table=1, priority=300,ct_state=+est-rel-rpl,ct_label=0/0xfffffff000000000000000 actions=goto_table:10",
		"table=1, priority=200,ct_state=-new+est actions=goto_table:69",
		"table=1, priority=200,ct_state=+rel+trk actions=goto_table:69",
		"table=1, priority=10,ip actions=goto_table:10",
		"table=1, priority=10,ipv6 actions=goto_table:10",
	}

	policyDirectionSelectionTableFlows = []string{
		"table=10, priority=200,in_port=1 actions=load:0x1->NXM_NX_REG5[8],goto_table:20",
		"table=10, priority=200,in_port=2 actions=load:0x1->NXM_NX_REG5[8],goto_table:50",
	}

	policyActionUpdateTableFlows = []string{
		"table=69, priority=200,ct_state=-rpl+trk,ct_label=0x30000000000000000000000000000020/0xb0000000000000000000000000000020,ip,in_port=2 actions=ct(commit,table=70,zone=NXM_NX_REG4[16..31],exec(move:NXM_NX_CT_LABEL[5]->NXM_NX_CT_LABEL[127],load:0->NXM_NX_CT_LABEL[60..87]))",
		"table=69, priority=200,ct_state=-rpl+trk,ct_label=0x30000000000000000000000000000020/0xb0000000000000000000000000000020,ipv6,in_port=2 actions=ct(commit,table=70,zone=NXM_NX_REG4[16..31],exec(move:NXM_NX_CT_LABEL[5]->NXM_NX_CT_LABEL[127],load:0->NXM_NX_CT_LABEL[60..87]))",
		"table=69, priority=200,ct_state=-rpl+trk,ct_label=0xb0000000000000000000000000000000/0xb0000000000000000000000000000020,ip,in_port=2 actions=ct(commit,table=70,zone=NXM_NX_REG4[16..31],exec(move:NXM_NX_CT_LABEL[5]->NXM_NX_CT_LABEL[127],load:0->NXM_NX_CT_LABEL[60..87]))",
		"table=69, priority=200,ct_state=-rpl+trk,ct_label=0xb0000000000000000000000000000000/0xb0000000000000000000000000000020,ipv6,in_port=2 actions=ct(commit,table=70,zone=NXM_NX_REG4[16..31],exec(move:NXM_NX_CT_LABEL[5]->NXM_NX_CT_LABEL[127],load:0->NXM_NX_CT_LABEL[60..87]))",
		"table=69, priority=200,ct_state=+rpl+trk,ct_label=0x30000000000000000000000000000020/0xb0000000000000000000000000000020,ip,in_port=1 actions=ct(commit,table=70,zone=NXM_NX_REG4[16..31],exec(move:NXM_NX_CT_LABEL[5]->NXM_NX_CT_LABEL[127],load:0->NXM_NX_CT_LABEL[60..87]))",
		"table=69, priority=200,ct_state=+rpl+trk,ct_label=0x30000000000000000000000000000020/0xb0000000000000000000000000000020,ipv6,in_port=1 actions=ct(commit,table=70,zone=NXM_NX_REG4[16..31],exec(move:NXM_NX_CT_LABEL[5]->NXM_NX_CT_LABEL[127],load:0->NXM_NX_CT_LABEL[60..87]))",
		"table=69, priority=200,ct_state=+rpl+trk,ct_label=0xb0000000000000000000000000000000/0xb0000000000000000000000000000020,ip,in_port=1 actions=ct(commit,table=70,zone=NXM_NX_REG4[16..31],exec(move:NXM_NX_CT_LABEL[5]->NXM_NX_CT_LABEL[127],load:0->NXM_NX_CT_LABEL[60..87]))",
		"table=69, priority=200,ct_state=+rpl+trk,ct_label=0xb0000000000000000000000000000000/0xb0000000000000000000000000000020,ipv6,in_port=1 actions=ct(commit,table=70,zone=NXM_NX_REG4[16..31],exec(move:NXM_NX_CT_LABEL[5]->NXM_NX_CT_LABEL[127],load:0->NXM_NX_CT_LABEL[60..87]))",
		"table=69, priority=200,ct_state=-rpl+trk,ct_label=0x30000000000000000000000000000010/0xb0000000000000000000000000000010,ip,in_port=1 actions=ct(commit,table=70,zone=NXM_NX_REG4[16..31],exec(move:NXM_NX_CT_LABEL[4]->NXM_NX_CT_LABEL[127],load:0->NXM_NX_CT_LABEL[60..87]))",
		"table=69, priority=200,ct_state=-rpl+trk,ct_label=0x30000000000000000000000000000010/0xb0000000000000000000000000000010,ipv6,in_port=1 actions=ct(commit,table=70,zone=NXM_NX_REG4[16..31],exec(move:NXM_NX_CT_LABEL[4]->NXM_NX_CT_LABEL[127],load:0->NXM_NX_CT_LABEL[60..87]))",
		"table=69, priority=200,ct_state=-rpl+trk,ct_label=0xb0000000000000000000000000000000/0xb0000000000000000000000000000010,ip,in_port=1 actions=ct(commit,table=70,zone=NXM_NX_REG4[16..31],exec(move:NXM_NX_CT_LABEL[4]->NXM_NX_CT_LABEL[127],load:0->NXM_NX_CT_LABEL[60..87]))",
		"table=69, priority=200,ct_state=-rpl+trk,ct_label=0xb0000000000000000000000000000000/0xb0000000000000000000000000000010,ipv6,in_port=1 actions=ct(commit,table=70,zone=NXM_NX_REG4[16..31],exec(move:NXM_NX_CT_LABEL[4]->NXM_NX_CT_LABEL[127],load:0->NXM_NX_CT_LABEL[60..87]))",
		"table=69, priority=200,ct_state=+rpl+trk,ct_label=0x30000000000000000000000000000010/0xb0000000000000000000000000000010,ip,in_port=2 actions=ct(commit,table=70,zone=NXM_NX_REG4[16..31],exec(move:NXM_NX_CT_LABEL[4]->NXM_NX_CT_LABEL[127],load:0->NXM_NX_CT_LABEL[60..87]))",
		"table=69, priority=200,ct_state=+rpl+trk,ct_label=0x30000000000000000000000000000010/0xb0000000000000000000000000000010,ipv6,in_port=2 actions=ct(commit,table=70,zone=NXM_NX_REG4[16..31],exec(move:NXM_NX_CT_LABEL[4]->NXM_NX_CT_LABEL[127],load:0->NXM_NX_CT_LABEL[60..87]))",
		"table=69, priority=200,ct_state=+rpl+trk,ct_label=0xb0000000000000000000000000000000/0xb0000000000000000000000000000010,ip,in_port=2 actions=ct(commit,table=70,zone=NXM_NX_REG4[16..31],exec(move:NXM_NX_CT_LABEL[4]->NXM_NX_CT_LABEL[127],load:0->NXM_NX_CT_LABEL[60..87]))",
		"table=69, priority=200,ct_state=+rpl+trk,ct_label=0xb0000000000000000000000000000000/0xb0000000000000000000000000000010,ipv6,in_port=2 actions=ct(commit,table=70,zone=NXM_NX_REG4[16..31],exec(move:NXM_NX_CT_LABEL[4]->NXM_NX_CT_LABEL[127],load:0->NXM_NX_CT_LABEL[60..87]))",
		"table=69, priority=100,ct_state=+new+trk actions=load:0x1->NXM_NX_REG5[8],goto_table:50",
		"table=69, priority=10 actions=goto_table:70",
	}
)

func TestMain(m *testing.M) {
	setupEverouteDp()
	setupOverlayDp()
	exitCode := m.Run()
	teardownEverouteDp()
	teardownOverlayDp()
	os.Exit(exitCode)
}

func setupEverouteDp() {
	if err := ExcuteCommand(SetupBridgeChain, "ovsbr0"); err != nil {
		log.Fatalf("Failed to setup bridgechain, error: %v", err)
	}

	ctrl.SetLogger(klog.Background())
	datapathManager = NewDatapathManager(&datapathConfig, endpointIPChan, metrics.NewAgentMetric())
	datapathManager.InitializeDatapath(ctx)
}

func setupOverlayDp() {
	if err := ExcuteCommand(SetupBridgeChain, cniBrName); err != nil {
		log.Fatalf("Failed to setup bridgechain, error: %v", err)
	}
	if err := ExcuteCommand(SetupCNIBridgeChain, cniBrName); err != nil {
		log.Fatalf("Failed to setup cni bridgechain, error: %v", err)
	}
	if err := ExcuteCommand(SetupTunnelBridgeChain, cniBrName); err != nil {
		log.Fatalf("Failed to setup tunnel bridgechain, error: %v", err)
	}

	var err error
	cniDpMgr, err = InitCNIDpMgrUT(ctx, cniBrName, false, true, false)
	if err != nil || cniDpMgr == nil {
		log.Fatalf("Failed to init cni dp mgr, err: %v", err)
	}
}

func teardownEverouteDp() {
	_ = ExcuteCommand(CleanBridgeChain, "ovsbr0")
}

func teardownOverlayDp() {
	_ = ExcuteCommand(CleanBridgeChain, cniBrName)
}

func TestOverlayDp(t *testing.T) {
	testLocalEndpointOverlay(t)
}

func TestEverouteDp(t *testing.T) {
	var err error
	if defaultFlowList, err = dumpAllFlows(); err != nil {
		log.Fatalf("Failed to dump default flow while test env setup")
	}
	RegisterTestingT(t)

	t.Run("validate local endpoint learning flow", func(t *testing.T) {
		Eventually(func() error {
			return flowValidator([]string{fromLocalLearningFlow, fromLocalTrunkPortLearningFlow, vlanFilterDefaultFlow})
		}, timeout, interval).Should(Succeed())
	})

	testLocalEndpoint(t)

	testERPolicyRule(t)
	testPolicyTableInit(t)
	testMonitorRule(t)
	testFlowReplay(t)
	testRoundNumFlip(t)
	testHandleEndpointIPTimeout(t)

	testUplinkBridgeMarkFlows(t)
	// test local bridge mark flows in "validate local endpoint forwarding flow add"
	TestPolicyBridgeFlows(t)
}

func testLocalEndpoint(t *testing.T) {
	RegisterTestingT(t)

	t.Run("Test add local endpoint", func(t *testing.T) {
		if err := datapathManager.AddLocalEndpoint(ep1); err != nil {
			t.Errorf("Failed to add local endpoint %v, error: %v", ep1, err)
		}
		if ep, _ := datapathManager.localEndpointDB.Get(ep1.InterfaceUUID); ep == nil {
			t.Errorf("Failed to add local endpoint, endpoint %v not found", ep1)
		}

		if err := datapathManager.UpdateLocalEndpoint(newep1, ep1); err != nil {
			t.Errorf("Failed to udpate local endpoint: from %v to %v, error: %v", ep1, newep1, err)
		}
		ep, _ := datapathManager.localEndpointDB.Get(ep1.InterfaceUUID)
		if ep == nil {
			t.Errorf("Failed to update local endpoint, null endpoint %v", ep1)
		}
		endpoint := ep.(*Endpoint)
		if endpoint.PortNo != newep1.PortNo {
			t.Errorf("Failed to update local endpoint ofport from %v to %v", ep1.PortNo, newep1.PortNo)
		}
		if err := datapathManager.RemoveLocalEndpoint(newep1); err != nil {
			t.Errorf("Failed to remove local endpoint %v, error: %v", newep1, err)
		}
		if ep, _ := datapathManager.localEndpointDB.Get(newep1.InterfaceUUID); ep != nil {
			t.Errorf("Failed to remove local endpoint, endpoint %v in cache", newep1)
		}
	})

	if err := datapathManager.AddLocalEndpoint(ep2); err != nil {
		t.Errorf("Failed to add local endpoint %v, error: %v", ep2, err)
	}
	t.Run("validate local endpoint forwarding flow add", func(t *testing.T) {
		Eventually(func() error {
			return flowValidator([]string{ep2LocalToLocalFlow, ep2VlanInputFlow, ep2VlanInputFlow1, ep2VlanFilterFlow1, ep2VlanFilterFlow2})
		}, timeout, interval).Should(Succeed())
	})

	if err := datapathManager.UpdateLocalEndpoint(newep2, ep2); err != nil {
		t.Errorf("Failed to udpate local endpoint: from %v to %v, error: %v", ep2, newep2, err)
	}
	t.Run("validate local endpoint forwarding flow update", func(t *testing.T) {
		Eventually(func() error {
			return flowValidator([]string{newep2LocalToLocalFlow, newep2VlanInputFlow})
		}, timeout, interval).Should(Succeed())
	})

	if err := datapathManager.RemoveLocalEndpoint(newep2); err != nil {
		t.Errorf("Failed to remove local endpoint %v, error: %v", newep2, err)
	}
	if ep, _ := datapathManager.localEndpointDB.Get(newep2.InterfaceName); ep != nil {
		t.Errorf("Failed to remove local endpoint, endpoint %v in cache", newep2)
	}

	if err := datapathManager.AddLocalEndpoint(ep3); err != nil {
		t.Errorf("Failed to add local endpoint %v, error: %v", ep3, err)
	}
	t.Run("validate local endpoint forwarding flow add", func(t *testing.T) {
		Eventually(func() error {
			return flowValidator([]string{ep3VlanInputFlow1, ep3VlanFilterFlow1, ep3VlanFilterFlow2})
		}, timeout, interval).Should(Succeed())
	})
}

func testERPolicyRule(t *testing.T) {
	t.Run("check policy rule work mode", func(t *testing.T) {
		baseInfo := RuleBaseInfo{
			Ref:       PolicyRuleRef{Policy: "policy1", Rule: "rule1"},
			Tier:      POLICY_TIER2,
			Direction: POLICY_DIRECTION_IN,
			Mode:      DEFAULT_POLICY_ENFORCEMENT_MODE,
		}
		if err := datapathManager.AddEveroutePolicyRule(ctx, rule1, baseInfo); err != nil {
			t.Errorf("Failed to add ER policy rule: %v, error: %v", rule1, err)
		}
		if _, ok := datapathManager.Rules[rule1.RuleID]; !ok {
			t.Errorf("Failed to add ER policy rule, not found %v in cache", rule1)
		}
		if datapathManager.policyRuleNums["policy1"] != 1 {
			t.Errorf("Failed to update policyruleNums for rule %v", rule1)
		}

		if err := datapathManager.RemoveEveroutePolicyRule(ctx, rule1.RuleID, baseInfo); err != nil {
			t.Errorf("Failed to remove ER policy rule: %v, error: %v", rule1, err)
		}
		if _, ok := datapathManager.Rules[rule1.RuleID]; ok {
			t.Errorf("Failed to remove ER policy rule %v in cache", rule1)
		}
		if _, ok := datapathManager.policyRuleNums["policy1"]; ok {
			t.Errorf("Failed to update policyruleNums for rule %v", rule1)
		}

		// test rule1 with ipv6
		baseInfo.Ref.Rule = "rule1v6"
		if err := datapathManager.AddEveroutePolicyRule(ctx, rule1V6, baseInfo); err != nil {
			t.Errorf("Failed to add ER policy rule: %v, error: %v", rule1V6, err)
		}
		if _, ok := datapathManager.Rules[rule1V6.RuleID]; !ok {
			t.Errorf("Failed to add ER policy rule, not found %v in cache", rule1V6)
		}
		if datapathManager.policyRuleNums["policy1"] != 1 {
			t.Errorf("Failed to update policyruleNums for rule %v", rule1V6)
		}

		if err := datapathManager.RemoveEveroutePolicyRule(ctx, rule1V6.RuleID, baseInfo); err != nil {
			t.Errorf("Failed to remove ER policy rule: %v, error: %v", rule1V6, err)
		}
		if _, ok := datapathManager.Rules[rule1V6.RuleID]; ok {
			t.Errorf("Failed to remove ER policy rule %v in cache", rule1V6)
		}
		if _, ok := datapathManager.policyRuleNums["policy1"]; ok {
			t.Errorf("Failed to update policyruleNums for rule %v", rule1V6)
		}

		baseInfo = RuleBaseInfo{
			Ref:       PolicyRuleRef{Policy: "policy2", Rule: "rule2"},
			Tier:      POLICY_TIER1,
			Direction: POLICY_DIRECTION_OUT,
			Mode:      DEFAULT_POLICY_ENFORCEMENT_MODE,
		}
		if err := datapathManager.AddEveroutePolicyRule(ctx, rule2, baseInfo); err != nil {
			t.Errorf("Failed to add ER policy rule: %v, error: %v", rule2, err)
		}
		if _, ok := datapathManager.Rules[rule2.RuleID]; !ok {
			t.Errorf("Failed to add ER policy rule, not found %v in cache", rule2)
		}
		if datapathManager.policyRuleNums["policy2"] != 1 {
			t.Errorf("Failed to update policyruleNums for rule %v", rule2)
		}
		if err := datapathManager.AddEveroutePolicyRule(ctx, rule2, baseInfo); err != nil {
			t.Errorf("Failed to add ER policy rule: %v, error: %v", rule2, err)
		}
		if datapathManager.policyRuleNums["policy2"] != 1 {
			t.Errorf("Failed to update policyruleNums for rule %v", rule2)
		}
		Eventually(func() error {
			return flowValidator([]string{rule2WorkModeFlow})
		}, timeout, interval).ShouldNot(HaveOccurred())

		baseInfo = RuleBaseInfo{
			Ref:       PolicyRuleRef{Policy: "policy2", Rule: "rule3"},
			Tier:      POLICY_TIER_ECP,
			Direction: POLICY_DIRECTION_IN,
			Mode:      DEFAULT_POLICY_ENFORCEMENT_MODE,
		}
		if err := datapathManager.AddEveroutePolicyRule(ctx, rule3, baseInfo); err != nil {
			t.Errorf("Failed to add ER policy rule: %v, error: %v", rule3, err)
		}
		if _, ok := datapathManager.Rules[rule3.RuleID]; !ok {
			t.Errorf("Failed to add ER policy rule, not found %v in cache", rule3)
		}
		if datapathManager.policyRuleNums["policy2"] != 2 {
			t.Errorf("Failed to update policyruleNums for rule %v", rule3)
		}
		if err := datapathManager.RemoveEveroutePolicyRule(ctx, rule3.RuleID, baseInfo); err != nil {
			t.Errorf("Failed to remove ER policy rule: %v, error: %v", rule3, err)
		}
		if _, ok := datapathManager.Rules[rule3.RuleID]; ok {
			t.Errorf("Failed to remove ER policy rule %v in cache", rule3)
		}
		if _, ok := datapathManager.policyRuleNums["policy3"]; ok {
			t.Errorf("Failed to update policyruleNums for rule %v", rule3)
		}
		if datapathManager.policyRuleNums["policy2"] != 1 {
			t.Errorf("Failed to update policyruleNums for rule %v", rule3)
		}
	})

	t.Run("check policy rule monitor mode", func(t *testing.T) {
		RegisterTestingT(t)

		t.Run("tier1 without monitor mode support", func(t *testing.T) {
			rule := &EveroutePolicyRule{
				RuleID:     rand.String(20),
				Priority:   rand.IntnRange(DEFAULT_FLOW_MISS_PRIORITY, HIGH_MATCH_FLOW_PRIORITY),
				SrcIPAddr:  randomIP(),
				DstIPAddr:  randomIP(),
				IPProtocol: uint8(rand.IntnRange(20, 254)),
				IPFamily:   unix.AF_INET,
				SrcPort:    uint16(rand.IntnRange(1, 65534)),
				DstPort:    uint16(rand.IntnRange(1, 65534)),
				Action:     "allow",
			}
			baseInfo := RuleBaseInfo{
				Ref:       PolicyRuleRef{Policy: "policy1", Rule: rule.RuleID},
				Direction: POLICY_DIRECTION_IN,
				Tier:      POLICY_TIER1,
				Mode:      "monitor",
			}
			err := datapathManager.AddEveroutePolicyRule(ctx, rule, baseInfo)
			Expect(err).Should(HaveOccurred())

			rule.IPFamily = unix.AF_INET6
			rule.SrcIPAddr = randomIPv6()
			rule.DstIPAddr = randomIPv6()

			err = datapathManager.AddEveroutePolicyRule(ctx, rule, baseInfo)
			Expect(err).Should(HaveOccurred())
		})

		t.Run("should add tier2 monitor policy rule", func(t *testing.T) {
			rule := &EveroutePolicyRule{
				RuleID:     rand.String(20),
				Priority:   rand.IntnRange(DEFAULT_FLOW_MISS_PRIORITY, HIGH_MATCH_FLOW_PRIORITY),
				SrcIPAddr:  randomIP(),
				DstIPAddr:  randomIP(),
				IPProtocol: uint8(rand.IntnRange(20, 254)),
				IPFamily:   unix.AF_INET,
				SrcPort:    uint16(rand.IntnRange(1, 65534)),
				DstPort:    uint16(rand.IntnRange(1, 65534)),
				Action:     "allow",
			}
			baseInfo := RuleBaseInfo{
				Ref:       PolicyRuleRef{Policy: "policy1", Rule: rule.RuleID},
				Direction: POLICY_DIRECTION_IN,
				Tier:      POLICY_TIER2,
				Mode:      "monitor",
			}
			err := datapathManager.AddEveroutePolicyRule(ctx, rule, baseInfo)
			Expect(err).ShouldNot(HaveOccurred())

			ruleV6 := rule.DeepCopy()
			ruleV6.IPFamily = unix.AF_INET6
			ruleV6.SrcIPAddr = randomIPv6()
			ruleV6.DstIPAddr = randomIPv6()
			err = datapathManager.AddEveroutePolicyRule(ctx, ruleV6, baseInfo)
			Expect(err).ShouldNot(HaveOccurred())

			Eventually(func() error {
				return flowValidator([]string{
					fmt.Sprintf("table=54, priority=%d,ip,nw_src=%s,nw_dst=%s,nw_proto=%d actions=load:0x->NXM_NX_XXREG0[0..3],goto_table:55", rule.Priority, rule.SrcIPAddr, rule.DstIPAddr, rule.IPProtocol),
					fmt.Sprintf("table=54, priority=%d,ipv6,ipv6_src=%s,ipv6_dst=%s,nw_proto=%d actions=load:0x->NXM_NX_XXREG0[0..3],goto_table:55", ruleV6.Priority, ruleV6.SrcIPAddr, ruleV6.DstIPAddr, ruleV6.IPProtocol),
				})
			}, timeout, interval).ShouldNot(HaveOccurred())
			err = datapathManager.RemoveEveroutePolicyRule(ctx, rule.RuleID, baseInfo)
			Expect(err).ShouldNot(HaveOccurred())
			err = datapathManager.RemoveEveroutePolicyRule(ctx, ruleV6.RuleID, baseInfo)
			Expect(err).ShouldNot(HaveOccurred())
		})

		t.Run("should add tier2 monitor policy rule icmp with type", func(t *testing.T) {
			rule := &EveroutePolicyRule{
				RuleID:         rand.String(20),
				Priority:       rand.IntnRange(DEFAULT_FLOW_MISS_PRIORITY, HIGH_MATCH_FLOW_PRIORITY),
				SrcIPAddr:      randomIP(),
				DstIPAddr:      randomIP(),
				IPProtocol:     PROTOCOL_ICMP,
				IPFamily:       unix.AF_INET,
				Action:         "allow",
				IcmpType:       3,
				IcmpTypeEnable: true,
			}
			baseInfo := RuleBaseInfo{
				Ref: PolicyRuleRef{
					Policy: "policy",
					Rule:   rule.RuleID,
				},
				Direction: POLICY_DIRECTION_IN,
				Tier:      POLICY_TIER2,
				Mode:      "monitor",
			}
			err := datapathManager.AddEveroutePolicyRule(ctx, rule, baseInfo)
			Expect(err).ShouldNot(HaveOccurred())

			ruleV6 := rule.DeepCopy()
			ruleV6.IPFamily = unix.AF_INET6
			ruleV6.IPProtocol = unix.IPPROTO_ICMPV6
			ruleV6.IcmpTypeEnable = false
			ruleV6.IcmpType = 0
			ruleV6.SrcIPAddr = randomIPv6()
			ruleV6.DstIPAddr = randomIPv6()
			err = datapathManager.AddEveroutePolicyRule(ctx, ruleV6, baseInfo)
			Expect(err).ShouldNot(HaveOccurred())

			Eventually(func() error {
				return flowValidator([]string{
					fmt.Sprintf("table=54, priority=%d,icmp,nw_src=%s,nw_dst=%s,icmp_type=%d actions=load:0x->NXM_NX_XXREG0[0..3],goto_table:55", rule.Priority, rule.SrcIPAddr, rule.DstIPAddr, rule.IcmpType),
					fmt.Sprintf("table=54, priority=%d,icmp6,ipv6_src=%s,ipv6_dst=%s actions=load:0x->NXM_NX_XXREG0[0..3],goto_table:55", ruleV6.Priority, ruleV6.SrcIPAddr, ruleV6.DstIPAddr),
				})
			}, timeout, interval).ShouldNot(HaveOccurred())
			err = datapathManager.RemoveEveroutePolicyRule(ctx, rule.RuleID, baseInfo)
			Expect(err).ShouldNot(HaveOccurred())
			err = datapathManager.RemoveEveroutePolicyRule(ctx, ruleV6.RuleID, baseInfo)
			Expect(err).ShouldNot(HaveOccurred())
		})

		t.Run("should add tier3 monitor policy rule with allow", func(t *testing.T) {
			rule := &EveroutePolicyRule{
				RuleID:     rand.String(20),
				Priority:   rand.IntnRange(DEFAULT_FLOW_MISS_PRIORITY, HIGH_MATCH_FLOW_PRIORITY),
				SrcIPAddr:  randomIP(),
				DstIPAddr:  randomIP(),
				IPProtocol: uint8(rand.IntnRange(20, 254)),
				IPFamily:   unix.AF_INET,
				SrcPort:    uint16(rand.IntnRange(1, 65534)),
				DstPort:    uint16(rand.IntnRange(1, 65534)),
				Action:     "allow",
			}
			baseInfo := RuleBaseInfo{
				Ref:       PolicyRuleRef{Policy: "policy1", Rule: rule.RuleID},
				Direction: POLICY_DIRECTION_IN,
				Tier:      POLICY_TIER3,
				Mode:      "monitor",
			}
			err := datapathManager.AddEveroutePolicyRule(ctx, rule, baseInfo)
			Expect(err).ShouldNot(HaveOccurred())

			ruleV6 := rule.DeepCopy()
			ruleV6.IPFamily = unix.AF_INET6
			ruleV6.SrcIPAddr = randomIPv6()
			ruleV6.DstIPAddr = randomIPv6()
			err = datapathManager.AddEveroutePolicyRule(ctx, ruleV6, baseInfo)
			Expect(err).ShouldNot(HaveOccurred())

			Eventually(func() error {
				return flowValidator([]string{
					fmt.Sprintf("table=59, priority=%d,ip,nw_src=%s,nw_dst=%s,nw_proto=%d actions=load:0x->NXM_NX_XXREG0[32..59],load:0x->NXM_NX_XXREG0[0..3],goto_table:60", rule.Priority, rule.SrcIPAddr, rule.DstIPAddr, rule.IPProtocol),
					fmt.Sprintf("table=59, priority=%d,ipv6,ipv6_src=%s,ipv6_dst=%s,nw_proto=%d actions=load:0x->NXM_NX_XXREG0[32..59],load:0x->NXM_NX_XXREG0[0..3],goto_table:60", ruleV6.Priority, ruleV6.SrcIPAddr, ruleV6.DstIPAddr, ruleV6.IPProtocol),
				})
			}, timeout, interval).ShouldNot(HaveOccurred())
			err = datapathManager.RemoveEveroutePolicyRule(ctx, rule.RuleID, baseInfo)
			Expect(err).ShouldNot(HaveOccurred())
			err = datapathManager.RemoveEveroutePolicyRule(ctx, ruleV6.RuleID, baseInfo)
			Expect(err).ShouldNot(HaveOccurred())
		})

		t.Run("should add tier3 monitor policy rule with deny on ingress", func(t *testing.T) {
			rule := &EveroutePolicyRule{
				RuleID:     rand.String(20),
				Priority:   rand.IntnRange(DEFAULT_FLOW_MISS_PRIORITY, HIGH_MATCH_FLOW_PRIORITY),
				SrcIPAddr:  randomIP(),
				DstIPAddr:  randomIP(),
				IPProtocol: uint8(rand.IntnRange(20, 254)),
				IPFamily:   unix.AF_INET,
				SrcPort:    uint16(rand.IntnRange(1, 65534)),
				DstPort:    uint16(rand.IntnRange(1, 65534)),
				Action:     "deny",
			}
			baseInfo := RuleBaseInfo{
				Ref:       PolicyRuleRef{Policy: "policy1", Rule: rule.RuleID},
				Direction: POLICY_DIRECTION_IN,
				Tier:      POLICY_TIER3,
				Mode:      "monitor",
			}
			err := datapathManager.AddEveroutePolicyRule(ctx, rule, baseInfo)
			Expect(err).ShouldNot(HaveOccurred())

			ruleV6 := rule.DeepCopy()
			ruleV6.IPFamily = unix.AF_INET6
			ruleV6.SrcIPAddr = randomIPv6()
			ruleV6.DstIPAddr = randomIPv6()
			err = datapathManager.AddEveroutePolicyRule(ctx, ruleV6, baseInfo)
			Expect(err).ShouldNot(HaveOccurred())

			Eventually(func() error {
				return flowValidator([]string{
					fmt.Sprintf("table=59, priority=%d,ip,nw_src=%s,nw_dst=%s,nw_proto=%d actions=load:0x->NXM_NX_XXREG0[32..59],load:0x->NXM_NX_XXREG0[126],load:0x->NXM_NX_XXREG0[0..3],goto_table:60", rule.Priority, rule.SrcIPAddr, rule.DstIPAddr, rule.IPProtocol),
					fmt.Sprintf("table=59, priority=%d,ipv6,ipv6_src=%s,ipv6_dst=%s,nw_proto=%d actions=load:0x->NXM_NX_XXREG0[32..59],load:0x->NXM_NX_XXREG0[126],load:0x->NXM_NX_XXREG0[0..3],goto_table:60", ruleV6.Priority, ruleV6.SrcIPAddr, ruleV6.DstIPAddr, ruleV6.IPProtocol),
				})
			}, timeout, interval).ShouldNot(HaveOccurred())
			err = datapathManager.RemoveEveroutePolicyRule(ctx, rule.RuleID, baseInfo)
			Expect(err).ShouldNot(HaveOccurred())
			err = datapathManager.RemoveEveroutePolicyRule(ctx, ruleV6.RuleID, baseInfo)
			Expect(err).ShouldNot(HaveOccurred())
		})

		t.Run("should add tier3 monitor policy rule with deny on egress", func(t *testing.T) {
			rule := &EveroutePolicyRule{
				RuleID:     rand.String(20),
				Priority:   rand.IntnRange(DEFAULT_FLOW_MISS_PRIORITY, HIGH_MATCH_FLOW_PRIORITY),
				SrcIPAddr:  randomIP(),
				DstIPAddr:  randomIP(),
				IPProtocol: uint8(rand.IntnRange(20, 254)),
				IPFamily:   unix.AF_INET,
				SrcPort:    uint16(rand.IntnRange(1, 65534)),
				DstPort:    uint16(rand.IntnRange(1, 65534)),
				Action:     "deny",
			}
			baseInfo := RuleBaseInfo{
				Ref:       PolicyRuleRef{Policy: "policy1", Rule: rule.RuleID},
				Direction: POLICY_DIRECTION_OUT,
				Tier:      POLICY_TIER3,
				Mode:      "monitor",
			}
			err := datapathManager.AddEveroutePolicyRule(ctx, rule, baseInfo)
			Expect(err).ShouldNot(HaveOccurred())

			ruleV6 := rule.DeepCopy()
			ruleV6.IPFamily = unix.AF_INET6
			ruleV6.SrcIPAddr = randomIPv6()
			ruleV6.DstIPAddr = randomIPv6()
			err = datapathManager.AddEveroutePolicyRule(ctx, ruleV6, baseInfo)
			Expect(err).ShouldNot(HaveOccurred())

			Eventually(func() error {
				return flowValidator([]string{
					fmt.Sprintf("table=29, priority=%d,ip,nw_src=%s,nw_dst=%s,nw_proto=%d actions=load:0x->NXM_NX_XXREG0[32..59],load:0x->NXM_NX_XXREG0[126],load:0x->NXM_NX_XXREG0[0..3],goto_table:30", rule.Priority, rule.SrcIPAddr, rule.DstIPAddr, rule.IPProtocol),
					fmt.Sprintf("table=29, priority=%d,ipv6,ipv6_src=%s,ipv6_dst=%s,nw_proto=%d actions=load:0x->NXM_NX_XXREG0[32..59],load:0x->NXM_NX_XXREG0[126],load:0x->NXM_NX_XXREG0[0..3],goto_table:30", ruleV6.Priority, ruleV6.SrcIPAddr, ruleV6.DstIPAddr, ruleV6.IPProtocol),
				})
			}, timeout, interval).ShouldNot(HaveOccurred())
			err = datapathManager.RemoveEveroutePolicyRule(ctx, rule.RuleID, baseInfo)
			Expect(err).ShouldNot(HaveOccurred())
			err = datapathManager.RemoveEveroutePolicyRule(ctx, ruleV6.RuleID, baseInfo)
			Expect(err).ShouldNot(HaveOccurred())
		})
	})
}

func testPolicyTableInit(t *testing.T) {
	t.Run("check policy table init flow", func(t *testing.T) {
		Eventually(func() error {
			return flowValidator([]string{
				ctInputFlow,
				ctCommitFlow,
				ctDropMatchFlow,
				ingressTier3MonitorDropFlow,
				ingressTier3MonitorDefaultFlow})
		}, timeout, interval).Should(Succeed())
	})
}

func testMonitorRule(t *testing.T) {
	t.Run("test ER policy rule with monitor mode", func(t *testing.T) {
		baseInfo := RuleBaseInfo{
			Ref:       PolicyRuleRef{Policy: "policy3", Rule: "rule1"},
			Direction: POLICY_DIRECTION_IN,
			Tier:      POLICY_TIER2,
			Mode:      v1alpha1.MonitorMode.String(),
		}
		if err := datapathManager.AddEveroutePolicyRule(ctx, rule1, baseInfo); err != nil {
			t.Errorf("Failed to add ER policy rule: %v, error: %v", rule1, err)
		}
		if _, ok := datapathManager.Rules[rule1.RuleID]; !ok {
			t.Errorf("Failed to add ER policy rule, not found %v in cache", rule1)
		}
		if datapathManager.policyRuleNums["policy3"] != 1 {
			t.Errorf("Failed to update policyruleNums for rule %v", rule1)
		}

		if err := datapathManager.RemoveEveroutePolicyRule(ctx, rule1.RuleID, baseInfo); err != nil {
			t.Errorf("Failed to remove ER policy rule: %v, error: %v", rule1, err)
		}
		if _, ok := datapathManager.Rules[rule1.RuleID]; ok {
			t.Errorf("Failed to remove ER policy rule, not found %v in cache", rule1)
		}
		if datapathManager.policyRuleNums["policy3"] != 0 {
			t.Errorf("Failed to update policyruleNums for rule %v", rule1)
		}

		baseInfo = RuleBaseInfo{
			Ref:       PolicyRuleRef{Policy: "policy3", Rule: "rule2"},
			Direction: POLICY_DIRECTION_OUT,
			Tier:      POLICY_TIER1,
			Mode:      v1alpha1.MonitorMode.String(),
		}
		if err := datapathManager.AddEveroutePolicyRule(ctx, rule2, baseInfo); err != nil {
			t.Errorf("Failed to add ER policy rule: %v, error: %v", rule2, err)
		}
		if _, ok := datapathManager.Rules[rule2.RuleID]; !ok {
			t.Errorf("Failed to add ER policy rule, not found %v in cache", rule2)
		}
		if datapathManager.policyRuleNums["policy3"] != 1 {
			t.Errorf("Failed to update policyruleNums for rule %v", rule2)
		}
		if err := datapathManager.AddEveroutePolicyRule(ctx, rule2, baseInfo); err != nil {
			t.Errorf("Failed to add ER policy rule: %v, error: %v", rule2, err)
		}
	})
}

func testFlowReplay(t *testing.T) {
	RegisterTestingT(t)

	if err := datapathManager.AddLocalEndpoint(ep1); err != nil {
		t.Errorf("Failed to add local endpoint %v, error: %v", ep1, err)
	}
	t.Run("add ER policy rule", func(t *testing.T) {
		Eventually(func() error {
			log.Infof("add policy rule to datapath, tier: %d", POLICY_TIER3)
			baseInfo := RuleBaseInfo{
				Ref:       PolicyRuleRef{Policy: "policy5", Rule: "rule1"},
				Direction: POLICY_DIRECTION_IN,
				Tier:      POLICY_TIER3,
				Mode:      DEFAULT_POLICY_ENFORCEMENT_MODE,
			}
			return datapathManager.AddEveroutePolicyRule(ctx, rule1, baseInfo)
		}, timeout, interval).Should(Succeed())
	})

	t.Run("add ER policy rule v6", func(t *testing.T) {
		Eventually(func() error {
			log.Infof("add policy rule to datapath, tier: %d", POLICY_TIER3)
			baseInfo := RuleBaseInfo{
				Ref:       PolicyRuleRef{Policy: "policy5", Rule: "rule1v6"},
				Direction: POLICY_DIRECTION_IN,
				Tier:      POLICY_TIER3,
				Mode:      DEFAULT_POLICY_ENFORCEMENT_MODE,
			}
			return datapathManager.AddEveroutePolicyRule(ctx, rule1V6, baseInfo)
		}, timeout, interval).Should(Succeed())
	})

	t.Run("restart ovs-vswitchd", func(t *testing.T) {
		Eventually(func() error {
			err := restartOvsVswitchd(ovsVswitchdRestartInterval)
			return err
		}, time.Second*2, time.Second*1).Should(Succeed())
	})

	t.Run("validate default Flow replay", func(t *testing.T) {
		Eventually(func() error {
			return flowValidator(defaultFlowList)
		}, timeout, interval).Should(Succeed())
	})

	t.Run("validate local endpoint flow replay", func(t *testing.T) {
		Eventually(func() error {
			return flowValidator([]string{ep1LocalToLocalFlow, ep1VlanInputFlow})
		}, timeout, interval).Should(Succeed())
	})

	t.Run("validate ER policyrule flow replay", func(t *testing.T) {
		Eventually(func() error {
			return flowValidator([]string{rule1Flow})
		}, timeout, interval).Should(Succeed())
	})

	t.Run("validate ER policyrule flow replay v6", func(t *testing.T) {
		Eventually(func() error {
			return flowValidator([]string{rule1v6Flow})
		}, timeout, interval).Should(Succeed())
	})
}

func testRoundNumFlip(t *testing.T) {
	roundInfo := RoundInfo{
		curRoundNum:      MaxRoundNum,
		previousRoundNum: MaxRoundNum - 1,
	}

	t.Run("persistentRoundInfo into local bridge", func(t *testing.T) {
		Eventually(func() error {
			return persistentRoundInfo(roundInfo.curRoundNum, datapathManager.OvsdbDriverMap["ovsbr0"][LOCAL_BRIDGE_KEYWORD])
		}, timeout, interval).Should(Succeed())
	})

	t.Run("validate ER agent Round num flip", func(t *testing.T) {
		Eventually(func() bool {
			round, _ := getRoundInfo(datapathManager.OvsdbDriverMap["ovsbr0"][LOCAL_BRIDGE_KEYWORD])
			return round.curRoundNum == 1
		}, timeout, interval).Should(BeTrue())
	})
}

func testHandleEndpointIPTimeout(t *testing.T) {
	RegisterTestingT(t)

	testEndpointIPTimeout := func(ip string) func() {
		return func() {
			endpointIP := mustAddEndpoint(rand.String(10), net.ParseIP(ip))
			endpointIP.Mac, _ = net.ParseMAC(FACK_MAC)
			Expect(datapathManager.HandleEndpointIPTimeout(context.Background(), endpointIP)).ShouldNot(HaveOccurred())

			Eventually(func() bool {
				for {
					select {
					case learnEndpointIP := <-endpointIPChan:
						if learnEndpointIP.IP.Equal(endpointIP.IP) &&
							learnEndpointIP.BridgeName == endpointIP.BridgeName &&
							learnEndpointIP.OfPort == endpointIP.OfPort {
							return true
						}
					default:
						return false
					}
				}
			}, timeout, interval).Should(BeTrue())
		}
	}
	testEndpointIPTimeout("10.10.200.24")
	testEndpointIPTimeout("2401::10:10:200:24")
}

func mustAddEndpoint(name string, ip net.IP) *types.EndpointIP {
	_, err := excuteCommand(fmt.Sprintf("ovs-vsctl add-port ovsbr0 %s -- set interface %s type=internal", name, name))
	Expect(err).ShouldNot(HaveOccurred())

	_, err = excuteCommand(fmt.Sprintf("ip link set %s up", name))
	Expect(err).ShouldNot(HaveOccurred())

	_, err = excuteCommand(fmt.Sprintf("ip a add dev %s %s/32", name, ip))
	Expect(err).ShouldNot(HaveOccurred())

	raw, err := excuteCommand(fmt.Sprintf("ovs-vsctl --columns=_uuid,ofport,mac_in_use -f json list interface %s", name))
	Expect(err).ShouldNot(HaveOccurred())

	response := make(map[string]interface{})
	Expect(json.Unmarshal(raw, &response)).ShouldNot(HaveOccurred())

	uuid := response["data"].([]interface{})[0].([]interface{})[0].([]interface{})[1].(string)
	ofport := uint32(response["data"].([]interface{})[0].([]interface{})[1].(float64))
	mac := response["data"].([]interface{})[0].([]interface{})[2].(string)

	Expect(datapathManager.AddLocalEndpoint(&Endpoint{
		InterfaceUUID: uuid,
		InterfaceName: name,
		PortNo:        ofport,
		MacAddrStr:    mac,
		BridgeName:    "ovsbr0",
	})).ShouldNot(HaveOccurred())

	hw, _ := net.ParseMAC(mac)
	return &types.EndpointIP{BridgeName: "ovsbr0", OfPort: ofport, IP: ip, Mac: hw}
}

func flowValidator(expectedFlows []string) error {
	var currentFlowList []string
	var err error
	if currentFlowList, err = dumpAllFlows(); err != nil {
		return fmt.Errorf("failed to dump current default flow")
	}

	for _, expectedFlow := range expectedFlows {
		isExpectedFlowExists := false
		for _, actualFlow := range currentFlowList {
			expr := `load:0x[0-9,a-f]+?->NXM_NX_XXREG0`
			re, _ := regexp.Compile(expr)
			actual := re.ReplaceAllString(actualFlow, "load:0x->NXM_NX_XXREG0")
			if strings.Contains(expectedFlow, actual) {
				isExpectedFlowExists = true
			}
		}
		if isExpectedFlowExists {
			continue
		}

		return fmt.Errorf("expected flow %v is not contains in current flow list\n: %v", expectedFlow, currentFlowList)
	}

	return nil
}

func excuteCommand(commandStr string) ([]byte, error) {
	out, err := exec.Command("/bin/sh", "-c", commandStr).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to excute cmd: %v, error: %v", string(out), err)
	}

	return out, nil
}

func restartOvsVswitchd(interval int) error {
	commandStr := fmt.Sprintf("kill -9 $(pidof ovs-vswitchd) && sleep %d && %s start", interval, ovsctlScriptPath)
	if _, err := excuteCommand(commandStr); err != nil {
		return err
	}

	return nil
}

func dumpAllFlows(bridges ...string) ([]string, error) {
	var flowDump []string
	var brList []string
	if len(bridges) == 0 {
		brList = ovsBridgeList
	} else {
		brList = bridges
	}
	for _, br := range brList {
		cmdStr := fmt.Sprintf("sudo /usr/bin/ovs-ofctl -O Openflow13 dump-flows %s", br)
		flowsByte, err := excuteCommand(cmdStr)
		if err != nil {
			return nil, err
		}

		flowOutStr := string(flowsByte)
		flowDB := strings.Split(flowOutStr, "\n")[1:]

		var flowList []string
		for _, flow := range flowDB {
			felem := strings.Fields(flow)
			if len(felem) > 2 {
				felem = append([]string{felem[2]}, felem[5:]...)
				fstr := strings.Join(felem, " ")
				flowList = append(flowList, fstr)
			}
		}

		flowDump = append(flowDump, flowList...)
	}

	return flowDump, nil
}

func testLocalEndpointOverlay(t *testing.T) {
	RegisterTestingT(t)
	ep1Copy := copyEp(ep1)
	ep1Copy.BridgeName = cniBrName
	newEp1Copy := copyEp(newep1)
	newEp1Copy.BridgeName = cniBrName
	ep2Copy := copyEp(ep2)
	ep2Copy.BridgeName = cniBrName
	newEp2Copy := copyEp(newep2)
	newEp2Copy.BridgeName = cniBrName

	t.Run("test add and remove local endpoint normal", func(t *testing.T) {
		if err := cniDpMgr.AddLocalEndpoint(ep1Copy); err != nil {
			t.Errorf("Failed to add local endpoint %+v, err: %v", ep1Copy, err)
		}

		Eventually(func() bool {
			validate, err := validateLocalEndpointFlowForOverlay(cniBrName, ep1Copy)
			if err != nil {
				return false
			}
			return validate
		}, timeout, interval).Should(BeTrue())

		if err := cniDpMgr.RemoveLocalEndpoint(ep1Copy); err != nil {
			t.Errorf("Failed to delete local endpoint : %+v, err: %v", ep1Copy, err)
		}
		Eventually(func() bool {
			validate, err := validateLocalEndpointFlowForOverlay(cniBrName, ep1Copy)
			if err != nil {
				return true
			}
			return validate
		}, timeout, interval).Should(BeFalse())
	})

	t.Run("test add local endpoint without ip", func(t *testing.T) {
		if err := cniDpMgr.AddLocalEndpoint(ep2Copy); err != nil {
			t.Errorf("Failed to add local endpoint %+v, err: %v", ep2Copy, err)
		}
		time.Sleep(timeout)
		validate, err := validateLocalEndpointFlowForOverlay(cniBrName, ep2Copy)
		if err != nil {
			t.Errorf("Failed to validate local endpoint flow: %v", err)
		}
		Expect(validate).Should(BeFalse())
	})

	t.Run("test update local endpoint exists flow", func(t *testing.T) {
		if err := cniDpMgr.AddLocalEndpoint(ep1Copy); err != nil {
			t.Errorf("Failed to add local endpoint %+v, err: %v", ep1Copy, err)
		}
		if err := cniDpMgr.UpdateLocalEndpoint(newEp1Copy, ep1Copy); err != nil {
			t.Errorf("Failed to update local endpoint %+v, err: %v", newEp1Copy, err)
		}

		Eventually(func() error {
			validate, err := validateLocalEndpointFlowForOverlay(cniBrName, ep1Copy)
			if err != nil {
				return err
			}
			if !validate {
				return fmt.Errorf("can't found flow")
			}
			return nil
		}, timeout, interval).Should(Succeed())

		if err := cniDpMgr.RemoveLocalEndpoint(newEp1Copy); err != nil {
			t.Errorf("Failed to delete local endpoint : %+v, err: %v", newEp1Copy, err)
		}
	})

	t.Run("test update local endpoint without exists flow", func(t *testing.T) {
		if err := cniDpMgr.AddLocalEndpoint(ep2Copy); err != nil {
			t.Errorf("Failed to add local endpoint %+v, err: %v", ep2Copy, err)
		}
		if err := cniDpMgr.UpdateLocalEndpoint(newEp2Copy, ep2Copy); err != nil {
			t.Errorf("Failed to update local endpoint %+v, err: %v", newEp2Copy, err)
		}
		Eventually(func() bool {
			validate, err := validateLocalEndpointFlowForOverlay(cniBrName, newEp2Copy)
			if err != nil {
				return false
			}
			return validate
		}, timeout, interval).Should(BeTrue())
		if err := cniDpMgr.RemoveLocalEndpoint(newEp2Copy); err != nil {
			t.Errorf("Failed to delete local endpoint : %+v, err: %v", newEp2Copy, err)
		}
	})
}

func validateLocalEndpointFlowForOverlay(brName string, ep *Endpoint) (bool, error) {
	localBrFlows, err := dumpAllFlows(brName)
	if err != nil {
		return false, err
	}
	validate := false
	for _, f := range localBrFlows {
		if !strings.Contains(f, fmt.Sprintf("table=%d", LBOForwardToLocalTable)) {
			continue
		}
		if !strings.Contains(f, fmt.Sprintf("nw_dst=%s", ep.IPAddr.String())) {
			continue
		}
		if !strings.Contains(f, fmt.Sprintf("load:%#x->NXM_NX_REG2[0..15]", ep.PortNo)) {
			continue
		}
		if !strings.Contains(f, fmt.Sprintf("set_field:%s->eth_dst", ep.MacAddrStr)) {
			continue
		}
		validate = true
		break
	}
	if !validate {
		return false, nil
	}

	validate = false
	uplinkBrFlows, err := dumpAllFlows(brName + "-uplink")
	if err != nil {
		return false, err
	}
	for _, f := range uplinkBrFlows {
		if !strings.Contains(f, fmt.Sprintf("table=%d", UBOForwardToLocalTable)) {
			continue
		}
		if !strings.Contains(f, fmt.Sprintf("nw_dst=%s", ep.IPAddr.String())) {
			continue
		}
		if !strings.Contains(f, "load:0x1->NXM_NX_REG2[0..15]") {
			continue
		}
		validate = true
	}
	return validate, nil
}

func copyEp(src *Endpoint) *Endpoint {
	return &Endpoint{
		InterfaceName: src.InterfaceName,
		InterfaceUUID: src.InterfaceUUID,
		PortNo:        src.PortNo,
		IPAddr:        src.IPAddr,
		MacAddrStr:    src.MacAddrStr,
		BridgeName:    src.BridgeName,
		VlanID:        src.VlanID,
	}
}

func randomIP() string {
	return fmt.Sprintf("%d.%d.%d.%d", rand.IntnRange(1, 255), rand.Intn(255), rand.Intn(255), rand.Intn(255))
}

func randomIPv6() string {
	return fmt.Sprintf("2401::%d:%d:%d:%d", rand.IntnRange(1, 255), rand.Intn(255), rand.Intn(255), rand.Intn(255))
}

func TestReleaseRuleSeqID(t *testing.T) {
	start := uint32(0x8000010)
	fAllo := NewFlowIDAlloctor(MSModuleName, start, 0x800001f, 0x0)
	allo := fAllo.GetNumAlloctor()

	allo.used.Set(0x8000012 - start)
	allo.used.Set(0x8000013 - start)
	allo.used.Set(0x8000014 - start)

	fAllo.Release(context.Background(), nil, []uint64{0xb8000009, 0xb8000013})
	if !allo.used.Contains(0x8000013 - start) {
		t.Errorf("release seqID failed when no dels")
	}

	fAllo.Release(context.Background(), []uint64{0xb8000013, 0xc8000014}, []uint64{0xb8000013, 0xc8000014})
	if !allo.used.Contains(0x8000013-start) || !allo.used.Contains(0x8000014-start) {
		t.Errorf("can't release dels in ress when all dels is in ress")
	}

	fAllo.Release(context.Background(), []uint64{0xb8000013, 0xb8000012}, []uint64{0xb8000013, 0xb8000015})
	if !allo.used.Contains(0x8000013-start) || allo.used.Contains(0x8000012-start) {
		t.Errorf("release seqID failed for part dels in ress")
	}

	fAllo.Release(context.Background(), []uint64{0x8000013, 0xc8000013, 0x8000014}, nil)
	if allo.used.Contains(0x8000013-start) || allo.used.Contains(0x800001-start) {
		t.Errorf("release seqID failed when no ress")
	}
}

func testUplinkBridgeMarkFlows(t *testing.T) {
	t.Run("test uplink bridge mark flows", func(t *testing.T) {
		RegisterTestingT(t)

		flows, err := dumpAllFlows("ovsbr0-uplink")
		Expect(err).ShouldNot(HaveOccurred())
		Expect(flows).ShouldNot(BeEmpty())

		var (
			containsClsToUplinkFlow = false
			containsMarkFlow        = false
		)
		for _, flow := range flows {
			if strings.Contains(flow, "table=0") {
				switch {
				case strings.Contains(flow, fmt.Sprintf("priority=%d", NORMAL_MATCH_FLOW_PRIORITY)) &&
					strings.Contains(flow, "in_port=") &&
					strings.Contains(flow, "actions=NORMAL"):
					containsClsToUplinkFlow = true
				case strings.Contains(flow, "priority=10") &&
					strings.Contains(flow, "load:0x3->NXM_NX_PKT_MARK[17..18]") &&
					strings.Contains(flow, "move:NXM_OF_IN_PORT[]->NXM_NX_PKT_MARK[0..15]"):
					containsMarkFlow = true
				}
			}
		}
		Expect(containsClsToUplinkFlow).Should(BeTrue())
		Expect(containsMarkFlow).Should(BeTrue())
	})
}

func containsAll(flow string, strs ...string) bool {
	for _, str := range strs {
		if !strings.Contains(flow, str) {
			return false
		}
	}
	return true
}

func isNewFlow(flow string) bool {
	checkNew := strings.Contains(flow, "reg5=0x100/0x100")
	checkActions := containsAll(flow,
		"move:NXM_NX_XXREG0[126..127]->NXM_NX_CT_LABEL[126..127]", // final policy actions
		"move:NXM_NX_XXREG0[4..5]->NXM_NX_CT_LABEL[4..5]",         // mark policy actions
		"move:NXM_NX_XXREG0[0..3]->NXM_NX_CT_LABEL[0..3]",         // round number
		"move:NXM_NX_XXREG0[32..87]->NXM_NX_CT_LABEL[32..87]",     // flow IDs
		"load:0x3->NXM_NX_CT_LABEL[124..125]",                     // mark micro-segment
		"move:NXM_NX_PKT_MARK[17..18]->NXM_NX_CT_LABEL[88..89]",   // origin packet source
		"load:0->NXM_NX_CT_LABEL[90..91]",                         // reset reply packet source
		"move:NXM_NX_PKT_MARK[0..15]->NXM_NX_CT_LABEL[92..107]",   // origin inport
		"load:0->NXM_NX_CT_LABEL[108..123]",                       // reset reply inport
	)
	return checkNew && checkActions
}

func isRplFlow(flow string) bool {
	checkRpl := strings.Contains(flow, "ct_state=+rpl+trk")
	checkActions := containsAll(flow,
		"load:0x3->NXM_NX_CT_LABEL[124..125]",                    // mark micro-segment
		"move:NXM_NX_PKT_MARK[17..18]->NXM_NX_CT_LABEL[90..91]",  // reply packet source
		"move:NXM_NX_PKT_MARK[0..15]->NXM_NX_CT_LABEL[108..123]", // reply inport
	)
	return checkRpl && checkActions
}

func isIp(flow string) bool {
	return strings.Contains(flow, "ip") && !isIp6(flow)
}

func isIp6(flow string) bool {
	return strings.Contains(flow, "ipv6")
}

func isTcp(flow string) bool {
	return strings.Contains(flow, "tcp") && !isTcp6(flow)
}

func isTcp6(flow string) bool {
	return strings.Contains(flow, "tcp6")
}

func isUdp(flow string) bool {
	return strings.Contains(flow, "udp") && !isUdp6(flow)
}

func isUdp6(flow string) bool {
	return strings.Contains(flow, "udp6")
}

func hasTpDst(flow string, port int) bool {
	return strings.Contains(flow, fmt.Sprintf("tp_dst=%d", port))
}

func TestPolicyBridgeFlows(t *testing.T) {
	t.Run("test policy bridge general flows", func(t *testing.T) {
		RegisterTestingT(t)
		flows, err := dumpAllFlows("ovsbr0-policy")
		Expect(err).ShouldNot(HaveOccurred())
		Expect(flows).ShouldNot(BeEmpty())
		table70Flows := []string{}
		for _, flow := range flows {
			// skip ALG flows and it should be in table 70
			if strings.Contains(flow, "table=70,") && !strings.Contains(flow, "tp_dst") {
				table70Flows = append(table70Flows, flow)
			}
		}
		var (
			ipNewFlow   = false
			ipv6NewFlow = false
			ipRplFlow   = false
			ipv6RplFlow = false
		)
		for _, flow := range table70Flows {
			switch {
			case isIp(flow) && isNewFlow(flow):
				ipNewFlow = true
			case isIp6(flow) && isNewFlow(flow):
				ipv6NewFlow = true
			case isIp(flow) && isRplFlow(flow):
				ipRplFlow = true
			case isIp6(flow) && isRplFlow(flow):
				ipv6RplFlow = true
			}
		}
		Expect(ipNewFlow).Should(BeTrue())
		Expect(ipv6NewFlow).Should(BeTrue())
		Expect(ipRplFlow).Should(BeTrue())
		Expect(ipv6RplFlow).Should(BeTrue())
	})

	t.Run("test policy bridge ALG flows", func(t *testing.T) {
		RegisterTestingT(t)
		flows, err := dumpAllFlows("ovsbr0-policy")
		Expect(err).ShouldNot(HaveOccurred())
		Expect(flows).ShouldNot(BeEmpty())
		table70Flows := []string{}
		for _, flow := range flows {
			if strings.Contains(flow, "table=70,") && strings.Contains(flow, "tp_dst") {
				table70Flows = append(table70Flows, flow)
			}
		}
		var (
			ftpNewFlow   = false // tcp 21
			ftp6NewFlow  = false // tcp6 21
			tftpNewFlow  = false // udp 69
			tftp6NewFlow = false // udp6 69
			ftpRplFlow   = false // tcp 21
			ftp6RplFlow  = false // tcp6 21
			tftpRplFlow  = false // udp 69
			tftp6RplFlow = false // udp6 69
		)
		for _, flow := range table70Flows {
			switch {
			case isTcp(flow) && hasTpDst(flow, 21) && isNewFlow(flow):
				ftpNewFlow = true
			case isTcp6(flow) && hasTpDst(flow, 21) && isNewFlow(flow):
				ftp6NewFlow = true
			case isUdp(flow) && hasTpDst(flow, 69) && isNewFlow(flow):
				tftpNewFlow = true
			case isUdp6(flow) && hasTpDst(flow, 69) && isNewFlow(flow):
				tftp6NewFlow = true
			case isTcp(flow) && hasTpDst(flow, 21) && isRplFlow(flow):
				ftpRplFlow = true
			case isTcp6(flow) && hasTpDst(flow, 21) && isRplFlow(flow):
				ftp6RplFlow = true
			case isUdp(flow) && hasTpDst(flow, 69) && isRplFlow(flow):
				tftpRplFlow = true
			case isUdp6(flow) && hasTpDst(flow, 69) && isRplFlow(flow):
				tftp6RplFlow = true
			}
		}
		Expect(ftpNewFlow).Should(BeTrue())
		Expect(ftp6NewFlow).Should(BeTrue())
		Expect(tftpNewFlow).Should(BeTrue())
		Expect(tftp6NewFlow).Should(BeTrue())
		Expect(ftpRplFlow).Should(BeTrue())
		Expect(ftp6RplFlow).Should(BeTrue())
		Expect(tftpRplFlow).Should(BeTrue())
		Expect(tftp6RplFlow).Should(BeTrue())
	})

	t.Run("test policy bridge ct state flows", func(t *testing.T) {
		RegisterTestingT(t)

		currentFlows, err := dumpAllFlows("ovsbr0-policy")
		Expect(err).ShouldNot(HaveOccurred())
		Expect(currentFlows).ShouldNot(BeEmpty())

		currentTable1Flows := lo.Filter(currentFlows, func(f string, _ int) bool { return strings.HasPrefix(f, "table=1,") })
		Expect(currentTable1Flows).Should(ConsistOf(policyCTStateTableFlows))
	})

	t.Run("test policy bridge direction selection flows", func(t *testing.T) {
		RegisterTestingT(t)

		currentFlows, err := dumpAllFlows("ovsbr0-policy")
		Expect(err).ShouldNot(HaveOccurred())
		Expect(currentFlows).ShouldNot(BeEmpty())

		currentTable10Flows := lo.Filter(currentFlows, func(f string, _ int) bool { return strings.HasPrefix(f, "table=10,") })
		Expect(currentTable10Flows).Should(ConsistOf(policyDirectionSelectionTableFlows))
	})

	t.Run("test policy bridge action update flows", func(t *testing.T) {
		RegisterTestingT(t)

		currentFlows, err := dumpAllFlows("ovsbr0-policy")
		Expect(err).ShouldNot(HaveOccurred())
		Expect(currentFlows).ShouldNot(BeEmpty())

		currentTable69Flows := lo.Filter(currentFlows, func(f string, _ int) bool { return strings.HasPrefix(f, "table=69,") })
		Expect(currentTable69Flows).Should(ConsistOf(policyActionUpdateTableFlows))
	})
}

func TestTREp(t *testing.T) {
	nicFlows := []string{
		fmt.Sprintf("table=0, priority=600,in_port=%d actions=goto_table:120", TRNicInPortNO),
		fmt.Sprintf("table=0, priority=600,in_port=%d actions=goto_table:130", TRNicOutPortNO),
		fmt.Sprintf("table=106, priority=100 actions=learn(table=125,idle_timeout=300,hard_timeout=300,priority=100,NXM_OF_ETH_SRC[],load:NXM_NX_PKT_MARK[0..14]->NXM_NX_PKT_MARK[0..14]),output:%d", TRNicOutPortNO),
		fmt.Sprintf("table=116, priority=100 actions=output:%d", TRNicInPortNO),
	}
	healthyFlows := []string{
		"table=105, priority=100 actions=resubmit(,106)",
		"table=115, priority=100 actions=resubmit(,116)",
	}
	RegisterTestingT(t)
	// add nicOut ep
	ep := Endpoint{
		InterfaceUUID: TRNicOutUUID,
		BridgeName:    "ovsbr0-policy",
		PortNo:        TRNicOutPortNO,
		InterfaceName: "nic1",
		State:         LinkUp,
		IfaceID:       TRNicOutIfaceID,
	}
	res := datapathManager.skipLocalEndpoint(&ep)
	Expect(res).Should(BeFalse())
	err := datapathManager.AddLocalEndpoint(&ep)
	Expect(err).ShouldNot(HaveOccurred())
	p := datapathManager.BridgeChainMap["ovsbr0"][POLICY_BRIDGE_KEYWORD].(*PolicyBridge)
	Expect(p.TrafficRedirect.Info.NicOut.PortNo).Should(Equal(TRNicOutPortNO))
	Expect(p.TrafficRedirect.Info.NicOut.State).Should(Equal(LinkUp))
	flows, err := dumpAllFlows("ovsbr0-policy")
	Expect(err).ShouldNot(HaveOccurred())
	Expect(flows).ShouldNot(BeEmpty())
	for i := range nicFlows {
		err = flowValidator([]string{nicFlows[i]})
		Expect(err).Should(HaveOccurred())
	}
	for i := range healthyFlows {
		err = flowValidator([]string{healthyFlows[i]})
		Expect(err).Should(HaveOccurred())
	}

	//add nic in ep
	ep = Endpoint{
		InterfaceUUID: TRNicInUUID,
		BridgeName:    "ovsbr0-policy",
		PortNo:        TRNicInPortNO,
		InterfaceName: "nic2",
		State:         LinkUnknown,
		IfaceID:       TRNicInIfaceID,
	}
	err = datapathManager.AddLocalEndpoint(&ep)
	Expect(err).ShouldNot(HaveOccurred())
	p = datapathManager.BridgeChainMap["ovsbr0"][POLICY_BRIDGE_KEYWORD].(*PolicyBridge)
	Expect(p.TrafficRedirect.Info.NicIn.PortNo).Should(Equal(TRNicInPortNO))
	Expect(p.TrafficRedirect.Info.NicIn.State).Should(Equal(LinkUnknown))
	flows, err = dumpAllFlows("ovsbr0-policy")
	Expect(err).ShouldNot(HaveOccurred())
	Expect(flows).ShouldNot(BeEmpty())
	err = flowValidator(nicFlows)
	Expect(err).ShouldNot(HaveOccurred())
	for i := range healthyFlows {
		err = flowValidator([]string{healthyFlows[i]})
		Expect(err).Should(HaveOccurred())
	}

	// dpi health
	datapathManager.ProcessDPIHealthyStatus(types.DPIAlive)
	p = datapathManager.BridgeChainMap["ovsbr0"][POLICY_BRIDGE_KEYWORD].(*PolicyBridge)
	Expect(p.TrafficRedirect.Info.DPIHealthy).Should(BeTrue())
	Expect(p.TrafficRedirect.Info.OldHealthy).Should(BeFalse())
	err = flowValidator(nicFlows)
	Expect(err).ShouldNot(HaveOccurred())
	for i := range healthyFlows {
		err = flowValidator([]string{healthyFlows[i]})
		Expect(err).Should(HaveOccurred())
	}

	// update nic in link up
	ep = Endpoint{
		InterfaceUUID: TRNicInUUID,
		BridgeName:    "ovsbr0-policy",
		PortNo:        TRNicInPortNO,
		InterfaceName: "nic2",
		State:         LinkUp,
		IfaceID:       TRNicInIfaceID,
	}
	err = datapathManager.UpdateLocalEndpoint(&ep, &ep)
	Expect(err).ShouldNot(HaveOccurred())
	p = datapathManager.BridgeChainMap["ovsbr0"][POLICY_BRIDGE_KEYWORD].(*PolicyBridge)
	Expect(p.TrafficRedirect.Info.NicIn.PortNo).Should(Equal(TRNicInPortNO))
	Expect(p.TrafficRedirect.Info.NicIn.State).Should(Equal(LinkUp))
	Expect(p.TrafficRedirect.Info.OldHealthy).Should(BeTrue())
	err = flowValidator(nicFlows)
	Expect(err).ShouldNot(HaveOccurred())
	err = flowValidator(healthyFlows)
	Expect(err).ShouldNot(HaveOccurred())

	// dpi unhealthy
	datapathManager.ProcessDPIHealthyStatus(types.DPIDead)
	p = datapathManager.BridgeChainMap["ovsbr0"][POLICY_BRIDGE_KEYWORD].(*PolicyBridge)
	Expect(p.TrafficRedirect.Info.DPIHealthy).Should(BeFalse())
	Expect(p.TrafficRedirect.Info.OldHealthy).Should(BeFalse())
	err = flowValidator(nicFlows)
	Expect(err).ShouldNot(HaveOccurred())
	for i := range healthyFlows {
		err = flowValidator([]string{healthyFlows[i]})
		Expect(err).Should(HaveOccurred())
	}

	// del out ep
	ep = Endpoint{
		InterfaceUUID: TRNicOutUUID,
		BridgeName:    "ovsbr0-policy",
		PortNo:        TRNicOutPortNO,
		InterfaceName: "nic2",
		State:         LinkUp,
		IfaceID:       TRNicOutIfaceID,
	}
	err = datapathManager.RemoveLocalEndpoint(&ep)
	Expect(err).ShouldNot(HaveOccurred())
	p = datapathManager.BridgeChainMap["ovsbr0"][POLICY_BRIDGE_KEYWORD].(*PolicyBridge)
	Expect(p.TrafficRedirect.Info.NicOut.PortNo).Should(Equal(uint32(0)))
	Expect(p.TrafficRedirect.Info.NicOut.State).Should(Equal(LinkUnknown))
	for i := range nicFlows {
		err = flowValidator([]string{nicFlows[i]})
		Expect(err).Should(HaveOccurred())
	}
	for i := range healthyFlows {
		err = flowValidator([]string{healthyFlows[i]})
		Expect(err).Should(HaveOccurred())
	}
}
