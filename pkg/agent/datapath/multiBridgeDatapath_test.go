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
	"regexp"
	"strings"
	"testing"
	"time"

	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"

	"github.com/everoute/everoute/pkg/apis/security/v1alpha1"
)

const (
	ovsctlScriptPath           = "/usr/share/openvswitch/scripts/ovs-ctl"
	ovsVswitchdRestartInterval = 1
	ifaceUUID                  = "10000000-0000-0000-0000-000000000000"
	iface2UUID                 = "20000000-0000-0000-0000-000000000000"
)

const (
	timeout  = time.Second * 20
	interval = time.Millisecond * 500
)

var (
	datapathManager *DpManager
	datapathConfig  = DpManagerConfig{
		ManagedVDSMap: map[string]string{
			"ovsbr0": "ovsbr0",
		},
	}

	cniDpMgr *DpManager
	cniBrName = "cnibr0"

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
		IPProtocol: uint8(1),
		SrcIPAddr:  "10.100.100.1",
		DstIPAddr:  "10.100.100.2",
		Action:     "allow",
	}
	rule2 = &EveroutePolicyRule{
		RuleID:     "rule2",
		IPProtocol: uint8(17),
		SrcIPAddr:  "10.100.100.0/24",
		Action:     "deny",
	}
	rule3 = &EveroutePolicyRule{
		RuleID:     "rule3",
		IPProtocol: uint8(4),
		SrcIPAddr:  "10.100.100.0/24",
		DstIPAddr:  "10.23.1.90",
		Action:     "allow",
	}

	rule1Flow = `table=60, priority=200,icmp,nw_src=10.100.100.1,nw_dst=10.100.100.2 ` +
		`actions=load:0x->NXM_NX_XXREG0[60..87],load:0x->NXM_NX_XXREG0[0..3],goto_table:70`
	ep1VlanInputFlow               = "table=0, priority=200,in_port=11 actions=push_vlan:0x8100,set_field:4097->vlan_vid,load:0xb->NXM_NX_PKT_MARK[0..15],resubmit(,10),resubmit(,15)"
	ep1LocalToLocalFlow            = "table=5, priority=200,dl_vlan=1,dl_src=00:00:aa:aa:aa:aa actions=load:0xb->NXM_OF_IN_PORT[],load:0->NXM_OF_VLAN_TCI[0..12],NORMAL"
	ep2VlanInputFlow               = "table=0, priority=200,in_port=22,vlan_tci=0x1000/0x1000 actions=load:0x1->NXM_NX_REG3[0..1],load:0x16->NXM_NX_PKT_MARK[0..15],resubmit(,1)"
	ep2VlanInputFlow1              = "table=0, priority=197,in_port=22 actions=load:0x16->NXM_NX_PKT_MARK[0..15],resubmit(,10),resubmit(,15)"
	ep2VlanFilterFlow1             = "table=1, priority=200,in_port=22,dl_vlan=1 actions=resubmit(,10),resubmit(,15)"
	ep2VlanFilterFlow2             = "table=1, priority=200,in_port=22,vlan_tci=0x1002/0x1ffe actions=resubmit(,10),resubmit(,15)"
	vlanFilterDefaultFlow          = "table=1, priority=10 actions=drop"
	ep2LocalToLocalFlow            = "table=5, priority=200,dl_src=00:00:aa:aa:aa:bb actions=load:0x16->NXM_OF_IN_PORT[],NORMAL"
	newep2VlanInputFlow            = "table=0, priority=200,in_port=22 actions=push_vlan:0x8100,set_field:4097->vlan_vid,load:0x16->NXM_NX_PKT_MARK[0..15],resubmit(,10),resubmit(,15)"
	newep2LocalToLocalFlow         = "table=5, priority=200,dl_vlan=1,dl_src=00:00:aa:aa:aa:bb actions=load:0x16->NXM_OF_IN_PORT[],load:0->NXM_OF_VLAN_TCI[0..12],NORMAL"
	fromLocalLearningFlow          = "table=10, priority=100 actions=learn(table=5,idle_timeout=300,hard_timeout=300,priority=203,NXM_OF_VLAN_TCI[0..11],NXM_OF_ETH_DST[]=NXM_OF_ETH_SRC[],load:0->NXM_OF_VLAN_TCI[0..12],output:NXM_OF_IN_PORT[])"
	fromLocalTrunkPortLearningFlow = "table=10, priority=103,reg3=0x1/0x3 actions=learn(table=5,idle_timeout=300,hard_timeout=300,priority=203,NXM_OF_VLAN_TCI[0..11],NXM_OF_ETH_DST[]=NXM_OF_ETH_SRC[],output:NXM_OF_IN_PORT[])"
	ep3VlanInputFlow1              = "table=0, priority=200,in_port=33 actions=load:0x1->NXM_NX_REG3[0..1],load:0x21->NXM_NX_PKT_MARK[0..15],resubmit(,1)"
	ep3VlanFilterFlow1             = "table=1, priority=200,in_port=33,dl_vlan=1 actions=resubmit(,10),resubmit(,15)"
	ep3VlanFilterFlow2             = "table=1, priority=200,in_port=33,vlan_tci=0x1002/0x1ffe actions=resubmit(,10),resubmit(,15)"
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
	ipAddressChan := make(chan map[string]net.IP, 100)
	if err := ExcuteCommand(SetupBridgeChain, "ovsbr0"); err != nil {
		log.Fatalf("Failed to setup bridgechain, error: %v", err)
	}

	stopChan := make(<-chan struct{})
	datapathManager = NewDatapathManager(&datapathConfig, ipAddressChan)
	datapathManager.InitializeDatapath(stopChan)
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

	stopChan := make(<-chan struct{})
	var err error
	cniDpMgr, err = InitCNIDpMgrUT(stopChan, cniBrName, false, true)
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

func testEverouteDp(t *testing.T) {
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
	testMonitorRule(t)
	testFlowReplay(t)
	testRoundNumFlip(t)
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
	t.Run("test ER policy rule", func(t *testing.T) {
		if err := datapathManager.AddEveroutePolicyRule(rule1, "rule1", POLICY_DIRECTION_IN, POLICY_TIER2, DEFAULT_POLICY_ENFORCEMENT_MODE); err != nil {
			t.Errorf("Failed to add ER policy rule: %v, error: %v", rule1, err)
		}
		if _, ok := datapathManager.Rules[rule1.RuleID]; !ok {
			t.Errorf("Failed to add ER policy rule, not found %v in cache", rule1)
		}

		if err := datapathManager.RemoveEveroutePolicyRule(rule1.RuleID, "rule1"); err != nil {
			t.Errorf("Failed to remove ER policy rule: %v, error: %v", rule1, err)
		}
		if _, ok := datapathManager.Rules[rule1.RuleID]; ok {
			t.Errorf("Failed to remove ER policy rule, rule %v in cache", rule1)
		}

		if err := datapathManager.AddEveroutePolicyRule(rule2, "rule2", POLICY_DIRECTION_OUT, POLICY_TIER1, DEFAULT_POLICY_ENFORCEMENT_MODE); err != nil {
			t.Errorf("Failed to add ER policy rule: %v, error: %v", rule2, err)
		}
		if _, ok := datapathManager.Rules[rule2.RuleID]; !ok {
			t.Errorf("Failed to add ER policy rule, not found %v in cache", rule2)
		}
		if err := datapathManager.AddEveroutePolicyRule(rule2, "rule2", POLICY_DIRECTION_OUT, POLICY_TIER1, DEFAULT_POLICY_ENFORCEMENT_MODE); err != nil {
			t.Errorf("Failed to add ER policy rule: %v, error: %v", rule2, err)
		}

		if err := datapathManager.AddEveroutePolicyRule(rule3, "rule3", POLICY_DIRECTION_IN, POLICY_TIER_ECP, DEFAULT_POLICY_ENFORCEMENT_MODE); err != nil {
			t.Errorf("Failed to add ER policy rule: %v, error: %v", rule3, err)
		}
		if _, ok := datapathManager.Rules[rule3.RuleID]; !ok {
			t.Errorf("Failed to add ER policy rule, not found %v in cache", rule3)
		}
		if err := datapathManager.RemoveEveroutePolicyRule(rule3.RuleID, "rule3"); err != nil {
			t.Errorf("Failed to remove ER policy rule: %v, error: %v", rule3, err)
		}
		if _, ok := datapathManager.Rules[rule3.RuleID]; ok {
			t.Errorf("Failed to remove ER policy rule, rule %v in cache", rule3)
		}
	})
}

func testMonitorRule(t *testing.T) {
	t.Run("test ER policy rule with monitor mode", func(t *testing.T) {
		if err := datapathManager.AddEveroutePolicyRule(rule1, "rule1", POLICY_DIRECTION_IN, POLICY_TIER2, v1alpha1.MonitorMode.String()); err != nil {
			t.Errorf("Failed to add ER policy rule: %v, error: %v", rule1, err)
		}
		if _, ok := datapathManager.Rules[rule1.RuleID]; !ok {
			t.Errorf("Failed to add ER policy rule, not found %v in cache", rule1)
		}

		if err := datapathManager.RemoveEveroutePolicyRule(rule1.RuleID, "rule1"); err != nil {
			t.Errorf("Failed to remove ER policy rule: %v, error: %v", rule1, err)
		}
		if _, ok := datapathManager.Rules[rule1.RuleID]; ok {
			t.Errorf("Failed to remove ER policy rule, rule %v in cache", rule1)
		}

		if err := datapathManager.AddEveroutePolicyRule(rule2, "rule2", POLICY_DIRECTION_OUT, POLICY_TIER1, v1alpha1.MonitorMode.String()); err != nil {
			t.Errorf("Failed to add ER policy rule: %v, error: %v", rule2, err)
		}
		if _, ok := datapathManager.Rules[rule2.RuleID]; !ok {
			t.Errorf("Failed to add ER policy rule, not found %v in cache", rule2)
		}
		if err := datapathManager.AddEveroutePolicyRule(rule2, "rule2", POLICY_DIRECTION_OUT, POLICY_TIER1, v1alpha1.MonitorMode.String()); err != nil {
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
			return datapathManager.AddEveroutePolicyRule(rule1, "rule1", POLICY_DIRECTION_IN, POLICY_TIER3, DEFAULT_POLICY_ENFORCEMENT_MODE)
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

	t.Run("test add and remove local endpoint normal", func (t *testing.T) {
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

	t.Run("test add local endpoint without ip", func (t *testing.T) {
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

	t.Run("test update local endpoint exists flow", func (t *testing.T) {
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

	t.Run("test update local endpoint without exists flow", func (t *testing.T) {
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
	uplinkBrFlows, err := dumpAllFlows(brName+"-uplink")
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