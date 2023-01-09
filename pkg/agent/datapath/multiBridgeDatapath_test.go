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

	log "github.com/Sirupsen/logrus"
	. "github.com/onsi/gomega"

	"github.com/everoute/everoute/pkg/apis/security/v1alpha1"
)

const (
	ovsctlScriptPath           = "/usr/share/openvswitch/scripts/ovs-ctl"
	ovsVswitchdRestartInterval = 1
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

	ovsBridgeList   = []string{"ovsbr0", "ovsbr0-policy", "ovsbr0-cls", "ovsbr0-uplink"}
	defaultFlowList []string

	ep1 = &Endpoint{
		InterfaceName: "ep1",
		PortNo:        uint32(11),
		MacAddrStr:    "00:00:aa:aa:aa:aa",
		BridgeName:    "ovsbr0",
		VlanID:        uint16(1),
	}
	newep1 = &Endpoint{
		InterfaceName: "ep1",
		PortNo:        uint32(12),
		MacAddrStr:    "00:00:aa:aa:aa:aa",
		BridgeName:    "ovsbr0",
		VlanID:        uint16(1),
	}
	ep2 = &Endpoint{
		InterfaceName: "ep2",
		PortNo:        uint32(22),
		MacAddrStr:    "00:00:aa:aa:aa:bb",
		BridgeName:    "ovsbr0",
		Trunk:         "0,1,2",
	}
	newep2 = &Endpoint{
		InterfaceName: "ep2",
		PortNo:        uint32(22),
		MacAddrStr:    "00:00:aa:aa:aa:bb",
		BridgeName:    "ovsbr0",
		VlanID:        uint16(1),
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

	rule1Flow = `table=60, priority=200,icmp,nw_src=10.100.100.1,nw_dst=10.100.100.2 ` +
		`actions=load:0x->NXM_NX_XXREG0[60..87],load:0x->NXM_NX_XXREG0[0..3],goto_table:70`
	ep1VlanInputFlow               = "table=0, priority=200,in_port=11 actions=load:0xb->NXM_NX_PKT_MARK[0..15],push_vlan:0x8100,set_field:4097->vlan_vid,resubmit(,10),resubmit(,15)"
	ep1LocalToLocalFlow            = "table=5, priority=200,dl_vlan=1,dl_src=00:00:aa:aa:aa:aa actions=load:0xb->NXM_OF_IN_PORT[],load:0->NXM_OF_VLAN_TCI[0..12],NORMAL"
	ep2VlanInputFlow               = "table=0, priority=200,in_port=22 actions=load:0x16->NXM_NX_PKT_MARK[0..15],load:0x1->NXM_NX_REG3[0..1],resubmit(,10),resubmit(,15)"
	ep2LocalToLocalFlow            = "table=5, priority=200,dl_src=00:00:aa:aa:aa:bb actions=load:0x16->NXM_OF_IN_PORT[],NORMAL"
	newep2VlanInputFlow            = "table=0, priority=200,in_port=22 actions=load:0x16->NXM_NX_PKT_MARK[0..15],push_vlan:0x8100,set_field:4097->vlan_vid,resubmit(,10),resubmit(,15)"
	newep2LocalToLocalFlow         = "table=5, priority=200,dl_vlan=1,dl_src=00:00:aa:aa:aa:bb actions=load:0x16->NXM_OF_IN_PORT[],load:0->NXM_OF_VLAN_TCI[0..12],NORMAL"
	fromLocalLearningFlow          = "table=10, priority=100 actions=learn(table=5,idle_timeout=300,hard_timeout=300,priority=203,NXM_OF_VLAN_TCI[0..11],NXM_OF_ETH_DST[]=NXM_OF_ETH_SRC[],load:0->NXM_OF_VLAN_TCI[0..12],output:NXM_OF_IN_PORT[])"
	fromLocalTrunkPortLearningFlow = "table=10, priority=100,reg3=0x1/0x3 actions=learn(table=5,idle_timeout=300,hard_timeout=300,priority=203,NXM_OF_VLAN_TCI[0..11],NXM_OF_ETH_DST[]=NXM_OF_ETH_SRC[],output:NXM_OF_IN_PORT[])"
)

func TestMain(m *testing.M) {
	ipAddressChan := make(chan map[string]net.IP, 100)
	if err := ExcuteCommand(SetupBridgeChain, "ovsbr0"); err != nil {
		log.Fatalf("Failed to setup bridgechain, error: %v", err)
	}

	stopChan := make(<-chan struct{})
	datapathManager = NewDatapathManager(&datapathConfig, ipAddressChan)
	datapathManager.InitializeDatapath(stopChan)

	exitCode := m.Run()
	_ = ExcuteCommand(CleanBridgeChain, "ovsbr0")
	os.Exit(exitCode)
}

func TestDpManager(t *testing.T) {
	var err error
	if defaultFlowList, err = dumpAllFlows(); err != nil {
		log.Fatalf("Failed to dump default flow while test env setup")
	}
	RegisterTestingT(t)

	t.Run("validate local endpoint learning flow", func(t *testing.T) {
		Eventually(func() error {
			return flowValidator([]string{fromLocalLearningFlow, fromLocalTrunkPortLearningFlow})
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
		if ep, _ := datapathManager.localEndpointDB.Get(ep1.InterfaceName); ep == nil {
			t.Errorf("Failed to add local endpoint, endpoint %v not found", ep1)
		}

		if err := datapathManager.UpdateLocalEndpoint(newep1, ep1); err != nil {
			t.Errorf("Failed to udpate local endpoint: from %v to %v, error: %v", ep1, newep1, err)
		}
		ep, _ := datapathManager.localEndpointDB.Get(ep1.InterfaceName)
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
		if ep, _ := datapathManager.localEndpointDB.Get(newep1.InterfaceName); ep != nil {
			t.Errorf("Failed to remove local endpoint, endpoint %v in cache", newep1)
		}
	})

	if err := datapathManager.AddLocalEndpoint(ep2); err != nil {
		t.Errorf("Failed to add local endpoint %v, error: %v", ep1, err)
	}
	t.Run("validate local endpoint forwarding flow add", func(t *testing.T) {
		Eventually(func() error {
			return flowValidator([]string{ep2LocalToLocalFlow, ep2VlanInputFlow})
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
			return flowValidator([]string{newep2LocalToLocalFlow, newep2VlanInputFlow})
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

func dumpAllFlows() ([]string, error) {
	var flowDump []string
	for _, br := range ovsBridgeList {
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
