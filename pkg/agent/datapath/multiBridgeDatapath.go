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
	"bytes"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	log "github.com/Sirupsen/logrus"
	cnitypes "github.com/containernetworking/cni/pkg/types"
	"github.com/contiv/libOpenflow/openflow13"
	"github.com/contiv/ofnet/ofctrl"
	"github.com/contiv/ofnet/ofctrl/cookie"
	"github.com/contiv/ofnet/ovsdbDriver"
	"github.com/fsnotify/fsnotify"
	cmap "github.com/streamrail/concurrent-map"
	"k8s.io/apimachinery/pkg/util/wait"
)

//nolint
const (
	HIGH_MATCH_FLOW_PRIORITY            = 300
	MID_MATCH_FLOW_PRIORITY             = 200
	NORMAL_MATCH_FLOW_PRIORITY          = 100
	GLOBAL_DEFAULT_POLICY_FLOW_PRIORITY = 40
	DEFAULT_FLOW_MISS_PRIORITY          = 10
	FLOW_MATCH_OFFSET                   = 3
)

//nolint
const (
	LOCAL_TO_POLICY_PORT = 101
	POLICY_TO_LOCAL_PORT = 102
	POLICY_TO_CLS_PORT   = 201
	CLS_TO_POLICY_PORT   = 202
	CLS_TO_UPLINK_PORT   = 301
	UPLINK_TO_CLS_PORT   = 302
	LOCAL_GATEWAY_PORT   = 10
)

//nolint
const (
	POLICY_TIER0 = 50
	POLICY_TIER1 = 100
	POLICY_TIER2 = 150
)

//nolint
const (
	POLICY_DIRECTION_OUT = 0
	POLICY_DIRECTION_IN  = 1
)

//nolint
const (
	IP_BROADCAST_ADDR = "255.255.255.255"
	LOOP_BACK_ADDR    = "127.0.0.1"
)

//nolint
const (
	PROTOCOL_ARP = 0x0806
	PROTOCOL_IP  = 0x0800
)

//nolint
const (
	LOCAL_BRIDGE_KEYWORD  = "local"
	POLICY_BRIDGE_KEYWORD = "policy"
	CLS_BRIDGE_KEYWORD    = "cls"
	UPLINK_BRIDGE_KEYWORD = "uplink"
)

const (
	datapathRestartRound            string = "datapathRestartRound"
	ovsVswitchdUnixDomainSockPath   string = "/var/run/openvswitch"
	ovsVswitchdUnixDomainSockSuffix string = "mgmt"
	ovsdbDomainSock                        = "/var/run/openvswitch/db.sock"

	openflowProtorolVersion10 string = "OpenFlow10"
	openflowProtorolVersion11 string = "OpenFlow11"
	openflowProtorolVersion12 string = "OpenFlow12"
	openflowProtorolVersion13 string = "OpenFlow13"
)

type Bridge interface {
	BridgeInit()
	BridgeReset()

	AddLocalEndpoint(endpoint *Endpoint) error
	RemoveLocalEndpoint(endpoint *Endpoint) error
	AddVNFInstance() error
	RemoveVNFInstance() error

	AddSFCRule() error
	RemoveSFCRule() error
	AddMicroSegmentRule(rule *EveroutePolicyRule, direction uint8, tier uint8) (*FlowEntry, error)
	RemoveMicroSegmentRule(rule *EveroutePolicyRule) error

	IsSwitchConnected() bool

	// of control app interface
	// A Switch connected to the controller
	SwitchConnected(sw *ofctrl.OFSwitch)

	// Switch disconnected from the controller
	SwitchDisconnected(sw *ofctrl.OFSwitch)

	// Controller received a packet from the switch
	PacketRcvd(sw *ofctrl.OFSwitch, pkt *ofctrl.PacketIn)

	// Controller received a multi-part reply from the switch
	MultipartReply(sw *ofctrl.OFSwitch, rep *openflow13.MultipartReply)
}

type DpManager struct {
	DpManagerMutex sync.Mutex
	BridgeChainMap map[string]map[string]Bridge                 // map vds to bridge instance map
	OvsdbDriverMap map[string]map[string]*ovsdbDriver.OvsDriver // map vds to bridge ovsdbDriver map
	ControllerMap  map[string]map[string]*ofctrl.Controller

	localEndpointDB           cmap.ConcurrentMap     // list of local endpoint map
	ofPortIPAddressUpdateChan chan map[string]net.IP // map bridgename-ofport to endpoint ips
	datapathConfig            *Config
	Rules                     map[string]*EveroutePolicyRuleEntry // rules database
	flowReplayChan            chan struct{}
	flowReplayMutex           sync.RWMutex
	ovsdbReconnectChan        chan struct{}

	AgentInfo *AgentConf
}

type AgentConf struct {
	EnableCNI bool // enable CNI in Everoute

	NodeName   string
	PodCIDR    []cnitypes.IPNet
	BridgeName string

	LocalGwName string
	LocalGwIP   net.IP
	LocalGwMac  net.HardwareAddr

	GatewayName string
	GatewayIP   net.IP
	GatewayMac  net.HardwareAddr
}

type Config struct {
	ManagedVDSMap map[string]string // map vds to ovsbr-name
}

type Endpoint struct {
	IPAddr     net.IP
	IPv6Addr   net.IP
	PortNo     uint32 // endpoint of port
	MacAddrStr string
	VlanID     uint16 // endpoint vlan id
	BridgeName string // bridge name that endpoint attached to
}

type EveroutePolicyRule struct {
	RuleID      string // Unique identifier for the rule
	Priority    int    // Priority for the rule (1..100. 100 is highest)
	SrcIPAddr   string // source IP addrss and mask
	DstIPAddr   string // Destination IP address and mask
	IPProtocol  uint8  // IP protocol number
	SrcPort     uint16 // Source port
	SrcPortMask uint16
	DstPort     uint16 // destination port
	DstPortMask uint16
	Action      string // rule action: 'accept' or 'deny'
}

type FlowEntry struct {
	Table    *ofctrl.Table
	Priority uint16
	FlowID   uint64
}

type EveroutePolicyRuleEntry struct {
	EveroutePolicyRule *EveroutePolicyRule
	Direction          uint8
	Tier               uint8
	RuleFlowMap        map[string]*FlowEntry
}

type RoundInfo struct {
	previousRoundNum uint64
	curRoundNum      uint64
}

// Datapath manager act as openflow controller:
// 1. event driven local endpoint info crud and related flow update,
// 2. collect local endpoint ip learned from different ovsbr(1 per vds), and sync it to management plane
func NewDatapathManager(datapathConfig *Config, ofPortIPAddressUpdateChan chan map[string]net.IP) *DpManager {
	datapathManager := new(DpManager)
	datapathManager.BridgeChainMap = make(map[string]map[string]Bridge)
	datapathManager.OvsdbDriverMap = make(map[string]map[string]*ovsdbDriver.OvsDriver)
	datapathManager.ControllerMap = make(map[string]map[string]*ofctrl.Controller)
	datapathManager.Rules = make(map[string]*EveroutePolicyRuleEntry)
	datapathManager.datapathConfig = datapathConfig
	datapathManager.localEndpointDB = cmap.New()
	datapathManager.AgentInfo = new(AgentConf)
	datapathManager.AgentInfo.EnableCNI = false
	datapathManager.flowReplayChan = make(chan struct{})
	datapathManager.flowReplayMutex = sync.RWMutex{}
	datapathManager.ovsdbReconnectChan = make(chan struct{})

	var wg sync.WaitGroup
	for vdsID, ovsbrname := range datapathConfig.ManagedVDSMap {
		wg.Add(1)
		go func(vdsID, ovsbrname string) {
			defer wg.Done()
			NewVDSForConfig(datapathManager, vdsID, ovsbrname)
		}(vdsID, ovsbrname)
	}
	wg.Wait()

	datapathManager.ofPortIPAddressUpdateChan = ofPortIPAddressUpdateChan

	return datapathManager
}

func (datapathManager *DpManager) InitializeDatapath(stopChan <-chan struct{}) {
	if err := datapathManager.removeControllers(); err != nil {
		log.Fatalf("Failed to clean old controller config, error: %v", err)
	}

	if err := datapathManager.addControllers(); err != nil {
		log.Fatalf("Failed to add new controller config, error: %v", err)
	}

	if !datapathManager.IsBridgesConnected() {
		datapathManager.WaitForBridgeConnected()
	}

	var wg sync.WaitGroup
	for vdsID := range datapathManager.datapathConfig.ManagedVDSMap {
		wg.Add(1)
		go func(vdsID string) {
			defer wg.Done()
			InitializeVDS(datapathManager, vdsID, stopChan)
		}(vdsID)
	}
	wg.Wait()

	var randOvsBr string
	for _, ovsbr := range datapathManager.datapathConfig.ManagedVDSMap {
		randOvsBr = ovsbr
		break
	}
	VswitchdUnixSock := fmt.Sprintf("%s/%s.%s", ovsVswitchdUnixDomainSockPath, randOvsBr, ovsVswitchdUnixDomainSockSuffix)
	go watchFile(VswitchdUnixSock, stopChan, datapathManager.flowReplayChan)
	go watchFile(ovsdbDomainSock, stopChan, datapathManager.ovsdbReconnectChan)

	go func() {
		for {
			select {
			case <-datapathManager.flowReplayChan:
				if err := datapathManager.replayFlows(); err != nil {
					log.Fatalf("Failed to replay flow, error: %v", err)
				}
			case <-datapathManager.ovsdbReconnectChan:
				if err := datapathManager.ovsdbConnectionReset(); err != nil {
					log.Fatalf("Failed to reset ovsbd connection while ovsdb recovery")
				}
			}
		}
	}()
}

func NewVDSForConfig(datapathManager *DpManager, vdsID, ovsbrname string) {
	// initialize vds bridge chain
	localBridge := NewLocalBridge(ovsbrname, datapathManager)
	policyBridge := NewPolicyBridge(ovsbrname, datapathManager)
	clsBridge := NewClsBridge(ovsbrname, datapathManager)
	uplinkBridge := NewUplinkBridge(ovsbrname, datapathManager)
	vdsBridgeMap := make(map[string]Bridge)
	vdsBridgeMap[LOCAL_BRIDGE_KEYWORD] = localBridge
	vdsBridgeMap[POLICY_BRIDGE_KEYWORD] = policyBridge
	vdsBridgeMap[CLS_BRIDGE_KEYWORD] = clsBridge
	vdsBridgeMap[UPLINK_BRIDGE_KEYWORD] = uplinkBridge

	// initialize of controller
	vdsOfControllerMap := make(map[string]*ofctrl.Controller)
	vdsOfControllerMap[LOCAL_BRIDGE_KEYWORD] = ofctrl.NewController(localBridge)
	vdsOfControllerMap[POLICY_BRIDGE_KEYWORD] = ofctrl.NewController(policyBridge)
	vdsOfControllerMap[CLS_BRIDGE_KEYWORD] = ofctrl.NewController(clsBridge)
	vdsOfControllerMap[UPLINK_BRIDGE_KEYWORD] = ofctrl.NewController(uplinkBridge)

	go vdsOfControllerMap[LOCAL_BRIDGE_KEYWORD].Listen("0")
	go vdsOfControllerMap[POLICY_BRIDGE_KEYWORD].Listen("0")
	go vdsOfControllerMap[CLS_BRIDGE_KEYWORD].Listen("0")
	go vdsOfControllerMap[UPLINK_BRIDGE_KEYWORD].Listen("0")

	// initialize ovsdbDriver
	vdsOvsdbDriverMap := make(map[string]*ovsdbDriver.OvsDriver)
	bridgeSuffixToNameMap := map[string]string{
		LOCAL_BRIDGE_KEYWORD:  localBridge.name,
		POLICY_BRIDGE_KEYWORD: policyBridge.name,
		CLS_BRIDGE_KEYWORD:    clsBridge.name,
		UPLINK_BRIDGE_KEYWORD: uplinkBridge.name,
	}
	var wg sync.WaitGroup
	var vdsOvsdbDriverMapMutex sync.RWMutex
	for suffix, brName := range bridgeSuffixToNameMap {
		wg.Add(1)
		go func(suffix, brName string, vdsOvsdbDriverMap map[string]*ovsdbDriver.OvsDriver) {
			defer wg.Done()
			vdsOvsdbDriverMapMutex.Lock()
			vdsOvsdbDriverMap[suffix] = ovsdbDriver.NewOvsDriverForExistBridge(brName)
			vdsOvsdbDriverMapMutex.Unlock()
		}(suffix, brName, vdsOvsdbDriverMap)
	}
	wg.Wait()

	// datapathManager config: write once, read many times, only agent initialize procedure would write this map,
	// thus lock it while write
	datapathManager.DpManagerMutex.Lock()
	datapathManager.BridgeChainMap[vdsID] = vdsBridgeMap
	datapathManager.ControllerMap[vdsID] = vdsOfControllerMap
	datapathManager.OvsdbDriverMap[vdsID] = vdsOvsdbDriverMap
	datapathManager.DpManagerMutex.Unlock()

	// setbridge work with openflow10 ~ openflow13
	protocols := map[string][]string{
		"protocols": {
			openflowProtorolVersion10, openflowProtorolVersion11, openflowProtorolVersion12, openflowProtorolVersion13,
		},
	}
	if err := vdsOvsdbDriverMap[LOCAL_BRIDGE_KEYWORD].UpdateBridge(protocols); err != nil {
		log.Fatalf("Failed to set local bridge: %v protocols, error: %v", vdsID, err)
	}
	if err := vdsOvsdbDriverMap[POLICY_BRIDGE_KEYWORD].UpdateBridge(protocols); err != nil {
		log.Fatalf("Failed to set policy bridge: %v protocols, error: %v", vdsID, err)
	}
	if err := vdsOvsdbDriverMap[CLS_BRIDGE_KEYWORD].UpdateBridge(protocols); err != nil {
		log.Fatalf("Failed to set cls bridge: %v protocols, error: %v", vdsID, err)
	}
	if err := vdsOvsdbDriverMap[UPLINK_BRIDGE_KEYWORD].UpdateBridge(protocols); err != nil {
		log.Fatalf("Failed to set uplink bridge: %v protocols, error: %v", vdsID, err)
	}
}

func InitializeVDS(datapathManager *DpManager, vdsID string, stopChan <-chan struct{}) {
	roundInfo, err := getRoundInfo(datapathManager.OvsdbDriverMap[vdsID][LOCAL_BRIDGE_KEYWORD])
	if err != nil {
		log.Fatalf("Failed to get Roundinfo from ovsdb: %v", err)
	}

	// Delete flow with curRoundNum cookie, for case: failed when restart process flow install.
	datapathManager.BridgeChainMap[vdsID][LOCAL_BRIDGE_KEYWORD].(*LocalBridge).OfSwitch.DeleteFlowByRoundInfo(roundInfo.curRoundNum)
	datapathManager.BridgeChainMap[vdsID][POLICY_BRIDGE_KEYWORD].(*PolicyBridge).OfSwitch.DeleteFlowByRoundInfo(roundInfo.curRoundNum)
	datapathManager.BridgeChainMap[vdsID][CLS_BRIDGE_KEYWORD].(*ClsBridge).OfSwitch.DeleteFlowByRoundInfo(roundInfo.curRoundNum)
	datapathManager.BridgeChainMap[vdsID][UPLINK_BRIDGE_KEYWORD].(*UplinkBridge).OfSwitch.DeleteFlowByRoundInfo(roundInfo.curRoundNum)

	// update cookie
	cookieAllocator := cookie.NewAllocator(roundInfo.curRoundNum)

	datapathManager.BridgeChainMap[vdsID][LOCAL_BRIDGE_KEYWORD].(*LocalBridge).OfSwitch.CookieAllocator = cookieAllocator
	datapathManager.BridgeChainMap[vdsID][POLICY_BRIDGE_KEYWORD].(*PolicyBridge).OfSwitch.CookieAllocator = cookieAllocator
	datapathManager.BridgeChainMap[vdsID][CLS_BRIDGE_KEYWORD].(*ClsBridge).OfSwitch.CookieAllocator = cookieAllocator
	datapathManager.BridgeChainMap[vdsID][UPLINK_BRIDGE_KEYWORD].(*UplinkBridge).OfSwitch.CookieAllocator = cookieAllocator

	datapathManager.BridgeChainMap[vdsID][LOCAL_BRIDGE_KEYWORD].BridgeInit()
	datapathManager.BridgeChainMap[vdsID][POLICY_BRIDGE_KEYWORD].BridgeInit()
	datapathManager.BridgeChainMap[vdsID][CLS_BRIDGE_KEYWORD].BridgeInit()
	datapathManager.BridgeChainMap[vdsID][UPLINK_BRIDGE_KEYWORD].BridgeInit()

	if err := SetPortNoFlood(datapathManager.BridgeChainMap[vdsID][LOCAL_BRIDGE_KEYWORD].(*LocalBridge).name,
		LOCAL_TO_POLICY_PORT); err != nil {
		log.Fatalf("Failed to set local to policy port with no flood port mode, %v", err)
	}

	// Delete flow with previousRoundNum cookie, and then persistent curRoundNum to ovsdb. We need to wait for long
	// enough to guarantee that all of the basic flow which we are still required updated with new roundInfo encoding to
	// flow cookie fields. But the time required to update all of the basic flow with updated roundInfo is
	// non-determined.
	// TODO  Implement a deterministic mechanism to control outdated flow flush procedure
	go func(vdsID string) {
		time.Sleep(time.Second * 15)

		datapathManager.BridgeChainMap[vdsID][LOCAL_BRIDGE_KEYWORD].(*LocalBridge).OfSwitch.DeleteFlowByRoundInfo(roundInfo.previousRoundNum)
		datapathManager.BridgeChainMap[vdsID][POLICY_BRIDGE_KEYWORD].(*PolicyBridge).OfSwitch.DeleteFlowByRoundInfo(roundInfo.previousRoundNum)
		datapathManager.BridgeChainMap[vdsID][CLS_BRIDGE_KEYWORD].(*ClsBridge).OfSwitch.DeleteFlowByRoundInfo(roundInfo.previousRoundNum)
		datapathManager.BridgeChainMap[vdsID][UPLINK_BRIDGE_KEYWORD].(*UplinkBridge).OfSwitch.DeleteFlowByRoundInfo(roundInfo.previousRoundNum)

		err := persistentRoundInfo(roundInfo.curRoundNum, datapathManager.OvsdbDriverMap[vdsID][LOCAL_BRIDGE_KEYWORD])
		if err != nil {
			log.Fatalf("Failed to persistent roundInfo into ovsdb: %v", err)
		}
	}(vdsID)
}

func (datapathManager *DpManager) replayFlows() error {
	log.Infof("flow replay")

	datapathManager.flowReplayMutex.Lock()
	defer datapathManager.flowReplayMutex.Unlock()

	if !datapathManager.IsBridgesConnected() {
		// 1 second retry interval is too long
		datapathManager.WaitForBridgeConnected()
	}

	// replay basic connectivity flow
	for vdsID := range datapathManager.datapathConfig.ManagedVDSMap {
		roundInfo, err := getRoundInfo(datapathManager.OvsdbDriverMap[vdsID]["local"])
		if err != nil {
			return fmt.Errorf("failed to get Roundinfo from ovsdb: %v", err)
		}
		cookieAllocator := cookie.NewAllocator(roundInfo.curRoundNum)

		datapathManager.BridgeChainMap[vdsID][LOCAL_BRIDGE_KEYWORD].(*LocalBridge).OfSwitch.CookieAllocator = cookieAllocator
		datapathManager.BridgeChainMap[vdsID][POLICY_BRIDGE_KEYWORD].(*PolicyBridge).OfSwitch.CookieAllocator = cookieAllocator
		datapathManager.BridgeChainMap[vdsID][CLS_BRIDGE_KEYWORD].(*ClsBridge).OfSwitch.CookieAllocator = cookieAllocator
		datapathManager.BridgeChainMap[vdsID][UPLINK_BRIDGE_KEYWORD].(*UplinkBridge).OfSwitch.CookieAllocator = cookieAllocator

		datapathManager.BridgeChainMap[vdsID][LOCAL_BRIDGE_KEYWORD].BridgeInit()
		datapathManager.BridgeChainMap[vdsID][POLICY_BRIDGE_KEYWORD].BridgeInit()
		datapathManager.BridgeChainMap[vdsID][CLS_BRIDGE_KEYWORD].BridgeInit()
		datapathManager.BridgeChainMap[vdsID][UPLINK_BRIDGE_KEYWORD].BridgeInit()
	}

	// replay local endpoint flow
	if err := datapathManager.ReplayLocalEndpointFlow(); err != nil {
		return fmt.Errorf("failed to replay local endpoint flow while vswitchd restart, error: %v", err)
	}

	// replay policy flow
	if err := datapathManager.ReplayMicroSegmentFlow(); err != nil {
		return fmt.Errorf("failed to replay microsegment flow while vswitchd restart, error: %v", err)
	}

	return nil
}

func (datapathManager *DpManager) ovsdbConnectionReset() error {
	for vdsID := range datapathManager.datapathConfig.ManagedVDSMap {
		if err := datapathManager.OvsdbDriverMap[vdsID][LOCAL_BRIDGE_KEYWORD].ReConnectOvsdb(); err != nil {
			return fmt.Errorf("failed to reconnect vds %v localBridge ovsdb, error: %v", vdsID, err)
		}
		if err := datapathManager.OvsdbDriverMap[vdsID][POLICY_BRIDGE_KEYWORD].ReConnectOvsdb(); err != nil {
			return fmt.Errorf("failed to reconnect vds %v policyBridge ovsdb, error: %v", vdsID, err)
		}
		if err := datapathManager.OvsdbDriverMap[vdsID][CLS_BRIDGE_KEYWORD].ReConnectOvsdb(); err != nil {
			return fmt.Errorf("failed to reconnect vds %v clsBridge ovsdb, error: %v", vdsID, err)
		}
		if err := datapathManager.OvsdbDriverMap[vdsID][UPLINK_BRIDGE_KEYWORD].ReConnectOvsdb(); err != nil {
			return fmt.Errorf("failed to reconnect vds %v uplinkBridge ovsdb, error: %v", vdsID, err)
		}
	}

	return nil
}

func (datapathManager *DpManager) ReplayLocalEndpointFlow() error {
	for endpointObj := range datapathManager.localEndpointDB.IterBuffered() {
		endpoint := endpointObj.Val.(*Endpoint)
		for vdsID, ovsbrname := range datapathManager.datapathConfig.ManagedVDSMap {
			if ovsbrname != endpoint.BridgeName {
				continue
			}

			err := datapathManager.BridgeChainMap[vdsID]["local"].AddLocalEndpoint(endpoint)
			if err != nil {
				return fmt.Errorf("failed to add local endpoint %v to vds %v : bridge %v, error: %v", endpoint.MacAddrStr, vdsID, ovsbrname, err)
			}

			break
		}
	}

	return nil
}

func (datapathManager *DpManager) ReplayMicroSegmentFlow() error {
	for ruleID, erPolicyRuleEntry := range datapathManager.Rules {
		for vdsID, bridgeChain := range datapathManager.BridgeChainMap {
			// Add new policy rule flow to datapath
			flowEntry, err := bridgeChain[POLICY_BRIDGE_KEYWORD].AddMicroSegmentRule(erPolicyRuleEntry.EveroutePolicyRule,
				erPolicyRuleEntry.Direction, erPolicyRuleEntry.Tier)
			if err != nil {
				return fmt.Errorf("failed to add microsegment rule to vdsID %v, bridge %s, error: %v", vdsID, bridgeChain["policy"], err)
			}
			// udpate new policy rule flow to datapath flow cache
			datapathManager.Rules[ruleID].RuleFlowMap[vdsID] = flowEntry
		}
	}

	return nil
}

func (datapathManager *DpManager) addControllers() error {
	for vdsID := range datapathManager.datapathConfig.ManagedVDSMap {
		if err := datapathManager.OvsdbDriverMap[vdsID][LOCAL_BRIDGE_KEYWORD].AddController(LOOP_BACK_ADDR,
			uint16(datapathManager.ControllerMap[vdsID][LOCAL_BRIDGE_KEYWORD].GetListenPort())); err != nil {
			return fmt.Errorf("failed to add local bridge controller to ovsdb, error: %v", err)
		}
		if err := datapathManager.OvsdbDriverMap[vdsID][POLICY_BRIDGE_KEYWORD].AddController(LOOP_BACK_ADDR,
			uint16(datapathManager.ControllerMap[vdsID][POLICY_BRIDGE_KEYWORD].GetListenPort())); err != nil {
			return fmt.Errorf("failed to add policy bridge controller to ovsdb, error: %v", err)
		}
		if err := datapathManager.OvsdbDriverMap[vdsID][CLS_BRIDGE_KEYWORD].AddController(LOOP_BACK_ADDR,
			uint16(datapathManager.ControllerMap[vdsID][CLS_BRIDGE_KEYWORD].GetListenPort())); err != nil {
			return fmt.Errorf("failed to add cls bridge controller to ovsdb, error: %v", err)
		}
		if err := datapathManager.OvsdbDriverMap[vdsID][UPLINK_BRIDGE_KEYWORD].AddController(LOOP_BACK_ADDR,
			uint16(datapathManager.ControllerMap[vdsID][UPLINK_BRIDGE_KEYWORD].GetListenPort())); err != nil {
			return fmt.Errorf("failed to add uplink bridge controller to ovsdb, error: %v", err)
		}
	}

	return nil
}

func (datapathManager *DpManager) removeControllers() error {
	for vdsID := range datapathManager.datapathConfig.ManagedVDSMap {
		if err := datapathManager.OvsdbDriverMap[vdsID][LOCAL_BRIDGE_KEYWORD].RemoveController(); err != nil {
			return fmt.Errorf("failed to remove local bridge controller from ovsdb, error: %v", err)
		}
		if err := datapathManager.OvsdbDriverMap[vdsID][POLICY_BRIDGE_KEYWORD].RemoveController(); err != nil {
			return fmt.Errorf("failed to remove policy bridge controller from ovsdb, error: %v", err)
		}
		if err := datapathManager.OvsdbDriverMap[vdsID][CLS_BRIDGE_KEYWORD].RemoveController(); err != nil {
			return fmt.Errorf("failed to remove cls bridge controller from ovsdb, error: %v", err)
		}
		if err := datapathManager.OvsdbDriverMap[vdsID][UPLINK_BRIDGE_KEYWORD].RemoveController(); err != nil {
			return fmt.Errorf("failed to remove uplink bridge controller from ovsdb, error: %v", err)
		}
	}

	return nil
}

func (datapathManager *DpManager) WaitForBridgeConnected() {
	for i := 0; i < 40; i++ {
		time.Sleep(1 * time.Second)
		if datapathManager.IsBridgesConnected() {
			return
		}
	}

	log.Fatalf("bridge chain Failed to connect")
}

func (datapathManager *DpManager) IsBridgesConnected() bool {
	var dpStatus bool = false

	for _, bridgeChain := range datapathManager.BridgeChainMap {
		if !bridgeChain[LOCAL_BRIDGE_KEYWORD].IsSwitchConnected() {
			return dpStatus
		}
		if !bridgeChain[POLICY_BRIDGE_KEYWORD].IsSwitchConnected() {
			return dpStatus
		}
		if !bridgeChain[CLS_BRIDGE_KEYWORD].IsSwitchConnected() {
			return dpStatus
		}
		if !bridgeChain[UPLINK_BRIDGE_KEYWORD].IsSwitchConnected() {
			return dpStatus
		}
	}

	dpStatus = true

	return dpStatus
}

func (datapathManager *DpManager) AddLocalEndpoint(endpoint *Endpoint) error {
	datapathManager.flowReplayMutex.Lock()
	defer datapathManager.flowReplayMutex.Unlock()

	for vdsID, ovsbrname := range datapathManager.datapathConfig.ManagedVDSMap {
		if ovsbrname == endpoint.BridgeName {
			if ep, _ := datapathManager.localEndpointDB.Get(fmt.Sprintf("%s-%d", ovsbrname, endpoint.PortNo)); ep != nil {
				log.Errorf("Already added local endpoint: %v", ep)
				return nil
			}

			err := datapathManager.BridgeChainMap[vdsID][LOCAL_BRIDGE_KEYWORD].AddLocalEndpoint(endpoint)
			if err != nil {
				return fmt.Errorf("failed to add local endpoint %v to vds %v : bridge %v, error: %v", endpoint.MacAddrStr, vdsID, ovsbrname, err)
			}

			datapathManager.localEndpointDB.Set(fmt.Sprintf("%s-%d", ovsbrname, endpoint.PortNo), endpoint)
			break
		}
	}

	return nil
}

func (datapathManager *DpManager) UpdateLocalEndpoint(newEndpoint, oldEndpoint *Endpoint) error {
	datapathManager.flowReplayMutex.Lock()
	defer datapathManager.flowReplayMutex.Unlock()
	var err error

	for vdsID, ovsbrname := range datapathManager.datapathConfig.ManagedVDSMap {
		if ovsbrname == newEndpoint.BridgeName {
			oldEP, _ := datapathManager.localEndpointDB.Get(fmt.Sprintf("%s-%d", ovsbrname, oldEndpoint.PortNo))
			if oldEP == nil {
				return fmt.Errorf("old local endpoint: %v not found", oldEP)
			}
			ep := oldEP.(*Endpoint)
			// NOTE copy ip addr cached in oldEP to newEndpoint can skip ip address learning operation
			learnedIP := make(net.IP, len(ep.IPAddr))
			copy(learnedIP, ep.IPAddr)
			newEndpoint.IPAddr = learnedIP

			err = datapathManager.BridgeChainMap[vdsID][LOCAL_BRIDGE_KEYWORD].RemoveLocalEndpoint(oldEndpoint)
			if err != nil {
				return fmt.Errorf("failed to remove old local endpoint %v from vds %v : bridge %v, error: %v", oldEndpoint.MacAddrStr, vdsID, ovsbrname, err)
			}
			datapathManager.localEndpointDB.Remove(fmt.Sprintf("%s-%d", ovsbrname, oldEndpoint.PortNo))

			if newEP, _ := datapathManager.localEndpointDB.Get(fmt.Sprintf("%s-%d", ovsbrname, newEndpoint.PortNo)); newEP != nil {
				return fmt.Errorf("new local endpoint: %v already exits", newEP)
			}
			err = datapathManager.BridgeChainMap[vdsID][LOCAL_BRIDGE_KEYWORD].AddLocalEndpoint(newEndpoint)
			if err != nil {
				return fmt.Errorf("failed to add local endpoint %v to vds %v : bridge %v, error: %v", newEndpoint.MacAddrStr, vdsID, ovsbrname, err)
			}

			datapathManager.localEndpointDB.Set(fmt.Sprintf("%s-%d", ovsbrname, newEndpoint.PortNo), newEndpoint)
			break
		}
	}

	return nil
}

func (datapathManager *DpManager) RemoveLocalEndpoint(endpoint *Endpoint) error {
	datapathManager.flowReplayMutex.Lock()
	defer datapathManager.flowReplayMutex.Unlock()

	for vdsID, ovsbrname := range datapathManager.datapathConfig.ManagedVDSMap {
		if ovsbrname != endpoint.BridgeName {
			continue
		}

		if ep, _ := datapathManager.localEndpointDB.Get(fmt.Sprintf("%s-%d", ovsbrname, endpoint.PortNo)); ep == nil {
			return fmt.Errorf("Endpoint not found for %v-%v", ovsbrname, endpoint.PortNo)
		}

		err := datapathManager.BridgeChainMap[vdsID][LOCAL_BRIDGE_KEYWORD].RemoveLocalEndpoint(endpoint)
		if err != nil {
			return fmt.Errorf("failed to remove local endpoint %v to vds %v : bridge %v, error: %v", endpoint.MacAddrStr, vdsID, ovsbrname, err)
		}

		datapathManager.localEndpointDB.Remove(fmt.Sprintf("%s-%d", ovsbrname, endpoint.PortNo))
		break
	}

	return nil
}

func (datapathManager *DpManager) AddEveroutePolicyRule(rule *EveroutePolicyRule, direction uint8, tier uint8) error {
	// check if we already have the rule
	datapathManager.flowReplayMutex.Lock()
	defer datapathManager.flowReplayMutex.Unlock()

	if _, ok := datapathManager.Rules[rule.RuleID]; ok {
		oldRule := datapathManager.Rules[rule.RuleID].EveroutePolicyRule

		if RuleIsSame(oldRule, rule) {
			log.Infof("Rule already exists. new rule: {%+v}, old rule: {%+v}", rule, oldRule)
			return nil
		}

		return fmt.Errorf("different rule %v and %v with same ruleID", oldRule, rule)
	}

	log.Infof("Received AddRule: %+v", rule)
	ruleFlowMap := make(map[string]*FlowEntry)
	// Install policy rule flow to datapath
	for vdsID, bridgeChain := range datapathManager.BridgeChainMap {
		flowEntry, err := bridgeChain[POLICY_BRIDGE_KEYWORD].AddMicroSegmentRule(rule, direction, tier)
		if err != nil {
			return fmt.Errorf("failed to add microsegment rule to vdsID %v, bridge %s, error: %v", vdsID, bridgeChain[POLICY_BRIDGE_KEYWORD], err)
		}
		ruleFlowMap[vdsID] = flowEntry
	}

	// save the rule. ruleFlowMap need deepcopy, NOTE
	pRule := EveroutePolicyRuleEntry{
		EveroutePolicyRule: rule,
		Direction:          direction,
		Tier:               tier,
		RuleFlowMap:        ruleFlowMap,
	}
	datapathManager.Rules[rule.RuleID] = &pRule

	return nil
}

func (datapathManager *DpManager) RemoveEveroutePolicyRule(rule *EveroutePolicyRule) error {
	datapathManager.flowReplayMutex.Lock()
	defer datapathManager.flowReplayMutex.Unlock()

	for vdsID := range datapathManager.BridgeChainMap {
		pRule := datapathManager.Rules[rule.RuleID]
		if pRule == nil {
			return fmt.Errorf("rule %v not found when deleting", rule)
		}
		err := ofctrl.DeleteFlow(pRule.RuleFlowMap[vdsID].Table, pRule.RuleFlowMap[vdsID].Priority, pRule.RuleFlowMap[vdsID].FlowID)
		if err != nil {
			return fmt.Errorf("failed to delete flow for rule: %+v. Err: %v", rule, err)
		}
	}

	delete(datapathManager.Rules, rule.RuleID)

	return nil
}

func RuleIsSame(r1, r2 *EveroutePolicyRule) bool {
	return reflect.DeepEqual(*r1, *r2)
}

func DeepCopyMap(theMap interface{}) interface{} {
	maptype := reflect.TypeOf(theMap)

	srcMap := reflect.ValueOf(theMap)
	dstMap := reflect.MakeMapWithSize(maptype, srcMap.Len())

	for _, key := range srcMap.MapKeys() {
		dstMap.SetMapIndex(key, srcMap.MapIndex(key))
	}
	return dstMap.Interface()
}

func getRoundInfo(ovsdbDriver *ovsdbDriver.OvsDriver) (*RoundInfo, error) {
	var num uint64
	var err error

	externalIds, err := ovsdbDriver.GetExternalIds()
	if err != nil {
		return nil, fmt.Errorf("failed to get ovsdb externalids: %v", err)
	}

	if len(externalIds) == 0 {
		log.Infof("Bridge's external-ids are empty")
		return &RoundInfo{
			curRoundNum: uint64(1),
		}, nil
	}

	roundNum, exists := externalIds[datapathRestartRound]
	if !exists {
		log.Infof("Bridge's external-ids don't contain ofnetRestartRound field")
		return &RoundInfo{
			curRoundNum: uint64(1),
		}, nil
	}

	num, err = strconv.ParseUint(roundNum, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("bad format of round number: %+v, parse error: %+v", roundNum, err)
	}

	return &RoundInfo{
		previousRoundNum: num,
		curRoundNum:      num + 1,
	}, nil
}

func persistentRoundInfo(curRoundNum uint64, ovsdbDriver *ovsdbDriver.OvsDriver) error {
	externalIds, err := ovsdbDriver.GetExternalIds()
	if err != nil {
		return err
	}

	externalIds[datapathRestartRound] = fmt.Sprint(curRoundNum)

	return ovsdbDriver.SetExternalIds(externalIds)
}

// ParseIPAddrMaskString Parse IP addr string
func ParseIPAddrMaskString(ipAddr string) (*net.IP, *net.IP, error) {
	if strings.Contains(ipAddr, "/") {
		ipDav, ipNet, err := net.ParseCIDR(ipAddr)
		if err != nil {
			log.Errorf("Error parsing ip %s. Err: %v", ipAddr, err)
			return nil, nil, err
		}

		ipMask := net.ParseIP(IP_BROADCAST_ADDR).Mask(ipNet.Mask)

		return &ipDav, &ipMask, nil
	}

	ipDa := net.ParseIP(ipAddr)
	if ipDa == nil {
		return nil, nil, errors.New("failed to parse ip address")
	}

	ipMask := net.ParseIP(IP_BROADCAST_ADDR)

	return &ipDa, &ipMask, nil
}

func SetPortNoFlood(bridge string, ofport int) error {
	cmdStr := fmt.Sprintf("ovs-ofctl mod-port %s %d no-flood", bridge, ofport)
	cmd := exec.Command("/bin/sh", "-c", cmdStr)

	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("fail to set no-flood config for port %d on bridge %s: %v, stderr: %s", ofport, bridge, err,
			stderr.String())
	}
	return nil
}

func watchFile(fileName string, stopChan <-chan struct{}, recoveryEventChan chan struct{}) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatalf("Failed to watch file: %v", fileName)
	}

	if err := addWatchFile(watcher, fileName); err != nil {
		log.Fatalf("Failed to add file to watcher, error: %v", err)
	}

	createChan := make(chan bool)
	removeChan := make(chan bool)
	go func() {
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					continue
				}
				if event.Op&fsnotify.Create == fsnotify.Create {
					createChan <- true
				}
				if event.Op&fsnotify.Remove == fsnotify.Remove {
					removeChan <- true
				}
			case err := <-watcher.Errors:
				// Error chan need handle
				log.Errorf("File watcher error: %v", err)
			}
		}
	}()

	go func(watcher *fsnotify.Watcher) {
		for {
			select {
			case <-removeChan:
				log.Infof("Deleted unix domain sock : %v", fileName)

				// wait for watched file recovery (e.g ovsdb/vswitchd failover). we need timeout constant, 10s is temporary value. FIXME
				if err := waitUntilFileCreate(fileName, 10*time.Second); err != nil {
					log.Infof("Time out for wait file restore")
				}
				// watch vswitchd doamain socket again
				if err := addWatchFile(watcher, fileName); err != nil {
					log.Fatalf("Failed to watch file after removed file was re-added")
				}

				// trigger datapathManager faileover event (e.g flow replay or ovsdb connection reset)
				recoveryEventChan <- struct{}{}
			case <-createChan:
				log.Infof("Created unix domain sock : %v", fileName)
			}
		}
	}(watcher)

	<-stopChan
	watcher.Close()
}

func addWatchFile(watcher *fsnotify.Watcher, filepath string) error {
	if err := watcher.Add(filepath); err != nil {
		return err
	}
	log.Infof("Add file watcher for file: %v", filepath)

	return nil
}

func waitUntilFileCreate(fileName string, timeout time.Duration) error {
	return wait.PollImmediate(10*time.Millisecond, timeout, func() (do bool, err error) {
		if _, err := os.Stat(fileName); os.IsNotExist(err) {
			return false, nil
		}

		return true, nil
	})
}
