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
	"errors"
	"fmt"
	"net"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/contiv/libOpenflow/openflow13"
	"github.com/contiv/ofnet/ofctrl"
	"github.com/contiv/ofnet/ofctrl/cookie"
	"github.com/contiv/ofnet/ovsdbDriver"
	cmap "github.com/streamrail/concurrent-map"
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
	datapathRestartRound string = "datapathRestartRound"
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
	AddMicroSegmentRule(rule *EveroutePolicyRule, direction uint8, tier uint8) (*ofctrl.Flow, error)
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
	BridgeChainMap map[string]map[string]Bridge                 // map vds to bridge instance map
	OvsdbDriverMap map[string]map[string]*ovsdbDriver.OvsDriver // map vds to bridge ovsdbDriver map
	ControllerMap  map[string]map[string]*ofctrl.Controller

	localEndpointDB           cmap.ConcurrentMap       // list of local endpoint map
	ofPortIPAddressUpdateChan chan map[string][]net.IP // map bridgename-ofport to endpoint ips
	datapathConfig            *Config
	ruleMux                   sync.RWMutex
	Rules                     map[string]*EveroutePolicyRuleEntry // rules database
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

type EveroutePolicyRuleEntry struct {
	EveroutePolicyRule *EveroutePolicyRule
	RuleFlowMap        map[string]*ofctrl.Flow
}

type RoundInfo struct {
	previousRoundNum uint64
	curRoundNum      uint64
}

// Datapath manager act as openflow controller:
// 1. event driven local endpoint info crud and related flow update,
// 2. collect local endpoint ip learned from different ovsbr(1 per vds), and sync it to management plane
func NewDatapathManager(datapathConfig *Config, ofPortIPAddressUpdateChan chan map[string][]net.IP) *DpManager {
	datapathManager := new(DpManager)
	datapathManager.BridgeChainMap = make(map[string]map[string]Bridge)
	datapathManager.OvsdbDriverMap = make(map[string]map[string]*ovsdbDriver.OvsDriver)
	datapathManager.ControllerMap = make(map[string]map[string]*ofctrl.Controller)
	datapathManager.Rules = make(map[string]*EveroutePolicyRuleEntry)
	datapathManager.datapathConfig = datapathConfig
	datapathManager.localEndpointDB = cmap.New()

	var vdsCount int = 0
	// vdsID equals to ovsbrname
	for vdsID, ovsbrname := range datapathConfig.ManagedVDSMap {

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
		datapathManager.BridgeChainMap[vdsID] = vdsBridgeMap

		// initialize of controller
		vdsOfControllerMap := make(map[string]*ofctrl.Controller)
		vdsOfControllerMap[LOCAL_BRIDGE_KEYWORD] = ofctrl.NewController(localBridge)
		vdsOfControllerMap[POLICY_BRIDGE_KEYWORD] = ofctrl.NewController(policyBridge)
		vdsOfControllerMap[CLS_BRIDGE_KEYWORD] = ofctrl.NewController(clsBridge)
		vdsOfControllerMap[UPLINK_BRIDGE_KEYWORD] = ofctrl.NewController(uplinkBridge)
		datapathManager.ControllerMap[vdsID] = vdsOfControllerMap

		go vdsOfControllerMap[LOCAL_BRIDGE_KEYWORD].Listen("0")
		go vdsOfControllerMap[POLICY_BRIDGE_KEYWORD].Listen("0")
		go vdsOfControllerMap[CLS_BRIDGE_KEYWORD].Listen("0")
		go vdsOfControllerMap[UPLINK_BRIDGE_KEYWORD].Listen("0")

		// initialize ovsdbDriver
		vdsOvsdbDriverMap := make(map[string]*ovsdbDriver.OvsDriver)
		vdsOvsdbDriverMap[LOCAL_BRIDGE_KEYWORD] = ovsdbDriver.NewOvsDriver(localBridge.name)
		vdsOvsdbDriverMap[POLICY_BRIDGE_KEYWORD] = ovsdbDriver.NewOvsDriver(policyBridge.name)
		vdsOvsdbDriverMap[CLS_BRIDGE_KEYWORD] = ovsdbDriver.NewOvsDriver(clsBridge.name)
		vdsOvsdbDriverMap[UPLINK_BRIDGE_KEYWORD] = ovsdbDriver.NewOvsDriver(uplinkBridge.name)
		datapathManager.OvsdbDriverMap[vdsID] = vdsOvsdbDriverMap

		if err := datapathManager.OvsdbDriverMap[vdsID][LOCAL_BRIDGE_KEYWORD].AddController(LOOP_BACK_ADDR,
			uint16(vdsOfControllerMap[LOCAL_BRIDGE_KEYWORD].GetListenPort())); err != nil {
			log.Fatalf("Failed to add local bridge controller to ovsdb, error: %v", err)
		}
		if err := datapathManager.OvsdbDriverMap[vdsID][POLICY_BRIDGE_KEYWORD].AddController(LOOP_BACK_ADDR,
			uint16(vdsOfControllerMap[POLICY_BRIDGE_KEYWORD].GetListenPort())); err != nil {
			log.Fatalf("Failed to add policy bridge controller to ovsdb, error: %v", err)
		}
		if err := datapathManager.OvsdbDriverMap[vdsID][CLS_BRIDGE_KEYWORD].AddController(LOOP_BACK_ADDR,
			uint16(vdsOfControllerMap[CLS_BRIDGE_KEYWORD].GetListenPort())); err != nil {
			log.Fatalf("Failed to add cls bridge controller to ovsdb, error: %v", err)
		}
		if err := datapathManager.OvsdbDriverMap[vdsID][UPLINK_BRIDGE_KEYWORD].AddController(LOOP_BACK_ADDR,
			uint16(vdsOfControllerMap[UPLINK_BRIDGE_KEYWORD].GetListenPort())); err != nil {
			log.Fatalf("Failed to add uplink bridge controller to ovsdb, error: %v", err)
		}

		vdsCount++
	}

	datapathManager.ofPortIPAddressUpdateChan = ofPortIPAddressUpdateChan

	return datapathManager
}

func (datapathManager *DpManager) InitializeDatapath() {
	if !datapathManager.IsBridgesConnected() {
		datapathManager.WaitForBridgeConnected()
	}

	var randID string
	for vdsID := range datapathManager.datapathConfig.ManagedVDSMap {
		randID = vdsID
		break
	}
	roundInfo, err := getRoundInfo(datapathManager.OvsdbDriverMap[randID][LOCAL_BRIDGE_KEYWORD])
	if err != nil {
		log.Fatalf("Failed to get Roundinfo from ovsdb: %v", err)
	}

	// Delete flow with curRoundNum cookie, for case: failed when restart process flow install.
	for vdsID := range datapathManager.datapathConfig.ManagedVDSMap {
		datapathManager.BridgeChainMap[vdsID][LOCAL_BRIDGE_KEYWORD].(*LocalBridge).OfSwitch.DeleteFlowByRoundInfo(roundInfo.curRoundNum)
		datapathManager.BridgeChainMap[vdsID][POLICY_BRIDGE_KEYWORD].(*PolicyBridge).OfSwitch.DeleteFlowByRoundInfo(roundInfo.curRoundNum)
		datapathManager.BridgeChainMap[vdsID][CLS_BRIDGE_KEYWORD].(*ClsBridge).OfSwitch.DeleteFlowByRoundInfo(roundInfo.curRoundNum)
		datapathManager.BridgeChainMap[vdsID][UPLINK_BRIDGE_KEYWORD].(*UplinkBridge).OfSwitch.DeleteFlowByRoundInfo(roundInfo.curRoundNum)
	}

	cookieAllocator := cookie.NewAllocator(roundInfo.curRoundNum)

	for vdsID := range datapathManager.datapathConfig.ManagedVDSMap {
		datapathManager.BridgeChainMap[vdsID][LOCAL_BRIDGE_KEYWORD].(*LocalBridge).OfSwitch.CookieAllocator = cookieAllocator
		datapathManager.BridgeChainMap[vdsID][POLICY_BRIDGE_KEYWORD].(*PolicyBridge).OfSwitch.CookieAllocator = cookieAllocator
		datapathManager.BridgeChainMap[vdsID][CLS_BRIDGE_KEYWORD].(*ClsBridge).OfSwitch.CookieAllocator = cookieAllocator
		datapathManager.BridgeChainMap[vdsID][UPLINK_BRIDGE_KEYWORD].(*UplinkBridge).OfSwitch.CookieAllocator = cookieAllocator

		datapathManager.BridgeChainMap[vdsID][LOCAL_BRIDGE_KEYWORD].BridgeInit()
		datapathManager.BridgeChainMap[vdsID][POLICY_BRIDGE_KEYWORD].BridgeInit()
		datapathManager.BridgeChainMap[vdsID][CLS_BRIDGE_KEYWORD].BridgeInit()
		datapathManager.BridgeChainMap[vdsID][UPLINK_BRIDGE_KEYWORD].BridgeInit()

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

func (datapathManager *DpManager) UpdateLocalEndpoint() {
}

func (datapathManager *DpManager) RemoveLocalEndpoint(endpoint *Endpoint) error {
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
	datapathManager.ruleMux.RLock()
	if _, ok := datapathManager.Rules[rule.RuleID]; ok {
		oldRule := datapathManager.Rules[rule.RuleID].EveroutePolicyRule

		if RuleIsSame(oldRule, rule) {
			log.Infof("Rule already exists. new rule: {%+v}, old rule: {%+v}", rule, oldRule)
		} else {
			datapathManager.ruleMux.RUnlock()
			log.Fatalf("Different rule %v and %v with same ruleId.", oldRule, rule)
		}
	}
	datapathManager.ruleMux.RUnlock()

	log.Infof("Received AddRule: %+v", rule)
	ruleFlowMap := make(map[string]*ofctrl.Flow)
	// Install policy rule flow to datapath
	for vdsID, bridgeChain := range datapathManager.BridgeChainMap {
		ruleFlow, err := bridgeChain[POLICY_BRIDGE_KEYWORD].AddMicroSegmentRule(rule, direction, tier)
		if err != nil {
			return fmt.Errorf("failed to add microsegment rule to vdsID %v, bridge %s, error: %v", vdsID, bridgeChain[POLICY_BRIDGE_KEYWORD], err)
		}
		ruleFlowMap[vdsID] = ruleFlow
	}

	// save the rule. ruleFlowMap need deepcopy, NOTE
	pRule := EveroutePolicyRuleEntry{
		EveroutePolicyRule: rule,
		RuleFlowMap:        ruleFlowMap,
	}
	datapathManager.ruleMux.Lock()
	datapathManager.Rules[rule.RuleID] = &pRule
	datapathManager.ruleMux.Unlock()

	return nil
}

func (datapathManager *DpManager) RemoveEveroutePolicyRule(rule *EveroutePolicyRule) error {
	datapathManager.ruleMux.Lock()
	defer datapathManager.ruleMux.Unlock()

	for vdsID := range datapathManager.BridgeChainMap {
		pRule := datapathManager.Rules[rule.RuleID]
		if pRule == nil {
			return fmt.Errorf("rule %v not found when deleting", rule)
		}

		err := pRule.RuleFlowMap[vdsID].Delete()
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
