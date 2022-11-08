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
	"github.com/contiv/libOpenflow/protocol"
	"github.com/contiv/ofnet/ofctrl"
	"github.com/contiv/ofnet/ofctrl/cookie"
	"github.com/contiv/ofnet/ovsdbDriver"
	"github.com/fsnotify/fsnotify"
	cmap "github.com/orcaman/concurrent-map"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/klog"

	policycache "github.com/everoute/everoute/pkg/agent/controller/policy/cache"
	"github.com/everoute/everoute/pkg/apis/rpc/v1alpha1"
	"github.com/everoute/everoute/pkg/constants"
	"github.com/everoute/everoute/pkg/utils"
)

//nolint
const (
	HIGH_MATCH_FLOW_PRIORITY            = 300
	MID_MATCH_FLOW_PRIORITY             = 200
	NORMAL_MATCH_FLOW_PRIORITY          = 100
	DEFAULT_DROP_FLOW_PRIORITY          = 70
	GLOBAL_DEFAULT_POLICY_FLOW_PRIORITY = 40
	DEFAULT_FLOW_MISS_PRIORITY          = 10
	FLOW_MATCH_OFFSET                   = 3
)

//nolint
const (
	POLICY_TIER1 = 50
	POLICY_TIER2 = 100
	POLICY_TIER3 = 150
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
	FLOW_ROUND_NUM_LENGTH           = 4
	FLOW_SEQ_NUM_LENGTH             = 28
	FLOW_ROUND_NUM_MASK             = 0xf0000000
	FLOW_SEQ_NUM_MASK               = 0x0fffffff
	DEFAULT_POLICY_ENFORCEMENT_MODE = "work"
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

	IPAddressTimeout                        = 60
	IPAddressCacheUpdateInterval            = 5
	LocalBridgeL2ForwardingTableHardTimeout = 300
	LocalBridgeL2ForwardingTableIdleTimeout = 300
	ClsBridgeL2ForwardingTableHardTimeout   = 300
	ClsBridgeL2ForwardingTableIdleTimeout   = 300
	MaxIPAddressLearningFrenquency          = 5

	LocalToPolicySuffix = "local-to-policy"
	PolicyToLocalSuffix = "policy-to-local"
	PolicyToClsSuffix   = "policy-to-cls"
	ClsToPolicySuffix   = "cls-to-policy"
	ClsToUplinkSuffix   = "cls-to-uplink"
	UplinkToClsSuffix   = "uplink-to-cls"

	InternalIngressRulePrefix = "/INTERNAL_INGRESS_POLICY/internal/ingress/-"
	InternalEgressRulePrefix  = "/INTERNAL_EGRESS_POLICY/internal/egress/-"

	MaxRoundNum = 15

	MaxArpChanCache = 100

	MaxCleanConntrackChanSize  = 2000
	MaxCleanConntrackWorkerNum = 5
)

type Bridge interface {
	BridgeInit()
	BridgeReset()

	BridgeInitCNI()

	AddLocalEndpoint(endpoint *Endpoint) error
	RemoveLocalEndpoint(endpoint *Endpoint) error
	AddVNFInstance() error
	RemoveVNFInstance() error

	AddSFCRule() error
	RemoveSFCRule() error
	AddMicroSegmentRule(rule *EveroutePolicyRule, direction uint8, tier uint8, mode string) (*FlowEntry, error)
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
	DpManagerMutex     sync.Mutex
	BridgeChainMap     map[string]map[string]Bridge                 // map vds to bridge instance map
	OvsdbDriverMap     map[string]map[string]*ovsdbDriver.OvsDriver // map vds to bridge ovsdbDriver map
	ControllerMap      map[string]map[string]*ofctrl.Controller
	BridgeChainPortMap map[string]map[string]uint32 // map vds to patch port to ofport-num map

	localEndpointDB           cmap.ConcurrentMap     // list of local endpoint map
	ofPortIPAddressUpdateChan chan map[string]net.IP // map bridgename-ofport to endpoint ips
	datapathConfig            *Config
	Rules                     map[string]*EveroutePolicyRuleEntry // rules database
	FlowIDToRules             map[uint64]*EveroutePolicyRuleEntry
	flowReplayChan            chan struct{}
	flowReplayMutex           sync.RWMutex
	ovsdbReconnectChan        chan struct{}
	cleanConntrackChan        chan EveroutePolicyRule // clean conntrack entries for rule in chan

	ArpChan chan protocol.ARP

	AgentInfo *AgentConf
}

type AgentConf struct {
	EnableCNI bool // enable CNI in Everoute

	NodeName   string
	PodCIDR    []cnitypes.IPNet
	BridgeName string

	ClusterCIDR *cnitypes.IPNet

	LocalGwName   string
	LocalGwIP     net.IP
	LocalGwMac    net.HardwareAddr
	LocalGwOfPort uint32

	GatewayName string
	GatewayIP   net.IP
	GatewayMac  net.HardwareAddr
}

type Config struct {
	ManagedVDSMap map[string]string // map vds to ovsbr-name
	InternalIPs   []string          // internal IPs
}

type Endpoint struct {
	InterfaceName        string // interface name that endpoint attached to
	IPAddr               net.IP
	IPAddrMutex          sync.RWMutex
	IPAddrLastUpdateTime time.Time
	IPv6Addr             net.IP
	PortNo               uint32 // endpoint of port
	MacAddrStr           string
	VlanID               uint16 // endpoint vlan id
	BridgeName           string // bridge name that endpoint attached to
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
	Action      string // rule action: 'allow' or 'deny'
}

const (
	EveroutePolicyAllow string = "allow"
	EveroutePolicyDeny  string = "deny"
)

type FlowEntry struct {
	Table    *ofctrl.Table
	Priority uint16
	FlowID   uint64
}

type EveroutePolicyRuleEntry struct {
	EveroutePolicyRule  *EveroutePolicyRule
	Direction           uint8
	Tier                uint8
	Mode                string
	RuleFlowMap         map[string]*FlowEntry
	PolicyRuleReference sets.String
}

type RoundInfo struct {
	previousRoundNum uint64
	curRoundNum      uint64
}

type PolicyInfo struct {
	Dir    uint8
	Action string
	Mode   string
	Item   []PolicyItem
}
type PolicyItem struct {
	Name       string
	Namespace  string
	PolicyType policycache.PolicyType
}

// Datapath manager act as openflow controller:
// 1. event driven local endpoint info crud and related flow update,
// 2. collect local endpoint ip learned from different ovsbr(1 per vds), and sync it to management plane
func NewDatapathManager(datapathConfig *Config, ofPortIPAddressUpdateChan chan map[string]net.IP) *DpManager {
	datapathManager := new(DpManager)
	datapathManager.BridgeChainMap = make(map[string]map[string]Bridge)
	datapathManager.BridgeChainPortMap = make(map[string]map[string]uint32)
	datapathManager.OvsdbDriverMap = make(map[string]map[string]*ovsdbDriver.OvsDriver)
	datapathManager.ControllerMap = make(map[string]map[string]*ofctrl.Controller)
	datapathManager.Rules = make(map[string]*EveroutePolicyRuleEntry)
	datapathManager.FlowIDToRules = make(map[uint64]*EveroutePolicyRuleEntry)
	datapathManager.datapathConfig = datapathConfig
	datapathManager.localEndpointDB = cmap.New()
	datapathManager.AgentInfo = new(AgentConf)
	datapathManager.AgentInfo.EnableCNI = false
	datapathManager.flowReplayChan = make(chan struct{})
	datapathManager.flowReplayMutex = sync.RWMutex{}
	datapathManager.ovsdbReconnectChan = make(chan struct{})
	datapathManager.cleanConntrackChan = make(chan EveroutePolicyRule, MaxCleanConntrackChanSize)
	datapathManager.ArpChan = make(chan protocol.ARP, MaxArpChanCache)

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
	if !datapathManager.IsBridgesConnected() {
		datapathManager.WaitForBridgeConnected()
	}

	var wg sync.WaitGroup
	for vdsID, ovsbrName := range datapathManager.datapathConfig.ManagedVDSMap {
		wg.Add(1)
		go func(vdsID, ovsbrName string) {
			defer wg.Done()
			InitializeVDS(datapathManager, vdsID, ovsbrName, stopChan)
		}(vdsID, ovsbrName)
	}
	wg.Wait()

	// add rules for internalIP
	for index, internalIP := range datapathManager.datapathConfig.InternalIPs {
		datapathManager.addIntenalIP(internalIP, index)
	}
	// add internal ip handle
	if len(datapathManager.datapathConfig.InternalIPs) != 0 {
		go datapathManager.syncIntenalIPs(stopChan)
	}

	go watchFile(ovsdbDomainSock, stopChan, datapathManager.ovsdbReconnectChan)

	go func() {
		for range datapathManager.ovsdbReconnectChan {
			if err := datapathManager.ovsdbConnectionReset(); err != nil {
				log.Fatalf("Failed to reset ovsbd connection while ovsdb recovery")
			}
		}
	}()

	for i := 0; i < MaxCleanConntrackWorkerNum; i++ {
		go wait.Until(datapathManager.cleanConntrackWorker, time.Second, stopChan)
	}

	bridgeKeywordList := []string{LOCAL_BRIDGE_KEYWORD, POLICY_BRIDGE_KEYWORD, CLS_BRIDGE_KEYWORD, UPLINK_BRIDGE_KEYWORD}
	for vdsID := range datapathManager.datapathConfig.ManagedVDSMap {
		for _, bridgeKeyword := range bridgeKeywordList {
			go func(vdsID, bridgeKeyword string) {
				for range datapathManager.ControllerMap[vdsID][bridgeKeyword].DisconnChan {
					log.Infof("Received vds %v bridge %v reconnect event", vdsID, bridgeKeyword)
					if err := datapathManager.replayVDSFlow(vdsID, bridgeKeyword); err != nil {
						log.Fatalf("Failed to replay vds %v, %v flow, error: %v", vdsID, bridgeKeyword, err)
					}
				}
			}(vdsID, bridgeKeyword)
		}
	}
}

func (datapathManager *DpManager) GetChainBridge() []string {
	datapathManager.flowReplayMutex.RLock()
	defer datapathManager.flowReplayMutex.RUnlock()

	var out []string
	for _, br := range datapathManager.datapathConfig.ManagedVDSMap {
		out = append(out, br)
	}

	return out
}

func (datapathManager *DpManager) GetPolicyByFlowID(flowID ...uint64) []*PolicyInfo {
	datapathManager.flowReplayMutex.RLock()
	defer datapathManager.flowReplayMutex.RUnlock()

	var policyInfoList []*PolicyInfo

	for _, id := range flowID {
		if id == 0 {
			continue
		}
		item := datapathManager.FlowIDToRules[id]
		if item != nil {
			policyInfo := &PolicyInfo{
				Dir:    item.Direction,
				Action: item.EveroutePolicyRule.Action,
				Mode:   item.Mode,
			}
			for _, p := range item.PolicyRuleReference.List() {
				policyInfo.Item = append(policyInfo.Item, PolicyItem{
					Name:       strings.Split(p, "/")[1],
					Namespace:  strings.Split(p, "/")[0],
					PolicyType: policycache.PolicyType(strings.Split(p, "/")[2]),
				})
			}
			policyInfoList = append(policyInfoList, policyInfo)
		}
	}

	return policyInfoList
}

func (datapathManager *DpManager) GetRulesByFlowIDs(flowIDs ...uint64) []*v1alpha1.RuleEntry {
	datapathManager.flowReplayMutex.RLock()
	defer datapathManager.flowReplayMutex.RUnlock()
	ans := []*v1alpha1.RuleEntry{}
	for _, id := range flowIDs {
		if entry, ok := datapathManager.FlowIDToRules[id]; ok {
			ans = append(ans, datapathRule2RpcRule(entry))
		}
	}
	return ans
}

func (datapathManager *DpManager) GetRulesByRuleIDs(ruleIDs ...string) []*v1alpha1.RuleEntry {
	datapathManager.flowReplayMutex.RLock()
	defer datapathManager.flowReplayMutex.RUnlock()
	ans := []*v1alpha1.RuleEntry{}
	for _, id := range ruleIDs {
		if entry, ok := datapathManager.Rules[id]; ok {
			ans = append(ans, datapathRule2RpcRule(entry))
		}
	}
	return ans
}

func (datapathManager *DpManager) GetAllRules() []*v1alpha1.RuleEntry {
	datapathManager.flowReplayMutex.RLock()
	defer datapathManager.flowReplayMutex.RUnlock()
	ans := []*v1alpha1.RuleEntry{}
	for _, entry := range datapathManager.Rules {
		ans = append(ans, datapathRule2RpcRule(entry))
	}
	return ans
}

func (datapathManager *DpManager) InitializeCNI() {
	var wg sync.WaitGroup
	for vdsID := range datapathManager.datapathConfig.ManagedVDSMap {
		wg.Add(1)
		go func(vdsID string) {
			defer wg.Done()
			datapathManager.BridgeChainMap[vdsID][LOCAL_BRIDGE_KEYWORD].BridgeInitCNI()
			datapathManager.BridgeChainMap[vdsID][POLICY_BRIDGE_KEYWORD].BridgeInitCNI()
			datapathManager.BridgeChainMap[vdsID][CLS_BRIDGE_KEYWORD].BridgeInitCNI()
			datapathManager.BridgeChainMap[vdsID][UPLINK_BRIDGE_KEYWORD].BridgeInitCNI()
		}(vdsID)
	}
	wg.Wait()
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
	vdsOfControllerMap[LOCAL_BRIDGE_KEYWORD] = ofctrl.NewControllerAsOFClient(localBridge, utils.GenerateControllerID(constants.EverouteComponentType))
	vdsOfControllerMap[POLICY_BRIDGE_KEYWORD] = ofctrl.NewControllerAsOFClient(policyBridge, utils.GenerateControllerID(constants.EverouteComponentType))
	vdsOfControllerMap[CLS_BRIDGE_KEYWORD] = ofctrl.NewControllerAsOFClient(clsBridge, utils.GenerateControllerID(constants.EverouteComponentType))
	vdsOfControllerMap[UPLINK_BRIDGE_KEYWORD] = ofctrl.NewControllerAsOFClient(uplinkBridge, utils.GenerateControllerID(constants.EverouteComponentType))

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

	portMap := make(map[string]uint32)
	localToPolicyOfPort, err := vdsOvsdbDriverMap[LOCAL_BRIDGE_KEYWORD].GetOfpPortNo(fmt.Sprintf("%s-%s", ovsbrname, LocalToPolicySuffix))
	if err != nil {
		log.Fatalf("Failed to get localToPolicyOfPort of ovsbrname %v, error: %v", ovsbrname, err)
	}
	policyToLocalOfPort, err := vdsOvsdbDriverMap[POLICY_BRIDGE_KEYWORD].GetOfpPortNo(fmt.Sprintf("%s-policy-%s", ovsbrname, PolicyToLocalSuffix))
	if err != nil {
		log.Fatalf("Failed to get policyToLocalOfPort of ovsbrname %v-policy, error: %v", ovsbrname, err)
	}
	policyToClsOfPort, err := vdsOvsdbDriverMap[POLICY_BRIDGE_KEYWORD].GetOfpPortNo(fmt.Sprintf("%s-policy-%s", ovsbrname, PolicyToClsSuffix))
	if err != nil {
		log.Fatalf("Failed to get policyToClsOfPort of ovsbrname %v-policy, error: %v", ovsbrname, err)
	}
	clsToPolicyOfPort, err := vdsOvsdbDriverMap[CLS_BRIDGE_KEYWORD].GetOfpPortNo(fmt.Sprintf("%s-cls-%s", ovsbrname, ClsToPolicySuffix))
	if err != nil {
		log.Fatalf("Failed to get clsToPolicyOfPort of ovsbrname %v-cls, error: %v", ovsbrname, err)
	}
	clsToUplinkOfPort, err := vdsOvsdbDriverMap[CLS_BRIDGE_KEYWORD].GetOfpPortNo(fmt.Sprintf("%s-cls-%s", ovsbrname, ClsToUplinkSuffix))
	if err != nil {
		log.Fatalf("Failed to get clsToUplinkOfPort of ovsbrname %v-cls, error: %v", ovsbrname, err)
	}
	uplinkToClsOfPort, err := vdsOvsdbDriverMap[CLS_BRIDGE_KEYWORD].GetOfpPortNo(fmt.Sprintf("%s-uplink-%s", ovsbrname, UplinkToClsSuffix))
	if err != nil {
		log.Fatalf("Failed to get uplinkToClsOfPort of ovsbrname %v-uplink, error: %v", ovsbrname, err)
	}
	portMap[LocalToPolicySuffix] = localToPolicyOfPort
	portMap[PolicyToLocalSuffix] = policyToLocalOfPort
	portMap[PolicyToClsSuffix] = policyToClsOfPort
	portMap[ClsToPolicySuffix] = clsToPolicyOfPort
	portMap[ClsToUplinkSuffix] = clsToUplinkOfPort
	portMap[UplinkToClsSuffix] = uplinkToClsOfPort
	datapathManager.BridgeChainPortMap[ovsbrname] = portMap

	go vdsOfControllerMap[LOCAL_BRIDGE_KEYWORD].Connect(fmt.Sprintf("%s/%s.%s", ovsVswitchdUnixDomainSockPath, localBridge.name, ovsVswitchdUnixDomainSockSuffix))
	go vdsOfControllerMap[POLICY_BRIDGE_KEYWORD].Connect(fmt.Sprintf("%s/%s.%s", ovsVswitchdUnixDomainSockPath, policyBridge.name, ovsVswitchdUnixDomainSockSuffix))
	go vdsOfControllerMap[CLS_BRIDGE_KEYWORD].Connect(fmt.Sprintf("%s/%s.%s", ovsVswitchdUnixDomainSockPath, clsBridge.name, ovsVswitchdUnixDomainSockSuffix))
	go vdsOfControllerMap[UPLINK_BRIDGE_KEYWORD].Connect(fmt.Sprintf("%s/%s.%s", ovsVswitchdUnixDomainSockPath, uplinkBridge.name, ovsVswitchdUnixDomainSockSuffix))
}

func InitializeVDS(datapathManager *DpManager, vdsID string, ovsbrName string, stopChan <-chan struct{}) {
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

	go datapathManager.BridgeChainMap[vdsID][LOCAL_BRIDGE_KEYWORD].(*LocalBridge).cleanLocalIPAddressCacheWorker(
		IPAddressCacheUpdateInterval, IPAddressTimeout, stopChan)

	go datapathManager.BridgeChainMap[vdsID][LOCAL_BRIDGE_KEYWORD].(*LocalBridge).cleanLocalEndpointIPAddrWorker(
		IPAddressCacheUpdateInterval, IPAddressTimeout, stopChan)

	if err := SetPortNoFlood(datapathManager.BridgeChainMap[vdsID][LOCAL_BRIDGE_KEYWORD].(*LocalBridge).name,
		int(datapathManager.BridgeChainPortMap[ovsbrName][LocalToPolicySuffix])); err != nil {
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

func (datapathManager *DpManager) replayVDSFlow(vdsID, bridgeKeyword string) error {
	datapathManager.flowReplayMutex.Lock()
	defer datapathManager.flowReplayMutex.Unlock()

	if !datapathManager.IsBridgesConnected() {
		// 1 second retry interval is too long
		datapathManager.WaitForBridgeConnected()
	}

	// replay basic connectivity flow
	roundInfo, err := getRoundInfo(datapathManager.OvsdbDriverMap[vdsID][LOCAL_BRIDGE_KEYWORD])
	if err != nil {
		return fmt.Errorf("failed to get Roundinfo from ovsdb: %v", err)
	}
	cookieAllocator := cookie.NewAllocator(roundInfo.curRoundNum)
	switch bridgeKeyword {
	case LOCAL_BRIDGE_KEYWORD:
		datapathManager.BridgeChainMap[vdsID][bridgeKeyword].(*LocalBridge).OfSwitch.CookieAllocator = cookieAllocator
	case POLICY_BRIDGE_KEYWORD:
		datapathManager.BridgeChainMap[vdsID][bridgeKeyword].(*PolicyBridge).OfSwitch.CookieAllocator = cookieAllocator
	case CLS_BRIDGE_KEYWORD:
		datapathManager.BridgeChainMap[vdsID][bridgeKeyword].(*ClsBridge).OfSwitch.CookieAllocator = cookieAllocator
	case UPLINK_BRIDGE_KEYWORD:
		datapathManager.BridgeChainMap[vdsID][bridgeKeyword].(*UplinkBridge).OfSwitch.CookieAllocator = cookieAllocator
	}
	datapathManager.BridgeChainMap[vdsID][bridgeKeyword].BridgeInit()
	datapathManager.BridgeChainMap[vdsID][bridgeKeyword].BridgeInitCNI()

	// replay local endpoint flow
	if bridgeKeyword == LOCAL_BRIDGE_KEYWORD {
		if err := datapathManager.ReplayVDSLocalEndpointFlow(vdsID); err != nil {
			return fmt.Errorf("failed to replay local endpoint flow while vswitchd restart, error: %v", err)
		}
	}

	// replay policy flow
	if bridgeKeyword == POLICY_BRIDGE_KEYWORD {
		if err := datapathManager.ReplayVDSMicroSegmentFlow(vdsID); err != nil {
			return fmt.Errorf("failed to replay microsegment flow while vswitchd restart, error: %v", err)
		}
	}

	return nil
}

func (datapathManager *DpManager) ReplayVDSLocalEndpointFlow(vdsID string) error {
	ovsbrname := datapathManager.datapathConfig.ManagedVDSMap[vdsID]
	for endpointObj := range datapathManager.localEndpointDB.IterBuffered() {
		endpoint := endpointObj.Val.(*Endpoint)
		if ovsbrname != endpoint.BridgeName {
			continue
		}

		err := datapathManager.BridgeChainMap[vdsID][LOCAL_BRIDGE_KEYWORD].AddLocalEndpoint(endpoint)
		if err != nil {
			return fmt.Errorf("failed to add local endpoint %v to vds %v : bridge %v, error: %v", endpoint.MacAddrStr, vdsID, ovsbrname, err)
		}

		break
	}

	return nil
}

func (datapathManager *DpManager) ReplayVDSMicroSegmentFlow(vdsID string) error {
	for ruleID, erPolicyRuleEntry := range datapathManager.Rules {
		// Add new policy rule flow to datapath
		flowEntry, err := datapathManager.BridgeChainMap[vdsID][POLICY_BRIDGE_KEYWORD].AddMicroSegmentRule(erPolicyRuleEntry.EveroutePolicyRule,
			erPolicyRuleEntry.Direction, erPolicyRuleEntry.Tier, erPolicyRuleEntry.Mode)
		if err != nil {
			return fmt.Errorf("failed to add microsegment rule to vdsID %v, bridge %s, error: %v", vdsID, datapathManager.BridgeChainMap[vdsID][POLICY_BRIDGE_KEYWORD], err)
		}
		// udpate new policy rule flow to datapath flow cache
		datapathManager.Rules[ruleID].RuleFlowMap[vdsID] = flowEntry
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
	if !datapathManager.IsBridgesConnected() {
		datapathManager.WaitForBridgeConnected()
	}

	for vdsID, ovsbrname := range datapathManager.datapathConfig.ManagedVDSMap {
		if ovsbrname == endpoint.BridgeName {
			if ep, _ := datapathManager.localEndpointDB.Get(endpoint.InterfaceName); ep != nil {
				log.Errorf("Already added local endpoint: %v", ep)
				return nil
			}

			// For endpoint event, first, we add it to local endpoint db, keep local endpointDB is consistent with
			// ovsdb interface table.
			// if it's failed to add endpoint flow, replayVDSFlow routine would rebuild local endpoint flow according to
			// current localEndpointDB
			datapathManager.localEndpointDB.Set(endpoint.InterfaceName, endpoint)
			err := datapathManager.BridgeChainMap[vdsID][LOCAL_BRIDGE_KEYWORD].AddLocalEndpoint(endpoint)
			if err != nil {
				return fmt.Errorf("failed to add local endpoint %v to vds %v : bridge %v, error: %v", endpoint.MacAddrStr, vdsID, ovsbrname, err)
			}

			break
		}
	}

	return nil
}

func (datapathManager *DpManager) UpdateLocalEndpoint(newEndpoint, oldEndpoint *Endpoint) error {
	datapathManager.flowReplayMutex.Lock()
	defer datapathManager.flowReplayMutex.Unlock()
	if !datapathManager.IsBridgesConnected() {
		datapathManager.WaitForBridgeConnected()
	}
	var err error

	for vdsID, ovsbrname := range datapathManager.datapathConfig.ManagedVDSMap {
		if ovsbrname == newEndpoint.BridgeName {
			oldEP, _ := datapathManager.localEndpointDB.Get(oldEndpoint.InterfaceName)
			if oldEP == nil {
				return fmt.Errorf("old local endpoint: %v not found", oldEP)
			}
			ep := oldEP.(*Endpoint)
			// NOTE copy ip addr cached in oldEP to newEndpoint can skip ip address learning operation
			learnedIP := make(net.IP, len(ep.IPAddr))
			copy(learnedIP, ep.IPAddr)
			newEndpoint.IPAddr = learnedIP

			datapathManager.localEndpointDB.Remove(oldEndpoint.InterfaceName)
			err = datapathManager.BridgeChainMap[vdsID][LOCAL_BRIDGE_KEYWORD].RemoveLocalEndpoint(oldEndpoint)
			if err != nil {
				return fmt.Errorf("failed to remove old local endpoint %v from vds %v : bridge %v, error: %v", oldEndpoint.MacAddrStr, vdsID, ovsbrname, err)
			}

			if newEP, _ := datapathManager.localEndpointDB.Get(newEndpoint.InterfaceName); newEP != nil {
				return fmt.Errorf("new local endpoint: %v already exits", newEP)
			}
			datapathManager.localEndpointDB.Set(newEndpoint.InterfaceName, newEndpoint)
			err = datapathManager.BridgeChainMap[vdsID][LOCAL_BRIDGE_KEYWORD].AddLocalEndpoint(newEndpoint)
			if err != nil {
				return fmt.Errorf("failed to add local endpoint %v to vds %v : bridge %v, error: %v", newEndpoint.MacAddrStr, vdsID, ovsbrname, err)
			}

			break
		}
	}

	return nil
}

func (datapathManager *DpManager) RemoveLocalEndpoint(endpoint *Endpoint) error {
	datapathManager.flowReplayMutex.Lock()
	defer datapathManager.flowReplayMutex.Unlock()
	if !datapathManager.IsBridgesConnected() {
		datapathManager.WaitForBridgeConnected()
	}
	ep, _ := datapathManager.localEndpointDB.Get(endpoint.InterfaceName)
	if ep == nil {
		return fmt.Errorf("Endpoint with interface name: %v, ofport: %v wasnot found", endpoint.InterfaceName, endpoint.PortNo)
	}
	cachedEP := ep.(*Endpoint)

	for vdsID, ovsbrname := range datapathManager.datapathConfig.ManagedVDSMap {
		if ovsbrname == cachedEP.BridgeName {
			// Same as addLocalEndpoint routine, keep datapath endpointDB is consistent with ovsdb
			datapathManager.localEndpointDB.Remove(endpoint.InterfaceName)
			err := datapathManager.BridgeChainMap[vdsID][LOCAL_BRIDGE_KEYWORD].RemoveLocalEndpoint(endpoint)
			if err != nil {
				return fmt.Errorf("failed to remove local endpoint %v to vds %v : bridge %v, error: %v", endpoint.MacAddrStr, vdsID, ovsbrname, err)
			}

			break
		}
	}

	return nil
}

func (datapathManager *DpManager) AddEveroutePolicyRule(rule *EveroutePolicyRule, ruleName string, direction uint8, tier uint8, mode string) error {
	datapathManager.flowReplayMutex.Lock()
	defer datapathManager.flowReplayMutex.Unlock()
	if !datapathManager.IsBridgesConnected() {
		datapathManager.WaitForBridgeConnected()
	}

	// check if we already have the rule
	var ruleEntry *EveroutePolicyRuleEntry
	if _, ok := datapathManager.Rules[rule.RuleID]; ok {
		ruleEntry = datapathManager.Rules[rule.RuleID]

		if RuleIsSame(ruleEntry.EveroutePolicyRule, rule) {
			datapathManager.Rules[rule.RuleID].PolicyRuleReference.Insert(ruleName)
			log.Infof("Rule already exists. new rule: {%+v}, old rule: {%+v}", rule, ruleEntry.EveroutePolicyRule)
			return nil
		}
		log.Infof("Rule already exists. update old rule: {%+v} to new rule: {%+v} ", ruleEntry.EveroutePolicyRule, rule)

		// clear CT flow while updating from "allow" to "deny"
		if ruleEntry.EveroutePolicyRule.Action == EveroutePolicyAllow && rule.Action == EveroutePolicyDeny {
			datapathManager.cleanConntrackFlow(rule)
		}
	}

	log.Infof("Received AddRule: %+v", rule)
	ruleFlowMap := make(map[string]*FlowEntry)
	// Install policy rule flow to datapath
	for vdsID, bridgeChain := range datapathManager.BridgeChainMap {
		flowEntry, err := bridgeChain[POLICY_BRIDGE_KEYWORD].AddMicroSegmentRule(rule, direction, tier, mode)
		if err != nil {
			log.Errorf("Failed to add microsegment rule to vdsID %v, bridge %s, error: %v", vdsID, bridgeChain[POLICY_BRIDGE_KEYWORD], err)
			return err
		}
		ruleFlowMap[vdsID] = flowEntry
	}

	// clean related CT flows only for "deny" action while adding
	if rule.Action == EveroutePolicyDeny {
		datapathManager.cleanConntrackFlow(rule)
	}

	// save the rule. ruleFlowMap need deepcopy, NOTE
	if ruleEntry == nil {
		ruleEntry = &EveroutePolicyRuleEntry{
			PolicyRuleReference: sets.NewString(ruleName),
		}
	}
	ruleEntry.Direction = direction
	ruleEntry.Tier = tier
	ruleEntry.Mode = mode
	ruleEntry.EveroutePolicyRule = rule
	ruleEntry.RuleFlowMap = ruleFlowMap

	// save flowID reference
	for _, v := range ruleEntry.RuleFlowMap {
		datapathManager.FlowIDToRules[v.FlowID] = ruleEntry
		log.Info(v.FlowID)
	}

	datapathManager.Rules[rule.RuleID] = ruleEntry

	return nil
}

func (datapathManager *DpManager) RemoveEveroutePolicyRule(ruleID string, ruleName string) error {
	datapathManager.flowReplayMutex.Lock()
	defer datapathManager.flowReplayMutex.Unlock()
	if !datapathManager.IsBridgesConnected() {
		datapathManager.WaitForBridgeConnected()
	}

	log.Infof("Received remove rule: %+v", ruleName)

	pRule := datapathManager.Rules[ruleID]
	if pRule == nil {
		log.Errorf("ruleID %v not found when deleting", ruleID)
		return nil
	}

	// check and remove rule reference
	if pRule.PolicyRuleReference.Has(ruleName) {
		pRule.PolicyRuleReference.Delete(ruleName)
		if pRule.PolicyRuleReference.Len() > 0 {
			return nil
		}
	}

	for vdsID := range datapathManager.BridgeChainMap {
		err := ofctrl.DeleteFlow(pRule.RuleFlowMap[vdsID].Table, pRule.RuleFlowMap[vdsID].Priority, pRule.RuleFlowMap[vdsID].FlowID)
		if err != nil {
			log.Errorf("Failed to delete flow for rule: %+v. Err: %v", ruleID, err)
			return err
		}
		// remove flowID reference
		delete(datapathManager.FlowIDToRules, pRule.RuleFlowMap[vdsID].FlowID)
	}

	// clean related CT flows only for "allow" action while deleting
	if datapathManager.Rules[ruleID].EveroutePolicyRule.Action == EveroutePolicyAllow {
		datapathManager.cleanConntrackFlow(datapathManager.Rules[ruleID].EveroutePolicyRule)
	}

	if pRule.PolicyRuleReference.Len() == 0 {
		delete(datapathManager.Rules, ruleID)
	}

	return nil
}

func (datapathManager *DpManager) syncIntenalIPs(stopChan <-chan struct{}) {
	const bufferSize = 100
	addrUpdateChan := make(chan netlink.AddrUpdate, bufferSize)
	if err := netlink.AddrSubscribeWithOptions(addrUpdateChan, stopChan, netlink.AddrSubscribeOptions{
		ListExisting:      true,
		ReceiveBufferSize: bufferSize,
	}); err != nil {
		klog.Fatalf("fail to init ip addr update handle, err: %s", err)
	}
	for addr := range addrUpdateChan {
		if addr.LinkAddress.IP.IsLoopback() || addr.LinkAddress.IP.To4() == nil {
			continue
		}
		if addr.NewAddr {
			datapathManager.addIntenalIP(addr.LinkAddress.IP.String(), addr.LinkIndex)
		} else {
			datapathManager.removeIntenalIP(addr.LinkAddress.IP.String(), addr.LinkIndex)
		}
	}
}

func (datapathManager *DpManager) addIntenalIP(ip string, index int) {
	ruleNameSuffix := fmt.Sprintf("%s-%d", ip, index)
	// add internal ingress rule
	err := datapathManager.AddEveroutePolicyRule(newInternalIngressRule(ip),
		InternalIngressRulePrefix+ruleNameSuffix, POLICY_DIRECTION_IN, POLICY_TIER3, DEFAULT_POLICY_ENFORCEMENT_MODE)
	if err != nil {
		log.Fatalf("Failed to add internal whitelist: %s: %v", ip, err)
	}
	// add internal egress rule
	err = datapathManager.AddEveroutePolicyRule(newInternalEgressRule(ip),
		InternalEgressRulePrefix+ruleNameSuffix, POLICY_DIRECTION_OUT, POLICY_TIER3, DEFAULT_POLICY_ENFORCEMENT_MODE)
	if err != nil {
		log.Fatalf("Failed to add internal whitelist: %s: %v", ip, err)
	}
}

func (datapathManager *DpManager) removeIntenalIP(ip string, index int) {
	ruleNameSuffix := fmt.Sprintf("%s-%d", ip, index)
	// del internal ingress rule
	err := datapathManager.RemoveEveroutePolicyRule(newInternalIngressRule(ip).RuleID, InternalIngressRulePrefix+ruleNameSuffix)
	if err != nil {
		log.Fatalf("Failed to del internal whitelist %s: %v", ip, err)
	}
	// del internal egress rule
	err = datapathManager.RemoveEveroutePolicyRule(newInternalEgressRule(ip).RuleID, InternalEgressRulePrefix+ruleNameSuffix)
	if err != nil {
		log.Fatalf("Failed to del internal whitelist %s: %v", ip, err)
	}
}

func (datapathManager *DpManager) cleanConntrackWorker() {
	for {
		ruleList := receiveRuleListFromChan(datapathManager.cleanConntrackChan)
		if ruleList == nil {
			return
		}
		matches, err := netlink.ConntrackDeleteFilter(netlink.ConntrackTable, unix.AF_INET, ruleList)
		if err != nil {
			klog.Errorf("clear conntrack error, rules: %+v, err: %s", ruleList, err)
			continue
		}
		klog.Infof("clear conntrack for rules: %+v, matches %d", ruleList, matches)
	}
}

func (datapathManager *DpManager) cleanConntrackFlow(rule *EveroutePolicyRule) {
	datapathManager.cleanConntrackChan <- *rule
}

func receiveRuleListFromChan(ruleChan <-chan EveroutePolicyRule) EveroutePolicyRuleList {
	var ruleList EveroutePolicyRuleList

	// block until chan have one or more rules
	rule, ok := <-ruleChan
	if !ok {
		return nil
	}
	ruleList = append(ruleList, rule)

	// read and return all rules in chan
	for {
		select {
		case rule := <-ruleChan:
			ruleList = append(ruleList, rule)
		default:
			return ruleList
		}
	}
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
	var num, newRoundNum uint64
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

	// Flipping current round num with minimum round num value while it equals with the maximum round num
	if num >= MaxRoundNum {
		newRoundNum = 1
	} else {
		newRoundNum = num + 1
	}

	return &RoundInfo{
		previousRoundNum: num,
		curRoundNum:      newRoundNum,
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

// newInternalIngressRule generate a rule allow all ingress to internalIP
func newInternalIngressRule(internalIP string) *EveroutePolicyRule {
	return &EveroutePolicyRule{
		RuleID:    fmt.Sprintf("internal.ingress.%s", internalIP),
		Priority:  constants.InternalWhitelistPriority,
		DstIPAddr: internalIP,
		Action:    EveroutePolicyAllow,
	}
}

// newInternalEgressRule generate a rule allow all egress from internalIP
func newInternalEgressRule(internalIP string) *EveroutePolicyRule {
	return &EveroutePolicyRule{
		RuleID:    fmt.Sprintf("internal.egress.%s", internalIP),
		Priority:  constants.InternalWhitelistPriority,
		SrcIPAddr: internalIP,
		Action:    EveroutePolicyAllow,
	}
}
