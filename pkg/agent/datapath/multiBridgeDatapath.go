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
	"os/exec"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	cnitypes "github.com/containernetworking/cni/pkg/types"
	"github.com/contiv/libOpenflow/openflow13"
	"github.com/contiv/libOpenflow/protocol"
	"github.com/contiv/ofnet/ofctrl"
	"github.com/contiv/ofnet/ofctrl/cookie"
	"github.com/contiv/ofnet/ovsdbDriver"
	cmap "github.com/orcaman/concurrent-map"
	log "github.com/sirupsen/logrus"
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
	POLICY_TIER1    = 50
	POLICY_TIER2    = 100
	POLICY_TIER_ECP = 130
	POLICY_TIER3    = 150
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
	PROTOCOL_UDP = 0x11
	PROTOCOL_TCP = 0x06
)

//nolint
const (
	LOCAL_BRIDGE_KEYWORD  = "local"
	POLICY_BRIDGE_KEYWORD = "policy"
	CLS_BRIDGE_KEYWORD    = "cls"
	UPLINK_BRIDGE_KEYWORD = "uplink"
	NAT_BRIDGE_KEYWORD    = "nat"
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
	LocalToNatSuffix    = "local-to-nat"
	NatToLocalSuffix    = "nat-to-local"

	InternalIngressRulePrefix = "/INTERNAL_INGRESS_POLICY/internal/ingress/-"
	InternalEgressRulePrefix  = "/INTERNAL_EGRESS_POLICY/internal/egress/-"

	MaxRoundNum = 15

	MaxArpChanCache = 100

	MaxCleanConntrackChanSize = 5000
)

var (
	EtherTypeLength uint16 = 16
	ProtocolLength  uint16 = 8
	MacLength       uint16 = 48
	IPv4Lenth       uint16 = 32
	PortLength      uint16 = 16

	ArpOperRequest uint16 = 1
	ArpOperReply   uint64 = 2
)

var IPMaskMatchFullBit = net.ParseIP("255.255.255.255")

const (
	PortMaskMatchFullBit uint16 = 65535

	FTPPort  uint16 = 21
	TFTPPort uint16 = 69
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

	GetName() string
	getOfSwitch() *ofctrl.OFSwitch
}

type DpManager struct {
	DpManagerMutex     sync.Mutex
	BridgeChainMap     map[string]map[string]Bridge                 // map vds to bridge instance map
	OvsdbDriverMap     map[string]map[string]*ovsdbDriver.OvsDriver // map vds to bridge ovsdbDriver map
	ControllerMap      map[string]map[string]*ofctrl.Controller
	BridgeChainPortMap map[string]map[string]uint32 // map vds to patch port to ofport-num map

	localEndpointDB           cmap.ConcurrentMap     // list of local endpoint map
	ofPortIPAddressUpdateChan chan map[string]net.IP // map bridgename-ofport to endpoint ips
	Config                    *DpManagerConfig
	Info                      *DpManagerInfo
	Rules                     map[string]*EveroutePolicyRuleEntry // rules database
	FlowIDToRules             map[uint64]*EveroutePolicyRuleEntry
	flowReplayMutex           sync.RWMutex

	flushMutex         sync.RWMutex
	needFlush          bool                    // need to flush
	cleanConntrackChan chan EveroutePolicyRule // clean conntrack entries for rule in chan

	ArpChan chan ArpInfo

	proxyReplayFunc   func()
	overlayReplayFunc func()
}

type DpManagerInfo struct {
	NodeName   string
	PodCIDR    []cnitypes.IPNet
	BridgeName string

	ClusterCIDR    *cnitypes.IPNet
	ClusterPodCIDR *net.IPNet

	LocalGwName   string
	LocalGwIP     net.IP
	LocalGwMac    net.HardwareAddr
	LocalGwOfPort uint32

	GatewayName   string
	GatewayIP     net.IP
	GatewayMask   net.IPMask
	GatewayMac    net.HardwareAddr
	GatewayOfPort uint32

	TunnelOfPort uint32

	Namespace string
}

type DpManagerConfig struct {
	ManagedVDSMap    map[string]string   // map vds to ovsbr-name
	InternalIPs      []string            // internal IPs
	EnableIPLearning bool                // enable ip learning
	EnableCNI        bool                // enable CNI in Everoute
	CNIConfig        *DpManagerCNIConfig // config related CNI
}

type DpManagerCNIConfig struct {
	EnableProxy bool // enable proxy
	EncapMode   string
	MTU         int // pod mtu
	IPAMType    string
}

type Endpoint struct {
	InterfaceUUID        string
	InterfaceName        string // interface name that endpoint attached to
	IPAddr               net.IP
	IPAddrMutex          sync.RWMutex
	IPAddrLastUpdateTime time.Time
	IPv6Addr             net.IP
	PortNo               uint32 // endpoint of port
	MacAddrStr           string
	VlanID               uint16 // endpoint vlan id
	Trunk                string // vlan trunk config
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
	FlowID uint64
	Item   []PolicyItem
}
type PolicyItem struct {
	Name       string
	Namespace  string
	PolicyType policycache.PolicyType
}

type ArpInfo struct {
	InPort uint32
	Pkt    protocol.ARP
	BrName string
}

// Datapath manager act as openflow controller:
// 1. event driven local endpoint info crud and related flow update,
// 2. collect local endpoint ip learned from different ovsbr(1 per vds), and sync it to management plane
func NewDatapathManager(datapathConfig *DpManagerConfig, ofPortIPAddressUpdateChan chan map[string]net.IP) *DpManager {
	datapathManager := new(DpManager)
	datapathManager.BridgeChainMap = make(map[string]map[string]Bridge)
	datapathManager.BridgeChainPortMap = make(map[string]map[string]uint32)
	datapathManager.OvsdbDriverMap = make(map[string]map[string]*ovsdbDriver.OvsDriver)
	datapathManager.ControllerMap = make(map[string]map[string]*ofctrl.Controller)
	datapathManager.Rules = make(map[string]*EveroutePolicyRuleEntry)
	datapathManager.FlowIDToRules = make(map[uint64]*EveroutePolicyRuleEntry)
	datapathManager.Config = datapathConfig
	datapathManager.localEndpointDB = cmap.New()
	datapathManager.Info = new(DpManagerInfo)
	datapathManager.flowReplayMutex = sync.RWMutex{}
	datapathManager.cleanConntrackChan = make(chan EveroutePolicyRule, MaxCleanConntrackChanSize)
	datapathManager.ArpChan = make(chan ArpInfo, MaxArpChanCache)
	datapathManager.proxyReplayFunc = func() {}
	datapathManager.overlayReplayFunc = func() {}

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
	for vdsID, ovsbrName := range datapathManager.Config.ManagedVDSMap {
		wg.Add(1)
		go func(vdsID, ovsbrName string) {
			defer wg.Done()
			InitializeVDS(datapathManager, vdsID, ovsbrName, stopChan)
		}(vdsID, ovsbrName)
	}
	wg.Wait()

	// add rules for internalIP
	for index, internalIP := range datapathManager.Config.InternalIPs {
		datapathManager.addIntenalIP(internalIP, index)
	}
	// add internal ip handle
	if len(datapathManager.Config.InternalIPs) != 0 {
		go datapathManager.syncIntenalIPs(stopChan)
	}

	go wait.Until(datapathManager.cleanConntrackWorker, time.Second, stopChan)

	for vdsID, vdsName := range datapathManager.Config.ManagedVDSMap {
		for bridgeKeyword := range datapathManager.ControllerMap[vdsID] {
			go func(vdsID, bridgeKeyword string) {
				for range datapathManager.ControllerMap[vdsID][bridgeKeyword].DisconnChan {
					log.Infof("Received vds %v bridge %v reconnect event", vdsID, bridgeKeyword)
					if err := datapathManager.replayVDSFlow(vdsID, vdsName, bridgeKeyword); err != nil {
						log.Fatalf("Failed to replay vds %v, %v flow, error: %v", vdsID, bridgeKeyword, err)
					}
				}
			}(vdsID, bridgeKeyword)
		}
	}
}

func (datapathManager *DpManager) SetProxySyncFunc(f func()) {
	datapathManager.proxyReplayFunc = f
}

func (datapathManager *DpManager) SetOverlaySyncFunc(f func()) {
	datapathManager.overlayReplayFunc = f
}

func (datapathManager *DpManager) GetChainBridge() []string {
	datapathManager.flowReplayMutex.RLock()
	defer datapathManager.flowReplayMutex.RUnlock()

	var out []string
	for _, br := range datapathManager.Config.ManagedVDSMap {
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
				FlowID: id,
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
	for vdsID := range datapathManager.Config.ManagedVDSMap {
		wg.Add(1)
		go func(vdsID string) {
			defer wg.Done()
			for brKeyword := range datapathManager.BridgeChainMap[vdsID] {
				datapathManager.BridgeChainMap[vdsID][brKeyword].BridgeInitCNI()
			}
		}(vdsID)
	}
	wg.Wait()
}

func NewVDSForConfig(datapathManager *DpManager, vdsID, ovsbrname string) {
	NewVDSForConfigBase(datapathManager, vdsID, ovsbrname)
	if datapathManager.IsEnableProxy() {
		NewVDSForConfigProxy(datapathManager, vdsID, ovsbrname)
	}
}

func NewVDSForConfigProxy(datapathManager *DpManager, vdsID, ovsbrname string) {
	natBr := NewNatBridge(ovsbrname, datapathManager)
	natControl := ofctrl.NewOFController(natBr, utils.GenerateControllerID(constants.EverouteComponentType), nil, natBr.GetName())
	natDriver := ovsdbDriver.NewOvsDriverForExistBridge(natBr.GetName())

	protocols := map[string][]string{
		"protocols": {
			openflowProtorolVersion10, openflowProtorolVersion11, openflowProtorolVersion12, openflowProtorolVersion13,
		},
	}
	if err := natDriver.UpdateBridge(protocols); err != nil {
		log.Fatalf("Failed to set local bridge: %v protocols, error: %v", vdsID, err)
	}

	natToLocalOfPort, err := natDriver.GetOfpPortNo(fmt.Sprintf("%s-nat-%s", ovsbrname, NatToLocalSuffix))
	if err != nil {
		log.Fatalf("Failed to get natToLocalOfPort ovs ovsbrname %v, error: %v", natBr.GetName(), err)
	}
	localToNatOfPort, err := datapathManager.OvsdbDriverMap[vdsID][LOCAL_BRIDGE_KEYWORD].GetOfpPortNo(fmt.Sprintf("%s-%s", ovsbrname, LocalToNatSuffix))
	if err != nil {
		log.Fatalf("Failed to get localToNatOfPort ovs ovsbrname %v, error: %v", ovsbrname, err)
	}

	datapathManager.DpManagerMutex.Lock()
	datapathManager.BridgeChainMap[vdsID][NAT_BRIDGE_KEYWORD] = natBr
	datapathManager.ControllerMap[vdsID][NAT_BRIDGE_KEYWORD] = natControl
	datapathManager.OvsdbDriverMap[vdsID][NAT_BRIDGE_KEYWORD] = natDriver
	datapathManager.BridgeChainPortMap[ovsbrname][LocalToNatSuffix] = localToNatOfPort
	datapathManager.BridgeChainPortMap[ovsbrname][NatToLocalSuffix] = natToLocalOfPort
	datapathManager.DpManagerMutex.Unlock()

	go natControl.Connect(fmt.Sprintf("%s/%s.%s", ovsVswitchdUnixDomainSockPath, natBr.GetName(), ovsVswitchdUnixDomainSockSuffix))
}

//nolint
func NewVDSForConfigBase(datapathManager *DpManager, vdsID, ovsbrname string) {
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
	vdsOfControllerMap[LOCAL_BRIDGE_KEYWORD] = ofctrl.NewOFController(localBridge, utils.GenerateControllerID(constants.EverouteComponentType), nil, localBridge.GetName())
	vdsOfControllerMap[POLICY_BRIDGE_KEYWORD] = ofctrl.NewOFController(policyBridge, utils.GenerateControllerID(constants.EverouteComponentType), nil, policyBridge.GetName())
	vdsOfControllerMap[CLS_BRIDGE_KEYWORD] = ofctrl.NewOFController(clsBridge, utils.GenerateControllerID(constants.EverouteComponentType), nil, clsBridge.GetName())
	vdsOfControllerMap[UPLINK_BRIDGE_KEYWORD] = ofctrl.NewOFController(uplinkBridge, utils.GenerateControllerID(constants.EverouteComponentType), nil, uplinkBridge.GetName())

	// initialize ovsdbDriver
	vdsOvsdbDriverMap := make(map[string]*ovsdbDriver.OvsDriver)
	bridgeSuffixToNameMap := map[string]string{
		LOCAL_BRIDGE_KEYWORD:  localBridge.GetName(),
		POLICY_BRIDGE_KEYWORD: policyBridge.GetName(),
		CLS_BRIDGE_KEYWORD:    clsBridge.GetName(),
		UPLINK_BRIDGE_KEYWORD: uplinkBridge.GetName(),
	}
	var wg sync.WaitGroup
	var vdsOvsdbDriverMapMutex sync.RWMutex
	for suffix, brName := range bridgeSuffixToNameMap {
		wg.Add(1)
		go func(suffix, brName string, vdsOvsdbDriverMap map[string]*ovsdbDriver.OvsDriver) {
			defer wg.Done()
			driver := ovsdbDriver.NewOvsDriverForExistBridge(brName)
			vdsOvsdbDriverMapMutex.Lock()
			vdsOvsdbDriverMap[suffix] = driver
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

	go vdsOfControllerMap[LOCAL_BRIDGE_KEYWORD].Connect(fmt.Sprintf("%s/%s.%s", ovsVswitchdUnixDomainSockPath, localBridge.GetName(), ovsVswitchdUnixDomainSockSuffix))
	go vdsOfControllerMap[POLICY_BRIDGE_KEYWORD].Connect(fmt.Sprintf("%s/%s.%s", ovsVswitchdUnixDomainSockPath, policyBridge.GetName(), ovsVswitchdUnixDomainSockSuffix))
	go vdsOfControllerMap[CLS_BRIDGE_KEYWORD].Connect(fmt.Sprintf("%s/%s.%s", ovsVswitchdUnixDomainSockPath, clsBridge.GetName(), ovsVswitchdUnixDomainSockSuffix))
	go vdsOfControllerMap[UPLINK_BRIDGE_KEYWORD].Connect(fmt.Sprintf("%s/%s.%s", ovsVswitchdUnixDomainSockPath, uplinkBridge.GetName(), ovsVswitchdUnixDomainSockSuffix))
}

func InitializeVDS(datapathManager *DpManager, vdsID string, ovsbrName string, stopChan <-chan struct{}) {
	roundInfo, err := getRoundInfo(datapathManager.OvsdbDriverMap[vdsID][LOCAL_BRIDGE_KEYWORD])
	if err != nil {
		log.Fatalf("Failed to get Roundinfo from ovsdb: %v", err)
	}

	cookieAllocator := cookie.NewAllocator(roundInfo.curRoundNum)
	for brKeyword := range datapathManager.BridgeChainMap[vdsID] {
		// Delete flow with curRoundNum cookie, for case: failed when restart process flow install.
		datapathManager.BridgeChainMap[vdsID][brKeyword].getOfSwitch().DeleteFlowByRoundInfo(roundInfo.curRoundNum)
		// update cookie
		datapathManager.BridgeChainMap[vdsID][brKeyword].getOfSwitch().CookieAllocator = cookieAllocator
		// bridge init
		datapathManager.BridgeChainMap[vdsID][brKeyword].BridgeInit()
	}

	if datapathManager.Config.EnableIPLearning {
		go datapathManager.BridgeChainMap[vdsID][LOCAL_BRIDGE_KEYWORD].(*LocalBridge).cleanLocalIPAddressCacheWorker(
			IPAddressCacheUpdateInterval, IPAddressTimeout, stopChan)

		go datapathManager.BridgeChainMap[vdsID][LOCAL_BRIDGE_KEYWORD].(*LocalBridge).cleanLocalEndpointIPAddrWorker(
			IPAddressCacheUpdateInterval, IPAddressTimeout, stopChan)
	}

	for _, portSuffix := range []string{LocalToPolicySuffix, LocalToNatSuffix} {
		if datapathManager.BridgeChainPortMap[ovsbrName][portSuffix] == 0 {
			log.Infof("Port %s in local bridge doesn't exist, skip set no flood port mode", portSuffix)
			continue
		}
		if err := SetPortNoFlood(datapathManager.BridgeChainMap[vdsID][LOCAL_BRIDGE_KEYWORD].GetName(),
			int(datapathManager.BridgeChainPortMap[ovsbrName][portSuffix])); err != nil {
			log.Fatalf("Failed to set %s port with no flood port mode, %v", portSuffix, err)
		}
	}

	// Delete flow with previousRoundNum cookie, and then persistent curRoundNum to ovsdb. We need to wait for long
	// enough to guarantee that all of the basic flow which we are still required updated with new roundInfo encoding to
	// flow cookie fields. But the time required to update all of the basic flow with updated roundInfo is
	// non-determined.
	// TODO  Implement a deterministic mechanism to control outdated flow flush procedure
	go func(vdsID string) {
		time.Sleep(time.Second * 15)

		for brKeyword := range datapathManager.BridgeChainMap[vdsID] {
			datapathManager.BridgeChainMap[vdsID][brKeyword].getOfSwitch().DeleteFlowByRoundInfo(roundInfo.previousRoundNum)
		}

		err := persistentRoundInfo(roundInfo.curRoundNum, datapathManager.OvsdbDriverMap[vdsID][LOCAL_BRIDGE_KEYWORD])
		if err != nil {
			log.Fatalf("Failed to persistent roundInfo into ovsdb: %v", err)
		}
	}(vdsID)
}

func (datapathManager *DpManager) replayVDSFlow(vdsID, vdsName, bridgeKeyword string) error {
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
	datapathManager.BridgeChainMap[vdsID][bridgeKeyword].getOfSwitch().CookieAllocator = cookieAllocator
	datapathManager.BridgeChainMap[vdsID][bridgeKeyword].BridgeInit()
	datapathManager.BridgeChainMap[vdsID][bridgeKeyword].BridgeInitCNI()

	// replay local endpoint flow
	if bridgeKeyword == LOCAL_BRIDGE_KEYWORD || bridgeKeyword == NAT_BRIDGE_KEYWORD ||
		(datapathManager.IsEnableOverlay() && bridgeKeyword == UPLINK_BRIDGE_KEYWORD) {
		if err := datapathManager.ReplayVDSLocalEndpointFlow(vdsID, bridgeKeyword); err != nil {
			return fmt.Errorf("failed to replay local endpoint flow while vswitchd restart, error: %v", err)
		}
	}

	// replay policy flow
	if bridgeKeyword == POLICY_BRIDGE_KEYWORD {
		if err := datapathManager.ReplayVDSMicroSegmentFlow(vdsID); err != nil {
			return fmt.Errorf("failed to replay microsegment flow while vswitchd restart, error: %v", err)
		}
	}

	// replay proxy flow
	if bridgeKeyword == NAT_BRIDGE_KEYWORD {
		datapathManager.proxyReplayFunc()
	}

	// replay overlay flow
	if datapathManager.IsEnableOverlay() && bridgeKeyword == UPLINK_BRIDGE_KEYWORD {
		datapathManager.overlayReplayFunc()
	}

	// reset port no flood
	for _, portSuffix := range []string{LocalToPolicySuffix, LocalToNatSuffix} {
		if datapathManager.BridgeChainPortMap[vdsName][portSuffix] == 0 {
			log.Infof("Port %s in local bridge doesn't exist, skip set no flood port mode", portSuffix)
			continue
		}
		if err := SetPortNoFlood(datapathManager.BridgeChainMap[vdsID][LOCAL_BRIDGE_KEYWORD].GetName(),
			int(datapathManager.BridgeChainPortMap[vdsName][portSuffix])); err != nil {
			return fmt.Errorf("failed to set %s port with no flood port mode, %v", portSuffix, err)
		}
	}

	return nil
}

func (datapathManager *DpManager) ReplayVDSLocalEndpointFlow(vdsID string, keyWord string) error {
	ovsbrname := datapathManager.Config.ManagedVDSMap[vdsID]
	for endpointObj := range datapathManager.localEndpointDB.IterBuffered() {
		endpoint := endpointObj.Val.(*Endpoint)
		if ovsbrname != endpoint.BridgeName {
			continue
		}

		bridge := datapathManager.BridgeChainMap[vdsID][keyWord]
		if err := bridge.AddLocalEndpoint(endpoint); err != nil {
			return fmt.Errorf("failed to add local endpoint %s to vds %s, bridge %s, error: %v", endpoint.InterfaceUUID, vdsID, bridge.GetName(), err)
		}
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

		// update new flowID to policy entry map
		datapathManager.FlowIDToRules[flowEntry.FlowID] = erPolicyRuleEntry
	}
	// TODO: clear except table if we support helpers
	netlink.ConntrackTableFlush(netlink.ConntrackTable)

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
		for bridgeKey := range bridgeChain {
			if !bridgeChain[bridgeKey].IsSwitchConnected() {
				return dpStatus
			}
		}
	}

	dpStatus = true

	return dpStatus
}

func (datapathManager *DpManager) skipLocalEndpoint(endpoint *Endpoint) bool {
	// skip ovs patch port
	if strings.HasSuffix(endpoint.InterfaceName, LocalToPolicySuffix) {
		return true
	}
	if strings.HasSuffix(endpoint.InterfaceName, LocalToNatSuffix) {
		return true
	}
	// skip cni local gateway
	if datapathManager.Info.LocalGwName == endpoint.InterfaceName {
		return true
	}

	// skip cni bridge default interface
	if endpoint.InterfaceName == datapathManager.Info.BridgeName {
		return true
	}

	return false
}

func (datapathManager *DpManager) AddLocalEndpoint(endpoint *Endpoint) error {
	datapathManager.flowReplayMutex.Lock()
	defer datapathManager.flowReplayMutex.Unlock()
	if !datapathManager.IsBridgesConnected() {
		datapathManager.WaitForBridgeConnected()
	}

	if datapathManager.skipLocalEndpoint(endpoint) {
		return nil
	}

	for vdsID, ovsbrname := range datapathManager.Config.ManagedVDSMap {
		if ovsbrname == endpoint.BridgeName {
			if ep, _ := datapathManager.localEndpointDB.Get(endpoint.InterfaceUUID); ep != nil {
				log.Errorf("Already added local endpoint: %v", ep)
				return nil
			}

			// For endpoint event, first, we add it to local endpoint db, keep local endpointDB is consistent with
			// ovsdb interface table.
			// if it's failed to add endpoint flow, replayVDSFlow routine would rebuild local endpoint flow according to
			// current localEndpointDB
			datapathManager.localEndpointDB.Set(endpoint.InterfaceUUID, endpoint)
			for kword := range datapathManager.BridgeChainMap[vdsID] {
				br := datapathManager.BridgeChainMap[vdsID][kword]
				if err := br.AddLocalEndpoint(endpoint); err != nil {
					return fmt.Errorf("failed to add local endpoint %s to vds %v, bridge %v, error: %v", endpoint.InterfaceUUID, vdsID, br.GetName(), err)
				}
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

	for vdsID, ovsbrname := range datapathManager.Config.ManagedVDSMap {
		if ovsbrname == newEndpoint.BridgeName {
			oldEP, _ := datapathManager.localEndpointDB.Get(oldEndpoint.InterfaceUUID)
			if oldEP == nil {
				return fmt.Errorf("old local endpoint: %v not found", oldEP)
			}
			ep := oldEP.(*Endpoint)
			if datapathManager.Config.EnableIPLearning {
				// NOTE copy ip addr cached in oldEP to newEndpoint can get learning ip address
				newEndpoint.IPAddr = utils.IPCopy(ep.IPAddr)
			}

			// assume that ofport does not update, so doesn't need to remove old flow for local bridge overlay
			datapathManager.localEndpointDB.Remove(oldEndpoint.InterfaceUUID)
			if !datapathManager.IsEnableOverlay() {
				err = datapathManager.BridgeChainMap[vdsID][LOCAL_BRIDGE_KEYWORD].RemoveLocalEndpoint(oldEndpoint)
				if err != nil {
					return fmt.Errorf("failed to remove old local endpoint %v from vds %v, bridge %v, error: %v", oldEndpoint.InterfaceUUID, vdsID, ovsbrname, err)
				}
			}

			if datapathManager.skipLocalEndpoint(newEndpoint) {
				break
			}
			if newEP, _ := datapathManager.localEndpointDB.Get(newEndpoint.InterfaceUUID); newEP != nil {
				return fmt.Errorf("new local endpoint: %v already exits", newEP)
			}
			datapathManager.localEndpointDB.Set(newEndpoint.InterfaceUUID, newEndpoint)
			for kword := range datapathManager.BridgeChainMap[vdsID] {
				br := datapathManager.BridgeChainMap[vdsID][kword]
				// for cni, endpoint ipaddr may update from null, so try to add endpoint
				if err := br.AddLocalEndpoint(newEndpoint); err != nil {
					return fmt.Errorf("failed to add local endpoint %v to vds %v, bridge %v, error: %v", newEndpoint.InterfaceUUID, vdsID, br.GetName(), err)
				}
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
	ep, _ := datapathManager.localEndpointDB.Get(endpoint.InterfaceUUID)
	if ep == nil {
		return fmt.Errorf("Endpoint with interface name: %v, ofport: %v wasnot found", endpoint.InterfaceName, endpoint.PortNo)
	}
	cachedEP := ep.(*Endpoint)

	for vdsID, ovsbrname := range datapathManager.Config.ManagedVDSMap {
		if ovsbrname == cachedEP.BridgeName {
			// Same as addLocalEndpoint routine, keep datapath endpointDB is consistent with ovsdb
			datapathManager.localEndpointDB.Remove(endpoint.InterfaceUUID)
			for kword := range datapathManager.BridgeChainMap[vdsID] {
				br := datapathManager.BridgeChainMap[vdsID][kword]
				if err := br.RemoveLocalEndpoint(endpoint); err != nil {
					return fmt.Errorf("failed to remove local endpoint %v to vds %v, bridge %v, error: %v", endpoint.InterfaceUUID, vdsID, br.GetName(), err)
				}
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

	datapathManager.cleanConntrackFlow(rule)

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

	datapathManager.cleanConntrackFlow(datapathManager.Rules[ruleID].EveroutePolicyRule)

	if pRule.PolicyRuleReference.Len() == 0 {
		delete(datapathManager.Rules, ruleID)
	}

	return nil
}

func (datapathManager *DpManager) GetNatBridges() []*NatBridge {
	natBrs := []*NatBridge{}
	for vdsID := range datapathManager.BridgeChainMap {
		natBr := datapathManager.BridgeChainMap[vdsID][NAT_BRIDGE_KEYWORD]
		if natBr != nil {
			natBrs = append(natBrs, natBr.(*NatBridge))
		}
	}
	return natBrs
}

func (datapathManager *DpManager) GetUplinkBridgeOverlay() *UplinkBridgeOverlay {
	for vdsID := range datapathManager.BridgeChainMap {
		br := datapathManager.BridgeChainMap[vdsID][UPLINK_BRIDGE_KEYWORD]
		if br != nil {
			uplinkBr, ok := br.(*UplinkBridgeOverlay)
			if ok {
				// cni only has one vdsID
				return uplinkBr
			}
		}
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

func (datapathManager *DpManager) getFlush() bool {
	datapathManager.flushMutex.Lock()
	defer datapathManager.flushMutex.Unlock()
	return datapathManager.needFlush
}

func (datapathManager *DpManager) setFlush(needFlush bool) {
	datapathManager.flushMutex.Lock()
	defer datapathManager.flushMutex.Unlock()
	datapathManager.needFlush = needFlush
}

func (datapathManager *DpManager) cleanConntrackWorker() {
	for {
		if datapathManager.getFlush() {
			datapathManager.flushMutex.Lock()
			err := netlink.ConntrackTableFlush(netlink.ConntrackTable)
			if err != nil {
				klog.Errorf("Flush ct failed: %v", err)
			} else {
				datapathManager.needFlush = false
				klog.Info("Success flush ct")
			}
			datapathManager.flushMutex.Unlock()
		}

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
	if rule == nil {
		klog.Error("The rule for clean conntrack flow is nil")
		return
	}

	if datapathManager.getFlush() {
		return
	}

	if len(datapathManager.cleanConntrackChan) < cap(datapathManager.cleanConntrackChan) {
		datapathManager.cleanConntrackChan <- *rule
		return
	}

	klog.Info("The cleanConntrackChan has blocked, clean channel")
	for {
		select {
		case <-datapathManager.cleanConntrackChan:
		default:
			datapathManager.setFlush(true)
			return
		}
	}
}

func (datapathManager *DpManager) IsEnableCNI() bool {
	if datapathManager.Config == nil {
		return false
	}
	return datapathManager.Config.EnableCNI
}

func (datapathManager *DpManager) IsEnableProxy() bool {
	if !datapathManager.IsEnableCNI() {
		return false
	}
	if datapathManager.Config.CNIConfig == nil {
		return false
	}

	return datapathManager.Config.CNIConfig.EnableProxy
}

func (datapathManager *DpManager) IsEnableOverlay() bool {
	if !datapathManager.IsEnableCNI() {
		return false
	}
	if datapathManager.Config.CNIConfig == nil {
		return false
	}

	return datapathManager.Config.CNIConfig.EncapMode == constants.EncapModeGeneve
}

func (datapathManager *DpManager) UseEverouteIPAM() bool {
	if !datapathManager.IsEnableOverlay() {
		return false
	}

	return datapathManager.Config.CNIConfig.IPAMType == constants.EverouteIPAM
}

func receiveRuleListFromChan(ruleChan <-chan EveroutePolicyRule) EveroutePolicyRuleList {
	var ruleList EveroutePolicyRuleList

	// block until chan have one or more rules
	rule, ok := <-ruleChan
	if !ok {
		return nil
	}
	ruleList = append(ruleList, rule)
	ruleSet := sets.NewString(rule.RuleID)

	// read and return all rules in chan
	for {
		select {
		case rule := <-ruleChan:
			if ruleSet.Has(rule.RuleID) {
				continue
			}
			ruleList = append(ruleList, rule)
			ruleSet.Insert(rule.RuleID)
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
