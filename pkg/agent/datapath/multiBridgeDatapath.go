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
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	cnitypes "github.com/containernetworking/cni/pkg/types"
	"github.com/contiv/libOpenflow/openflow13"
	"github.com/contiv/libOpenflow/protocol"
	"github.com/contiv/libOpenflow/util"
	"github.com/contiv/ofnet/ofctrl"
	"github.com/contiv/ofnet/ofctrl/cookie"
	"github.com/contiv/ofnet/ovsdbDriver"
	"github.com/mdlayher/ndp"
	"github.com/mdlayher/netx/eui64"
	cmap "github.com/orcaman/concurrent-map"
	"github.com/samber/lo"
	lock "github.com/viney-shih/go-lock"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"golang.org/x/time/rate"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	klog "k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"

	policycache "github.com/everoute/everoute/pkg/agent/controller/policy/cache"
	"github.com/everoute/everoute/pkg/apis/rpc/v1alpha1"
	"github.com/everoute/everoute/pkg/constants"
	cniconst "github.com/everoute/everoute/pkg/constants/cni"
	"github.com/everoute/everoute/pkg/metrics"
	"github.com/everoute/everoute/pkg/types"
	"github.com/everoute/everoute/pkg/utils"
)

//nolint:all
const (
	HIGH_MATCH_FLOW_PRIORITY            = 300
	MID_MATCH_FLOW_PRIORITY             = 200
	NORMAL_MATCH_FLOW_PRIORITY          = 100
	DEFAULT_DROP_FLOW_PRIORITY          = 70
	GLOBAL_DEFAULT_POLICY_FLOW_PRIORITY = 40
	DEFAULT_FLOW_MISS_PRIORITY          = 10
	FLOW_MATCH_OFFSET                   = 3
	LARGE_FLOW_MATCH_OFFSET             = 100
)

//nolint:all
const (
	POLICY_TIER1    = 50
	POLICY_TIER2    = 100
	POLICY_TIER_ECP = 130
	POLICY_TIER3    = 150
)

//nolint:all
const (
	POLICY_DIRECTION_OUT = 0
	POLICY_DIRECTION_IN  = 1
)

//nolint:all
const (
	IP_BROADCAST_ADDR = "255.255.255.255"
	LOOP_BACK_ADDR    = "127.0.0.1"
)

//nolint:all
const (
	FLOW_ROUND_NUM_LENGTH           = 4
	FLOW_SEQ_NUM_LENGTH             = 28
	FLOW_ROUND_NUM_MASK             = 0xf0000000
	FLOW_SEQ_NUM_MASK               = 0x0fffffff
	DEFAULT_POLICY_ENFORCEMENT_MODE = "work"
)

//nolint:all
const (
	PROTOCOL_ARP  = 0x0806
	PROTOCOL_IP   = 0x0800
	PROTOCOL_UDP  = 0x11
	PROTOCOL_TCP  = 0x06
	PROTOCOL_ICMP = 0x01
)

//nolint:all
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

	IPAddressTimeout                        = 10
	IPAddressCacheUpdateInterval            = 5
	LocalBridgeL2ForwardingTableHardTimeout = 300
	LocalBridgeL2ForwardingTableIdleTimeout = 300
	ClsBridgeL2ForwardingTableHardTimeout   = 300
	ClsBridgeL2ForwardingTableIdleTimeout   = 300
	MaxIPAddressLearningFrenquency          = 3

	LocalToPolicySuffix = "local-to-policy"
	PolicyToLocalSuffix = "policy-to-local"
	PolicyToClsSuffix   = "policy-to-cls"
	ClsToPolicySuffix   = "cls-to-policy"
	ClsToUplinkSuffix   = "cls-to-uplink"
	UplinkToClsSuffix   = "uplink-to-cls"
	LocalToNatSuffix    = "local-to-nat"
	NatToLocalSuffix    = "nat-to-local"
	NatToUplinkSuffix   = "nat-to-uplink"
	UplinkToNatSuffix   = "uplink-to-nat"

	InternalIngressPolicy     = "/INTERNAL_INGRESS_POLICY"
	InternalEgressPolicy      = "/INTERNAL_EGRESS_POLICY"
	InternalIngressRulePrefix = "/INTERNAL_INGRESS_POLICY/internal/ingress/-"
	InternalEgressRulePrefix  = "/INTERNAL_EGRESS_POLICY/internal/egress/-"

	MaxRoundNum = 15

	MaxArpChanCache = 100
	ArpLimiterRate  = 5000

	MaxCleanConntrackChanSize = 5000

	RuleEntryCap = 10000
)

var (
	EtherTypeLength uint16 = 16
	ProtocolLength  uint16 = 8
	MacLength       uint16 = 48
	IPv4Lenth       uint16 = 32
	PortLength      uint16 = 16

	ArpOperRequest uint16 = 1
	ArpOperReply   uint64 = 2

	IcmpTypeRequest uint8 = 8
	IcmpTypeReply   uint8

	lockTimeout = 5 * time.Minute
)

var IPv6AllFF = net.IP{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

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
	AddMicroSegmentRule(ctx context.Context, seqID uint32, rule *EveroutePolicyRule, direction uint8, tier uint8, mode string) (*FlowEntry, error)

	IsSwitchConnected() bool
	DisconnectedNotify() chan struct{}

	// of control app interface
	// A Switch connected to the controller
	SwitchConnected(sw *ofctrl.OFSwitch)

	// Switch disconnected from the controller
	SwitchDisconnected(sw *ofctrl.OFSwitch)

	// Controller received a packet from the switch
	PacketRcvd(sw *ofctrl.OFSwitch, pkt *ofctrl.PacketIn)

	// Controller received a multi-part reply from the switch
	MultipartReply(sw *ofctrl.OFSwitch, rep *openflow13.MultipartReply)

	// Everoute IPAM
	AddIPPoolSubnet(string) error
	DelIPPoolSubnet(string) error
	AddIPPoolGW(string) error
	DelIPPoolGW(string) error

	GetName() string
	getOfSwitch() *ofctrl.OFSwitch

	SetRoundNumber(uint64)
}

type DpManager struct {
	DpManagerMutex     sync.Mutex
	BridgeChainMap     map[string]map[string]Bridge                 // map vds to bridge instance map
	OvsdbDriverMap     map[string]map[string]*ovsdbDriver.OvsDriver // map vds to bridge ovsdbDriver map
	ControllerMap      map[string]map[string]*ofctrl.Controller
	BridgeChainPortMap map[string]map[string]uint32 // map vds to patch port to ofport-num map

	localEndpointDB           cmap.ConcurrentMap     // list of local endpoint map
	ofPortIPAddressUpdateChan chan *types.EndpointIP // map bridgename-ofport to endpoint ips
	Config                    *DpManagerConfig
	Info                      *DpManagerInfo
	Rules                     map[string]*EveroutePolicyRuleEntry // rules database
	FlowIDToRules             map[uint64]*EveroutePolicyRuleEntry
	policyRuleNums            map[string]int
	flowReplayMutex           *lock.CASMutex
	SeqIDAlloctorForRule      *NumAllocator

	flushMutex           *lock.ChanMutex
	needFlush            bool                         // need to flush
	cleanConntrackChan   chan EveroutePolicyRuleForCT // clean conntrack entries for rule in chan
	cleanConntrackChanV6 chan EveroutePolicyRuleForCT // clean conntrack entries for rule in chan

	ArpChan    chan ArpInfo
	ArpLimiter *rate.Limiter

	AgentMetric *metrics.AgentMetric

	proxyReplayFunc   func()
	overlayReplayFunc func()

	// everoute ipam
	ippoolSubnets sets.Set[string]
	ippoolGWs     sets.Set[string]
}

type DpManagerInfo struct {
	NodeName   string
	PodCIDR    []cnitypes.IPNet
	BridgeName string

	ClusterCIDR    *cnitypes.IPNet
	ClusterPodCIDR *net.IPNet
	ClusterPodGw   *net.IP

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
	EnableProxy      bool // enable proxy
	EncapMode        string
	MTU              int // pod mtu
	IPAMType         string
	KubeProxyReplace bool
	SvcInternalIP    net.IP // kube-proxy replace need it
}

type Endpoint struct {
	InterfaceUUID        string
	InterfaceName        string // interface name that endpoint attached to
	IPAddr               net.IP
	IPAddrMutex          sync.RWMutex
	IPAddrLastUpdateTime time.Time
	PortNo               uint32 // endpoint of port
	MacAddrStr           string
	VlanID               uint16 // endpoint vlan id
	Trunk                string // vlan trunk config
	BridgeName           string // bridge name that endpoint attached to
}

type RoundInfo struct {
	previousRoundNum uint64
	curRoundNum      uint64
}

type PolicyInfo struct {
	Dir      uint8
	Action   string
	Mode     string
	FlowID   uint64
	Item     []PolicyItem
	Tier     uint8
	Priority int
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
func NewDatapathManager(datapathConfig *DpManagerConfig, ofPortIPAddressUpdateChan chan *types.EndpointIP, agentMetric *metrics.AgentMetric) *DpManager {
	datapathManager := new(DpManager)
	datapathManager.BridgeChainMap = make(map[string]map[string]Bridge)
	datapathManager.BridgeChainPortMap = make(map[string]map[string]uint32)
	datapathManager.OvsdbDriverMap = make(map[string]map[string]*ovsdbDriver.OvsDriver)
	datapathManager.ControllerMap = make(map[string]map[string]*ofctrl.Controller)
	datapathManager.Rules = make(map[string]*EveroutePolicyRuleEntry)
	datapathManager.FlowIDToRules = make(map[uint64]*EveroutePolicyRuleEntry)
	datapathManager.SeqIDAlloctorForRule = NewRuleSeqIDAlloctor()
	datapathManager.policyRuleNums = make(map[string]int)
	datapathManager.Config = datapathConfig
	datapathManager.localEndpointDB = cmap.New()
	datapathManager.Info = new(DpManagerInfo)
	datapathManager.flowReplayMutex = lock.NewCASMutex()
	datapathManager.flushMutex = lock.NewChanMutex()
	datapathManager.cleanConntrackChan = make(chan EveroutePolicyRuleForCT, MaxCleanConntrackChanSize)
	datapathManager.cleanConntrackChanV6 = make(chan EveroutePolicyRuleForCT, MaxCleanConntrackChanSize)
	datapathManager.ArpChan = make(chan ArpInfo, MaxArpChanCache)
	datapathManager.ArpLimiter = rate.NewLimiter(rate.Every(time.Second/ArpLimiterRate), ArpLimiterRate)
	datapathManager.proxyReplayFunc = func() {}
	datapathManager.overlayReplayFunc = func() {}
	datapathManager.ippoolSubnets = sets.New[string]()
	datapathManager.ippoolGWs = sets.New[string]()
	datapathManager.AgentMetric = agentMetric

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

func (dp *DpManager) lockflowReplayWithTimeout() {
	if !dp.flowReplayMutex.TryLockWithTimeout(lockTimeout) {
		klog.Fatalf("fail to acquire datapath flowReplayMutex lock for %s", lockTimeout)
	}
}
func (dp *DpManager) lockRflowReplayWithTimeout() {
	if !dp.flowReplayMutex.RTryLockWithTimeout(lockTimeout) {
		klog.Fatalf("fail to acquire datapath flowReplayMutex read lock for %s", lockTimeout)
	}
}

func (dp *DpManager) lockflushWithTimeout() {
	if !dp.flushMutex.TryLockWithTimeout(lockTimeout) {
		klog.Fatalf("fail to acquire datapath flushMutex lock for %s", lockTimeout)
	}
}

func (dp *DpManager) InitializeDatapath(ctx context.Context) {
	log := ctrl.LoggerFrom(ctx)
	if !dp.IsBridgesConnected() {
		dp.WaitForBridgeConnected()
	}

	var wg sync.WaitGroup
	for vdsID, ovsbrName := range dp.Config.ManagedVDSMap {
		wg.Add(1)

		// setup local bridge internal mac
		macStr, err := dp.OvsdbDriverMap[vdsID][LOCAL_BRIDGE_KEYWORD].GetInternalPortMac()
		if err != nil {
			klog.Fatalf("Failed to setup local bridge %s %s internal mac, err = %s", vdsID, ovsbrName, err)
		}
		mac, err := net.ParseMAC(macStr)
		if err != nil {
			klog.Fatalf("Failed to setup local bridge %s %s internal mac, err = %s", vdsID, ovsbrName, err)
		}
		if br, ok := dp.BridgeChainMap[vdsID][LOCAL_BRIDGE_KEYWORD].(*LocalBridge); ok {
			br.SetLocalPortMac(&mac)
		}

		go func(vdsID, ovsbrName string) {
			defer wg.Done()
			InitializeVDS(ctx, dp, vdsID, ovsbrName)
		}(vdsID, ovsbrName)
	}
	wg.Wait()

	// add rules for internalIP
	for index, internalIP := range dp.Config.InternalIPs {
		dp.addIntenalIP(internalIP, index)
	}
	// add internal ip handle
	if len(dp.Config.InternalIPs) != 0 {
		go dp.syncIntenalIPs(ctx.Done())
	}

	go wait.Until(func() { dp.cleanConntrackWorker(unix.AF_INET, dp.cleanConntrackChan) }, time.Second, ctx.Done())
	go wait.Until(func() { dp.cleanConntrackWorker(unix.AF_INET6, dp.cleanConntrackChanV6) }, time.Second, ctx.Done())

	for vdsID, bridgeName := range dp.Config.ManagedVDSMap {
		for bridgeKeyword := range dp.ControllerMap[vdsID] {
			bridgeName := bridgeName
			vdsID := vdsID
			bridgeKeyword := bridgeKeyword

			go func() {
				for range dp.BridgeChainMap[vdsID][bridgeKeyword].DisconnectedNotify() {
					log.Info("Received ovs bridge reconnect event", "vds", vdsID, "bridge", bridgeKeyword)
					if err := dp.replayVDSFlow(ctx, vdsID, bridgeName, bridgeKeyword); err != nil {
						klog.Fatalf("Failed to replay vds %v, %v flow, error: %v", vdsID, bridgeKeyword, err)
					}
				}
			}()
		}
	}
}

func (dp *DpManager) SetProxySyncFunc(f func()) {
	dp.proxyReplayFunc = f
}

func (dp *DpManager) SetOverlaySyncFunc(f func()) {
	dp.overlayReplayFunc = f
}

func (dp *DpManager) GetChainBridge() []string {
	dp.lockRflowReplayWithTimeout()
	defer dp.flowReplayMutex.RUnlock()

	var out []string
	for _, br := range dp.Config.ManagedVDSMap {
		out = append(out, br)
	}

	return out
}

func (dp *DpManager) GetPolicyByFlowID(flowID ...uint64) []*PolicyInfo {
	dp.lockRflowReplayWithTimeout()
	defer dp.flowReplayMutex.RUnlock()

	var policyInfoList []*PolicyInfo

	for _, id := range flowID {
		if id == 0 {
			continue
		}
		item := dp.FlowIDToRules[id]
		if item != nil {
			policyInfo := &PolicyInfo{
				Dir:    item.Direction,
				Action: item.EveroutePolicyRule.Action,
				Mode:   item.Mode,
				FlowID: id,
			}
			for p := range item.PolicyRuleReference {
				res := strings.Split(p.Rule, "/")
				if len(res) < 3 {
					continue
				}
				policyInfo.Item = append(policyInfo.Item, PolicyItem{
					Name:       res[1],
					Namespace:  res[0],
					PolicyType: policycache.PolicyType(res[2]),
				})
			}
			policyInfoList = append(policyInfoList, policyInfo)
		}
	}

	return policyInfoList
}

func (dp *DpManager) GetRulesByFlowIDs(flowIDs ...uint64) []*v1alpha1.RuleEntry {
	dp.lockRflowReplayWithTimeout()
	defer dp.flowReplayMutex.RUnlock()
	ans := []*v1alpha1.RuleEntry{}
	for _, id := range flowIDs {
		if entry := dp.FlowIDToRules[id]; entry != nil {
			ans = append(ans, datapathRule2RpcRule(entry))
		}
	}
	return ans
}

func (dp *DpManager) GetRulesByRuleIDs(ruleIDs ...string) []*v1alpha1.RuleEntry {
	dp.lockRflowReplayWithTimeout()
	defer dp.flowReplayMutex.RUnlock()
	ans := []*v1alpha1.RuleEntry{}
	for _, id := range ruleIDs {
		if entry := dp.Rules[id]; entry != nil {
			ans = append(ans, datapathRule2RpcRule(entry))
		}
	}
	return ans
}

func (dp *DpManager) GetAllRules() []*v1alpha1.RuleEntry {
	dp.lockRflowReplayWithTimeout()
	defer dp.flowReplayMutex.RUnlock()
	ans := []*v1alpha1.RuleEntry{}
	for _, entry := range dp.Rules {
		ans = append(ans, datapathRule2RpcRule(entry))
	}
	return ans
}

func (dp *DpManager) InitializeCNI() {
	var wg sync.WaitGroup
	for vdsID := range dp.Config.ManagedVDSMap {
		wg.Add(1)
		go func(vdsID string) {
			defer wg.Done()
			for brKeyword := range dp.BridgeChainMap[vdsID] {
				dp.BridgeChainMap[vdsID][brKeyword].BridgeInitCNI()
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
	natControl := ofctrl.NewOFController(natBr, utils.GenerateControllerID(constants.EverouteComponentType), nil, natBr.GetName(), ofctrl.DisableCleanGroup())
	natDriver := ovsdbDriver.NewOvsDriverForExistBridge(natBr.GetName())

	protocols := map[string][]string{
		"protocols": {
			openflowProtorolVersion10, openflowProtorolVersion11, openflowProtorolVersion12, openflowProtorolVersion13,
		},
	}
	if err := natDriver.UpdateBridge(protocols); err != nil {
		klog.Fatalf("Failed to set local bridge: %v protocols, error: %v", vdsID, err)
	}

	natToLocalOfPort, err := natDriver.GetOfpPortNo(fmt.Sprintf("%s-nat-%s", ovsbrname, NatToLocalSuffix))
	if err != nil {
		klog.Fatalf("Failed to get natToLocalOfPort ovs ovsbrname %v, error: %v", natBr.GetName(), err)
	}
	localToNatOfPort, err := datapathManager.OvsdbDriverMap[vdsID][LOCAL_BRIDGE_KEYWORD].GetOfpPortNo(fmt.Sprintf("%s-%s", ovsbrname, LocalToNatSuffix))
	if err != nil {
		klog.Fatalf("Failed to get localToNatOfPort ovs ovsbrname %v, error: %v", ovsbrname, err)
	}

	datapathManager.DpManagerMutex.Lock()
	datapathManager.BridgeChainMap[vdsID][NAT_BRIDGE_KEYWORD] = natBr
	datapathManager.ControllerMap[vdsID][NAT_BRIDGE_KEYWORD] = natControl
	datapathManager.OvsdbDriverMap[vdsID][NAT_BRIDGE_KEYWORD] = natDriver
	datapathManager.BridgeChainPortMap[ovsbrname][LocalToNatSuffix] = localToNatOfPort
	datapathManager.BridgeChainPortMap[ovsbrname][NatToLocalSuffix] = natToLocalOfPort
	datapathManager.DpManagerMutex.Unlock()

	if datapathManager.IsEnableKubeProxyReplace() {
		setPortMapForKubeProxyReplace(datapathManager, vdsID, ovsbrname)
	}

	go natControl.Connect(fmt.Sprintf("%s/%s.%s", ovsVswitchdUnixDomainSockPath, natBr.GetName(), ovsVswitchdUnixDomainSockSuffix))
}

func setPortMapForKubeProxyReplace(datapathManager *DpManager, vdsID, ovsbrname string) {
	natToUplinkOfPort, err := datapathManager.OvsdbDriverMap[vdsID][NAT_BRIDGE_KEYWORD].GetOfpPortNo(fmt.Sprintf("%s-nat-%s", ovsbrname, NatToUplinkSuffix))
	if err != nil {
		klog.Fatalf("Failed to get natToUplinkOfPort ovs ovsbrname %s, error: %s", ovsbrname, err)
	}
	uplinkToNatOfPort, err := datapathManager.OvsdbDriverMap[vdsID][UPLINK_BRIDGE_KEYWORD].GetOfpPortNo(fmt.Sprintf("%s-uplink-%s", ovsbrname, UplinkToNatSuffix))
	if err != nil {
		klog.Fatalf("Failed to get UplinkToNatOfPort ovs ovsbrname %s, error: %s", ovsbrname, err)
	}

	datapathManager.DpManagerMutex.Lock()
	datapathManager.BridgeChainPortMap[ovsbrname][NatToUplinkSuffix] = natToUplinkOfPort
	datapathManager.BridgeChainPortMap[ovsbrname][UplinkToNatSuffix] = uplinkToNatOfPort
	datapathManager.DpManagerMutex.Unlock()
}

//nolint:all
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
		klog.Fatalf("Failed to set local bridge: %v protocols, error: %v", vdsID, err)
	}
	if err := vdsOvsdbDriverMap[POLICY_BRIDGE_KEYWORD].UpdateBridge(protocols); err != nil {
		klog.Fatalf("Failed to set policy bridge: %v protocols, error: %v", vdsID, err)
	}
	if err := vdsOvsdbDriverMap[CLS_BRIDGE_KEYWORD].UpdateBridge(protocols); err != nil {
		klog.Fatalf("Failed to set cls bridge: %v protocols, error: %v", vdsID, err)
	}
	if err := vdsOvsdbDriverMap[UPLINK_BRIDGE_KEYWORD].UpdateBridge(protocols); err != nil {
		klog.Fatalf("Failed to set uplink bridge: %v protocols, error: %v", vdsID, err)
	}

	portMap := make(map[string]uint32)
	localToPolicyOfPort, err := vdsOvsdbDriverMap[LOCAL_BRIDGE_KEYWORD].GetOfpPortNo(fmt.Sprintf("%s-%s", ovsbrname, LocalToPolicySuffix))
	if err != nil {
		klog.Fatalf("Failed to get localToPolicyOfPort of ovsbrname %v, error: %v", ovsbrname, err)
	}
	policyToLocalOfPort, err := vdsOvsdbDriverMap[POLICY_BRIDGE_KEYWORD].GetOfpPortNo(fmt.Sprintf("%s-policy-%s", ovsbrname, PolicyToLocalSuffix))
	if err != nil {
		klog.Fatalf("Failed to get policyToLocalOfPort of ovsbrname %v-policy, error: %v", ovsbrname, err)
	}
	policyToClsOfPort, err := vdsOvsdbDriverMap[POLICY_BRIDGE_KEYWORD].GetOfpPortNo(fmt.Sprintf("%s-policy-%s", ovsbrname, PolicyToClsSuffix))
	if err != nil {
		klog.Fatalf("Failed to get policyToClsOfPort of ovsbrname %v-policy, error: %v", ovsbrname, err)
	}
	clsToPolicyOfPort, err := vdsOvsdbDriverMap[CLS_BRIDGE_KEYWORD].GetOfpPortNo(fmt.Sprintf("%s-cls-%s", ovsbrname, ClsToPolicySuffix))
	if err != nil {
		klog.Fatalf("Failed to get clsToPolicyOfPort of ovsbrname %v-cls, error: %v", ovsbrname, err)
	}
	clsToUplinkOfPort, err := vdsOvsdbDriverMap[CLS_BRIDGE_KEYWORD].GetOfpPortNo(fmt.Sprintf("%s-cls-%s", ovsbrname, ClsToUplinkSuffix))
	if err != nil {
		klog.Fatalf("Failed to get clsToUplinkOfPort of ovsbrname %v-cls, error: %v", ovsbrname, err)
	}
	uplinkToClsOfPort, err := vdsOvsdbDriverMap[CLS_BRIDGE_KEYWORD].GetOfpPortNo(fmt.Sprintf("%s-uplink-%s", ovsbrname, UplinkToClsSuffix))
	if err != nil {
		klog.Fatalf("Failed to get uplinkToClsOfPort of ovsbrname %v-uplink, error: %v", ovsbrname, err)
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

func policyBrCookieAllocator(roundNum uint64) cookie.Allocator {
	return cookie.NewAllocator(roundNum, cookie.SetFlowIDRange(cookie.InitFlowID, 1<<CookieAutoAllocBitWidthForPolicyBr-1))
}

func InitializeVDS(ctx context.Context, datapathManager *DpManager, vdsID string, ovsbrName string) {
	log := ctrl.LoggerFrom(ctx)
	roundInfo, err := getRoundInfo(datapathManager.OvsdbDriverMap[vdsID][LOCAL_BRIDGE_KEYWORD])
	if err != nil {
		klog.Fatalf("Failed to get Roundinfo from ovsdb: %v", err)
	}

	cookieAllocator := cookie.NewAllocator(roundInfo.curRoundNum, cookie.SetDefaultFlowIDRange())
	for brKeyword := range datapathManager.BridgeChainMap[vdsID] {
		// Delete flow with curRoundNum cookie, for case: failed when restart process flow install.
		datapathManager.BridgeChainMap[vdsID][brKeyword].getOfSwitch().DeleteFlowByRoundInfo(roundInfo.curRoundNum)
		// update cookie
		if brKeyword == POLICY_BRIDGE_KEYWORD {
			policyBrCookieAllo := policyBrCookieAllocator(roundInfo.curRoundNum)
			if policyBrCookieAllo == nil {
				klog.Fatalf("Failed to new policy bridge cookie allocator")
			}
			datapathManager.BridgeChainMap[vdsID][brKeyword].getOfSwitch().CookieAllocator = policyBrCookieAllo
		} else {
			datapathManager.BridgeChainMap[vdsID][brKeyword].getOfSwitch().CookieAllocator = cookieAllocator
		}
		datapathManager.BridgeChainMap[vdsID][brKeyword].SetRoundNumber(roundInfo.curRoundNum)

		// bridge init
		datapathManager.BridgeChainMap[vdsID][brKeyword].BridgeInit()
	}

	if datapathManager.Config.EnableIPLearning {
		go datapathManager.BridgeChainMap[vdsID][LOCAL_BRIDGE_KEYWORD].(*LocalBridge).cleanLocalIPAddressCacheWorker(
			IPAddressCacheUpdateInterval, IPAddressTimeout, ctx.Done())

		go datapathManager.BridgeChainMap[vdsID][LOCAL_BRIDGE_KEYWORD].(*LocalBridge).cleanLocalEndpointIPAddrWorker(
			IPAddressCacheUpdateInterval, IPAddressTimeout, ctx.Done())
	}

	for _, portSuffix := range []string{LocalToPolicySuffix, LocalToNatSuffix} {
		if datapathManager.BridgeChainPortMap[ovsbrName][portSuffix] == 0 {
			log.Info("Port in local bridge doesn't exist, skip set no flood port mode", "port", portSuffix)
			continue
		}
		if err := SetPortNoFlood(datapathManager.BridgeChainMap[vdsID][LOCAL_BRIDGE_KEYWORD].GetName(),
			int(datapathManager.BridgeChainPortMap[ovsbrName][portSuffix])); err != nil {
			klog.Fatalf("Failed to set %s port with no flood port mode, %v", portSuffix, err)
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
			klog.Fatalf("Failed to persistent roundInfo into ovsdb: %v", err)
		}
	}(vdsID)
}

func (dp *DpManager) replayVDSFlow(ctx context.Context, vdsID, bridgeName, bridgeKeyword string) error {
	log := ctrl.LoggerFrom(ctx)
	dp.lockflowReplayWithTimeout()
	defer dp.flowReplayMutex.Unlock()

	if !dp.IsBridgesConnected() {
		// 1 second retry interval is too long
		dp.WaitForBridgeConnected()
	}

	// replay basic connectivity flow
	roundInfo, err := getRoundInfo(dp.OvsdbDriverMap[vdsID][LOCAL_BRIDGE_KEYWORD])
	if err != nil {
		return fmt.Errorf("failed to get Roundinfo from ovsdb: %v", err)
	}

	var cookieAllocator cookie.Allocator
	if bridgeKeyword == POLICY_BRIDGE_KEYWORD {
		cookieAllocator = policyBrCookieAllocator(roundInfo.curRoundNum)
		if cookieAllocator == nil {
			return fmt.Errorf("failed to create policy bridge cookie alloctor")
		}
	} else {
		cookieAllocator = cookie.NewAllocator(roundInfo.curRoundNum, cookie.SetDefaultFlowIDRange())
	}
	dp.BridgeChainMap[vdsID][bridgeKeyword].SetRoundNumber(roundInfo.curRoundNum)
	dp.BridgeChainMap[vdsID][bridgeKeyword].getOfSwitch().CookieAllocator = cookieAllocator
	dp.BridgeChainMap[vdsID][bridgeKeyword].BridgeInit()
	dp.BridgeChainMap[vdsID][bridgeKeyword].BridgeInitCNI()

	// replay local endpoint flow
	if bridgeKeyword == LOCAL_BRIDGE_KEYWORD || bridgeKeyword == NAT_BRIDGE_KEYWORD ||
		(dp.IsEnableOverlay() && bridgeKeyword == UPLINK_BRIDGE_KEYWORD) {
		if err := dp.ReplayVDSLocalEndpointFlow(vdsID, bridgeKeyword); err != nil {
			return fmt.Errorf("failed to replay local endpoint flow while vswitchd restart, error: %v", err)
		}
	}

	// replay policy flow
	if bridgeKeyword == POLICY_BRIDGE_KEYWORD {
		if err := dp.ReplayVDSMicroSegmentFlow(vdsID); err != nil {
			return fmt.Errorf("failed to replay microsegment flow while vswitchd restart, error: %v", err)
		}
	}

	// replay proxy flow
	if bridgeKeyword == NAT_BRIDGE_KEYWORD {
		dp.proxyReplayFunc()
	}

	// replay overlay flow
	if dp.IsEnableOverlay() && bridgeKeyword == UPLINK_BRIDGE_KEYWORD {
		dp.overlayReplayFunc()
	}

	// replay everoute ipam flow
	if dp.UseEverouteIPAM() {
		if err := dp.ReplayEverouteIPAMFlow(vdsID, bridgeKeyword); err != nil {
			log.Error(err, "Failed to replay everoute ipam flow")
			return err
		}
	}

	// reset port no flood
	for _, portSuffix := range []string{LocalToPolicySuffix, LocalToNatSuffix} {
		if dp.BridgeChainPortMap[bridgeName][portSuffix] == 0 {
			log.Info("Port in local bridge doesn't exist, skip set no flood port mode", "port", portSuffix)
			continue
		}
		if err := SetPortNoFlood(dp.BridgeChainMap[vdsID][LOCAL_BRIDGE_KEYWORD].GetName(),
			int(dp.BridgeChainPortMap[bridgeName][portSuffix])); err != nil {
			return fmt.Errorf("failed to set %s port with no flood port mode, %v", portSuffix, err)
		}
	}

	return nil
}

func (dp *DpManager) ReplayVDSLocalEndpointFlow(vdsID string, keyWord string) error {
	ovsbrname := dp.Config.ManagedVDSMap[vdsID]
	for endpointObj := range dp.localEndpointDB.IterBuffered() {
		endpoint := endpointObj.Val.(*Endpoint)
		if ovsbrname != endpoint.BridgeName {
			continue
		}

		bridge := dp.BridgeChainMap[vdsID][keyWord]
		if err := bridge.AddLocalEndpoint(endpoint); err != nil {
			return fmt.Errorf("failed to add local endpoint %s to vds %s, bridge %s, error: %v", endpoint.InterfaceUUID, vdsID, bridge.GetName(), err)
		}
	}

	return nil
}

func (dp *DpManager) getSeqIDForReplayRule(vdsID string, entry *EveroutePolicyRuleEntry) (uint32, error) {
	if entry.RuleFlowMap[vdsID] != nil {
		seqID := GetSeqIDByFlowID(entry.RuleFlowMap[vdsID].FlowID)
		return seqID, nil
	}
	return dp.SeqIDAlloctorForRule.Allocate()
}

func (dp *DpManager) ReplayVDSMicroSegmentFlow(vdsID string) error {
	var errs error
	for ruleID, entry := range dp.Rules {
		// Add new policy rule flow to datapath
		seqID, err := dp.getSeqIDForReplayRule(vdsID, entry)
		if err != nil {
			errs = errors.Join(errs, err)
			continue
		}
		flowEntry, err := dp.BridgeChainMap[vdsID][POLICY_BRIDGE_KEYWORD].AddMicroSegmentRule(context.Background(), seqID, entry.EveroutePolicyRule,
			entry.Direction, entry.Tier, entry.Mode)
		if err != nil {
			errs = errors.Join(errs,
				fmt.Errorf("failed to add microsegment rule to vdsID %v, bridge %s, error: %v",
					vdsID, dp.BridgeChainMap[vdsID][POLICY_BRIDGE_KEYWORD].GetName(), err))
			continue
		}

		// udpate new policy rule flow to datapath flow cache
		dp.Rules[ruleID].RuleFlowMap[vdsID] = flowEntry

		// update new flowID to policy entry map
		dp.FlowIDToRules[flowEntry.FlowID] = entry
	}

	// TODO: clear except table if we support helpers
	netlink.ConntrackTableFlush(netlink.ConntrackTable)

	return errs
}

func (dp *DpManager) ReplayEverouteIPAMFlow(vdsID string, brKey string) error {
	if brKey == LOCAL_BRIDGE_KEYWORD {
		// replay icmp reply flow
		gws := dp.ippoolGWs.UnsortedList()
		for _, gw := range gws {
			if err := dp.BridgeChainMap[vdsID][brKey].AddIPPoolGW(gw); err != nil {
				return err
			}
		}
	}

	if brKey == UPLINK_BRIDGE_KEYWORD || brKey == LOCAL_BRIDGE_KEYWORD {
		// replay arp and ip reply flow
		subnets := dp.ippoolSubnets.UnsortedList()
		for _, subnet := range subnets {
			if err := dp.BridgeChainMap[vdsID][brKey].AddIPPoolSubnet(subnet); err != nil {
				return err
			}
		}
	}

	return nil
}

func (dp *DpManager) AddIPPoolSubnet(subnet string) error {
	dp.lockflowReplayWithTimeout()
	defer dp.flowReplayMutex.Unlock()
	if dp.ippoolSubnets.Has(subnet) {
		return nil
	}

	for vdsID := range dp.BridgeChainMap {
		if err := dp.BridgeChainMap[vdsID][UPLINK_BRIDGE_KEYWORD].AddIPPoolSubnet(subnet); err != nil {
			klog.Errorf("Failed to add IPPool subnet %s flow in uplink bridge: %v", subnet, err)
			return err
		}
		if err := dp.BridgeChainMap[vdsID][LOCAL_BRIDGE_KEYWORD].AddIPPoolSubnet(subnet); err != nil {
			klog.Errorf("Failed to add IPPool subnet %s flow in local bridge: %v", subnet, err)
			return err
		}
	}

	dp.ippoolSubnets.Insert(subnet)
	return nil
}

func (dp *DpManager) DelIPPoolSubnet(subnet string) error {
	dp.lockflowReplayWithTimeout()
	defer dp.flowReplayMutex.Unlock()
	if !dp.ippoolSubnets.Has(subnet) {
		return nil
	}

	for vdsID := range dp.BridgeChainMap {
		if err := dp.BridgeChainMap[vdsID][UPLINK_BRIDGE_KEYWORD].DelIPPoolSubnet(subnet); err != nil {
			klog.Errorf("Failed to delete IPPool subnet %s flow in uplink bridge: %v", subnet, err)
			return err
		}
		if err := dp.BridgeChainMap[vdsID][LOCAL_BRIDGE_KEYWORD].DelIPPoolSubnet(subnet); err != nil {
			klog.Errorf("Failed to delete IPPool subnet %s flow in local bridge: %v", subnet, err)
			return err
		}
	}
	dp.ippoolSubnets.Delete(subnet)
	return nil
}

func (dp *DpManager) AddIPPoolGW(gw string) error {
	dp.lockflowReplayWithTimeout()
	defer dp.flowReplayMutex.Unlock()
	if dp.ippoolGWs.Has(gw) {
		return nil
	}

	for vdsID := range dp.BridgeChainMap {
		if err := dp.BridgeChainMap[vdsID][LOCAL_BRIDGE_KEYWORD].AddIPPoolGW(gw); err != nil {
			klog.Errorf("Failed to add IPPool gw %s flow in local bridge: %v", gw, err)
			return err
		}
	}

	dp.ippoolGWs.Insert(gw)
	return nil
}

func (dp *DpManager) DelIPPoolGW(gw string) error {
	dp.lockflowReplayWithTimeout()
	defer dp.flowReplayMutex.Unlock()
	if !dp.ippoolGWs.Has(gw) {
		return nil
	}

	for vdsID := range dp.BridgeChainMap {
		if err := dp.BridgeChainMap[vdsID][LOCAL_BRIDGE_KEYWORD].DelIPPoolGW(gw); err != nil {
			klog.Errorf("Failed to delete IPPool gw %s flow in local bridge: %v", gw, err)
			return err
		}
	}
	dp.ippoolGWs.Delete(gw)
	return nil
}

func (dp *DpManager) WaitForBridgeConnected() {
	for i := 0; i < 40; i++ {
		time.Sleep(1 * time.Second)
		if dp.IsBridgesConnected() {
			return
		}
	}

	klog.Fatalf("bridge chain Failed to connect")
}

func (dp *DpManager) IsBridgesConnected() bool {
	var dpStatus = false

	for _, bridgeChain := range dp.BridgeChainMap {
		for bridgeKey := range bridgeChain {
			if !bridgeChain[bridgeKey].IsSwitchConnected() {
				return dpStatus
			}
		}
	}

	dpStatus = true

	return dpStatus
}

func (dp *DpManager) skipLocalEndpoint(endpoint *Endpoint) bool {
	// skip ovs patch port
	if strings.HasSuffix(endpoint.InterfaceName, LocalToPolicySuffix) {
		return true
	}
	if strings.HasSuffix(endpoint.InterfaceName, LocalToNatSuffix) {
		return true
	}
	// skip cni local gateway
	if dp.Info.LocalGwName == endpoint.InterfaceName {
		return true
	}

	// skip cni bridge default interface
	if endpoint.InterfaceName == dp.Info.BridgeName {
		return true
	}

	return false
}

func (dp *DpManager) AddLocalEndpoint(endpoint *Endpoint) error {
	dp.lockflowReplayWithTimeout()
	defer dp.flowReplayMutex.Unlock()
	if !dp.IsBridgesConnected() {
		dp.WaitForBridgeConnected()
	}

	if dp.skipLocalEndpoint(endpoint) {
		return nil
	}

	for vdsID, ovsbrname := range dp.Config.ManagedVDSMap {
		if ovsbrname == endpoint.BridgeName {
			if ep, _ := dp.localEndpointDB.Get(endpoint.InterfaceUUID); ep != nil {
				klog.Infof("Already added local endpoint: %v", ep)
				return nil
			}

			// For endpoint event, first, we add it to local endpoint db, keep local endpointDB is consistent with
			// ovsdb interface table.
			// if it's failed to add endpoint flow, replayVDSFlow routine would rebuild local endpoint flow according to
			// current localEndpointDB
			dp.localEndpointDB.Set(endpoint.InterfaceUUID, endpoint)
			for kword := range dp.BridgeChainMap[vdsID] {
				br := dp.BridgeChainMap[vdsID][kword]
				if err := br.AddLocalEndpoint(endpoint); err != nil {
					return fmt.Errorf("failed to add local endpoint %s to vds %v, bridge %v, error: %v", endpoint.InterfaceUUID, vdsID, br.GetName(), err)
				}
			}
			break
		}
	}

	return nil
}

func (dp *DpManager) UpdateLocalEndpoint(newEndpoint, oldEndpoint *Endpoint) error {
	dp.lockflowReplayWithTimeout()
	defer dp.flowReplayMutex.Unlock()
	if !dp.IsBridgesConnected() {
		dp.WaitForBridgeConnected()
	}
	var err error

	for vdsID, ovsbrname := range dp.Config.ManagedVDSMap {
		if ovsbrname == newEndpoint.BridgeName {
			oldEP, _ := dp.localEndpointDB.Get(oldEndpoint.InterfaceUUID)
			if oldEP == nil {
				return fmt.Errorf("old local endpoint: %v not found", oldEP)
			}
			ep := oldEP.(*Endpoint)
			if dp.Config.EnableIPLearning {
				// NOTE copy ip addr cached in oldEP to newEndpoint can get learning ip address
				newEndpoint.IPAddr = utils.IPCopy(ep.IPAddr)
			}

			// assume that ofport does not update, so doesn't need to remove old flow for local bridge overlay
			dp.localEndpointDB.Remove(oldEndpoint.InterfaceUUID)
			if !dp.IsEnableOverlay() {
				err = dp.BridgeChainMap[vdsID][LOCAL_BRIDGE_KEYWORD].RemoveLocalEndpoint(oldEndpoint)
				if err != nil {
					return fmt.Errorf("failed to remove old local endpoint %v from vds %v, bridge %v, error: %v", oldEndpoint.InterfaceUUID, vdsID, ovsbrname, err)
				}
			}

			if dp.skipLocalEndpoint(newEndpoint) {
				break
			}
			if newEP, _ := dp.localEndpointDB.Get(newEndpoint.InterfaceUUID); newEP != nil {
				return fmt.Errorf("new local endpoint: %v already exits", newEP)
			}
			dp.localEndpointDB.Set(newEndpoint.InterfaceUUID, newEndpoint)
			for kword := range dp.BridgeChainMap[vdsID] {
				br := dp.BridgeChainMap[vdsID][kword]
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

func (dp *DpManager) RemoveLocalEndpoint(endpoint *Endpoint) error {
	dp.lockflowReplayWithTimeout()
	defer dp.flowReplayMutex.Unlock()
	if !dp.IsBridgesConnected() {
		dp.WaitForBridgeConnected()
	}
	ep, _ := dp.localEndpointDB.Get(endpoint.InterfaceUUID)
	if ep == nil {
		return fmt.Errorf("Endpoint with interface name: %v, ofport: %v wasnot found", endpoint.InterfaceName, endpoint.PortNo)
	}
	cachedEP := ep.(*Endpoint)

	for vdsID, ovsbrname := range dp.Config.ManagedVDSMap {
		if ovsbrname == cachedEP.BridgeName {
			// Same as addLocalEndpoint routine, keep datapath endpointDB is consistent with ovsdb
			dp.localEndpointDB.Remove(endpoint.InterfaceUUID)
			for kword := range dp.BridgeChainMap[vdsID] {
				br := dp.BridgeChainMap[vdsID][kword]
				if err := br.RemoveLocalEndpoint(endpoint); err != nil {
					return fmt.Errorf("failed to remove local endpoint %v to vds %v, bridge %v, error: %v", endpoint.InterfaceUUID, vdsID, br.GetName(), err)
				}
			}

			break
		}
	}

	return nil
}

func (dp *DpManager) updatePolicyRuleNumForAddRule(policyName string, oriRuleRef map[PolicyRuleRef]struct{}) {
	for k := range oriRuleRef {
		if k.Policy == policyName {
			return
		}
	}
	dp.policyRuleNums[policyName]++
}

func (dp *DpManager) updatePolicyRuleNumForRemoveRule(policyName string, policyRef map[PolicyRuleRef]struct{}) {
	for k := range policyRef {
		if k.Policy == policyName {
			return
		}
	}
	dp.decPolicyRuleNum(policyName)
}

func (dp *DpManager) decPolicyRuleNum(policyName string) {
	if dp.policyRuleNums[policyName] > 0 {
		dp.policyRuleNums[policyName]--
	}
	if dp.policyRuleNums[policyName] <= 0 {
		delete(dp.policyRuleNums, policyName)
	}
}

//nolint:all
func (dp *DpManager) AddEveroutePolicyRule(ctx context.Context, rule *EveroutePolicyRule, ruleBase RuleBaseInfo) error {
	log := ctrl.LoggerFrom(ctx, "ruleBase", ruleBase, "newRule", rule)
	dp.lockflowReplayWithTimeout()
	defer dp.flowReplayMutex.Unlock()
	if !dp.IsBridgesConnected() {
		dp.WaitForBridgeConnected()
	}

	policyRef := ruleBase.Ref
	// check if we already have the rule
	ruleEntry := dp.Rules[rule.RuleID]
	var oldRule *EveroutePolicyRule
	if ruleEntry != nil {
		if RuleIsSame(ruleEntry.EveroutePolicyRule, rule) {
			dp.updatePolicyRuleNumForAddRule(policyRef.Policy, ruleEntry.PolicyRuleReference)
			ruleEntry.PolicyRuleReference[policyRef] = struct{}{}
			log.Info("Rule already exists, skip add flow")
			return nil
		}
		oldRule = ruleEntry.EveroutePolicyRule
	}
	log = log.WithValues("oldRule", oldRule)
	ctx = ctrl.LoggerInto(ctx, log)

	seqID, err := dp.SeqIDAlloctorForRule.Allocate()
	if err != nil {
		log.Error(err, "Failed to allocate seqID for rule")
		return err
	}
	ruleFlowMap := make(map[string]*FlowEntry)
	// Install policy rule flow to datapath
	for vdsID, bridgeChain := range dp.BridgeChainMap {
		logL := ctrl.LoggerFrom(ctx, "vds", vdsID, "bridge", bridgeChain[POLICY_BRIDGE_KEYWORD].GetName())
		ctxL := ctrl.LoggerInto(ctx, logL)
		flowEntry, err := bridgeChain[POLICY_BRIDGE_KEYWORD].AddMicroSegmentRule(ctxL, seqID, rule, ruleBase.Direction, ruleBase.Tier, ruleBase.Mode)
		if err != nil {
			return err
		}
		ruleFlowMap[vdsID] = flowEntry
	}

	dp.cleanConntrackFlow(ctx, rule)

	// save the rule. ruleFlowMap need deepcopy, NOTE
	if ruleEntry == nil {
		dp.policyRuleNums[policyRef.Policy]++
		ruleEntry = &EveroutePolicyRuleEntry{
			PolicyRuleReference: map[PolicyRuleRef]struct{}{policyRef: struct{}{}},
		}
	}
	ruleEntry.Direction = ruleBase.Direction
	ruleEntry.Tier = ruleBase.Tier
	ruleEntry.Mode = ruleBase.Mode
	ruleEntry.EveroutePolicyRule = rule
	ruleEntry.RuleFlowMap = ruleFlowMap
	dp.Rules[rule.RuleID] = ruleEntry
	// save flowID reference
	for _, v := range ruleEntry.RuleFlowMap {
		dp.FlowIDToRules[v.FlowID] = ruleEntry
	}
	log.Info("Success to add or update rule")
	return nil
}

func (dp *DpManager) RemoveEveroutePolicyRule(ctx context.Context, ruleID string, ruleBase RuleBaseInfo) error {
	log := ctrl.LoggerFrom(ctx)
	dp.lockflowReplayWithTimeout()
	defer dp.flowReplayMutex.Unlock()
	if !dp.IsBridgesConnected() {
		dp.WaitForBridgeConnected()
	}

	policyRef := ruleBase.Ref
	pRule := dp.Rules[ruleID]
	if pRule == nil {
		log.Error(utils.ErrInternal, "rule not found when deleting", "ruleID", ruleID, "ruleRef", ruleBase.Ref)
		return nil
	}
	// for log
	oldRule := *pRule.EveroutePolicyRule
	ruleBase.Direction = pRule.Direction
	ruleBase.Tier = pRule.Tier
	ruleBase.Mode = pRule.Mode
	log = log.WithValues("rule", oldRule, "ruleBase", ruleBase)

	// check and remove rule reference
	delete(pRule.PolicyRuleReference, policyRef)
	if len(pRule.PolicyRuleReference) > 0 {
		dp.updatePolicyRuleNumForRemoveRule(policyRef.Policy, pRule.PolicyRuleReference)
		log.Info("Rule referenced by other policy rules, skip del flow")
		return nil
	}

	var errs []error
	var delFlowIDs, resFlowIDs []uint64
	defer dp.releaseRuleSeqID(ctx, delFlowIDs, resFlowIDs)
	for vdsID := range dp.BridgeChainMap {
		err := ofctrl.DeleteFlow(pRule.RuleFlowMap[vdsID].Table, pRule.RuleFlowMap[vdsID].Priority, pRule.RuleFlowMap[vdsID].FlowID)
		if err != nil {
			log.Error(err, "Failed to delete flow for rule", "vdsID", vdsID)
			resFlowIDs = append(resFlowIDs, pRule.RuleFlowMap[vdsID].FlowID)
			errs = append(errs, err)
			continue
		}
		delFlowIDs = append(delFlowIDs, pRule.RuleFlowMap[vdsID].FlowID)
		log.V(2).Info("Success to delete flow for rule", "vdsID", vdsID)
		// remove flowID reference
		delete(dp.FlowIDToRules, pRule.RuleFlowMap[vdsID].FlowID)
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}

	dp.cleanConntrackFlow(ctx, pRule.EveroutePolicyRule)

	delete(dp.Rules, ruleID)
	dp.decPolicyRuleNum(policyRef.Policy)
	log.Info("Success delete rule")
	return nil
}

func (dp *DpManager) releaseRuleSeqID(ctx context.Context, dels, ress []uint64) {
	log := ctrl.LoggerFrom(ctx)
	if len(dels) == 0 {
		return
	}
	delSeqIDs := sets.New[uint32]()
	resSeqIDs := sets.New[uint32]()
	for i := range dels {
		delSeqIDs.Insert(GetSeqIDByFlowID(dels[i]))
	}
	for i := range ress {
		resSeqIDs.Insert(GetSeqIDByFlowID(ress[i]))
	}
	needReleases := delSeqIDs.Difference(resSeqIDs)
	if len(needReleases) == 0 {
		return
	}
	for _, seqID := range needReleases.UnsortedList() {
		dp.SeqIDAlloctorForRule.Release(seqID)
	}
	log.V(4).Info("success release seq ids", "seqIDs", needReleases)
}

func (dp *DpManager) GetNatBridges() []*NatBridge {
	natBrs := []*NatBridge{}
	for vdsID := range dp.BridgeChainMap {
		natBr := dp.BridgeChainMap[vdsID][NAT_BRIDGE_KEYWORD]
		if natBr != nil {
			natBrs = append(natBrs, natBr.(*NatBridge))
		}
	}
	return natBrs
}

func (dp *DpManager) GetUplinkBridgeOverlay() *UplinkBridgeOverlay {
	for vdsID := range dp.BridgeChainMap {
		br := dp.BridgeChainMap[vdsID][UPLINK_BRIDGE_KEYWORD]
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

func (dp *DpManager) syncIntenalIPs(stopChan <-chan struct{}) {
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
			dp.addIntenalIP(addr.LinkAddress.IP.String(), addr.LinkIndex)
		} else {
			dp.removeIntenalIP(addr.LinkAddress.IP.String(), addr.LinkIndex)
		}
	}
}

func (dp *DpManager) addIntenalIP(ip string, index int) {
	ruleNameSuffix := fmt.Sprintf("%s-%d", ip, index)

	ruleBase1 := RuleBaseInfo{
		Ref: PolicyRuleRef{
			Policy: InternalIngressPolicy,
			Rule:   InternalIngressRulePrefix + ruleNameSuffix,
		},
		Direction: POLICY_DIRECTION_IN,
		Tier:      POLICY_TIER3,
		Mode:      DEFAULT_POLICY_ENFORCEMENT_MODE,
	}
	// add internal ingress rule
	err := dp.AddEveroutePolicyRule(context.Background(), newInternalIngressRule(ip), ruleBase1)
	if err != nil {
		klog.Fatalf("Failed to add internal whitelist: %s: %v", ip, err)
	}

	ruleBase2 := RuleBaseInfo{
		Ref: PolicyRuleRef{
			Policy: InternalEgressPolicy,
			Rule:   InternalEgressRulePrefix + ruleNameSuffix,
		},
		Direction: POLICY_DIRECTION_OUT,
		Tier:      POLICY_TIER3,
		Mode:      DEFAULT_POLICY_ENFORCEMENT_MODE,
	}
	// add internal egress rule
	err = dp.AddEveroutePolicyRule(context.Background(), newInternalEgressRule(ip), ruleBase2)
	if err != nil {
		klog.Fatalf("Failed to add internal whitelist: %s: %v", ip, err)
	}
}

func (dp *DpManager) removeIntenalIP(ip string, index int) {
	ruleNameSuffix := fmt.Sprintf("%s-%d", ip, index)

	ruleBase1 := RuleBaseInfo{
		Ref: PolicyRuleRef{
			Policy: InternalEgressPolicy,
			Rule:   InternalEgressRulePrefix + ruleNameSuffix,
		},
	}
	// del internal ingress rule
	err := dp.RemoveEveroutePolicyRule(context.Background(), newInternalIngressRule(ip).RuleID, ruleBase1)
	if err != nil {
		klog.Fatalf("Failed to del internal whitelist %s: %v", ip, err)
	}

	ruleBase2 := RuleBaseInfo{
		Ref: PolicyRuleRef{
			Policy: InternalEgressPolicy,
			Rule:   InternalEgressRulePrefix + ruleNameSuffix,
		},
	}
	// del internal egress rule
	err = dp.RemoveEveroutePolicyRule(context.Background(), newInternalEgressRule(ip).RuleID, ruleBase2)
	if err != nil {
		klog.Fatalf("Failed to del internal whitelist %s: %v", ip, err)
	}
}

func (dp *DpManager) getFlush() bool {
	dp.lockflushWithTimeout()
	defer dp.flushMutex.Unlock()
	return dp.needFlush
}

func (dp *DpManager) setFlush(needFlush bool) {
	dp.lockflushWithTimeout()
	defer dp.flushMutex.Unlock()
	dp.needFlush = needFlush
}

func (dp *DpManager) cleanConntrackWorker(family uint8, cleanChan chan EveroutePolicyRuleForCT) {
	for {
		// only one worker (ipv4) process flush
		if family == unix.AF_INET && dp.getFlush() {
			dp.lockflushWithTimeout()
			err := netlink.ConntrackTableFlush(netlink.ConntrackTable)
			if err != nil {
				klog.Errorf("Flush ct failed: %v", err)
			} else {
				dp.needFlush = false
				klog.Info("Success flush ct")
			}
			dp.flushMutex.Unlock()
		}

		ruleList := receiveRuleListFromChan(cleanChan)
		if ruleList == nil {
			return
		}
		ruleIDs := []string{}
		for i := range ruleList {
			ruleIDs = append(ruleIDs, ruleList[i].RuleID)
		}
		matches, err := netlink.ConntrackDeleteFilter(netlink.ConntrackTable, netlink.InetFamily(family), ruleList)
		if err != nil {
			klog.Errorf("clear conntrack error, rules: %s, err: %s", ruleIDs, err)
			continue
		}
		klog.Infof("clear conntrack for rules %s, matches: %d", ruleIDs, matches)
	}
}

func (dp *DpManager) cleanConntrackFlow(ctx context.Context, rule *EveroutePolicyRule) {
	log := ctrl.LoggerFrom(ctx)
	if rule == nil {
		log.Error(utils.ErrInternal, "The rule for clean conntrack flow is nil")
		return
	}

	if dp.getFlush() {
		return
	}

	var cleanChan chan EveroutePolicyRuleForCT
	switch rule.IPFamily {
	case unix.AF_INET:
		cleanChan = dp.cleanConntrackChan
	case unix.AF_INET6:
		cleanChan = dp.cleanConntrackChanV6
	}

	if len(cleanChan) < cap(cleanChan) {
		cleanChan <- rule.toEveroutePolicyRuleForCT()
		return
	}

	log.Info("The clean Conntrack Chan has blocked, clean channel")
	for {
		select {
		case <-cleanChan:
		default:
			dp.setFlush(true)
			return
		}
	}
}

func (dp *DpManager) IsEnableCNI() bool {
	if dp.Config == nil {
		return false
	}
	return dp.Config.EnableCNI
}

func (dp *DpManager) IsEnableProxy() bool {
	if !dp.IsEnableCNI() {
		return false
	}
	if dp.Config.CNIConfig == nil {
		return false
	}

	return dp.Config.CNIConfig.EnableProxy
}

func (dp *DpManager) IsEnableKubeProxyReplace() bool {
	if !dp.IsEnableProxy() {
		return false
	}

	return dp.Config.CNIConfig.KubeProxyReplace
}

func (dp *DpManager) IsEnableOverlay() bool {
	if !dp.IsEnableCNI() {
		return false
	}
	if dp.Config.CNIConfig == nil {
		return false
	}

	return dp.Config.CNIConfig.EncapMode == cniconst.EncapModeGeneve
}

func (dp *DpManager) UseEverouteIPAM() bool {
	if !dp.IsEnableOverlay() {
		return false
	}

	return dp.Config.CNIConfig.IPAMType == cniconst.EverouteIPAM
}

func (dp *DpManager) HandleEndpointIPTimeout(_ context.Context, endpointIP *types.EndpointIP) error {
	ofSwitch := dp.getOfSwitchByBridge(endpointIP.BridgeName, LOCAL_BRIDGE_KEYWORD)
	if ofSwitch == nil {
		return fmt.Errorf("connect to bridge %s break", endpointIP.BridgeName)
	}
	sendProbeRequest(ofSwitch, endpointIP.OfPort, endpointIP.VlanID, endpointIP.Mac, endpointIP.IP)
	return nil
}

func (dp *DpManager) getOfSwitchByBridge(bridgeName, bridgeKeyword string) *ofctrl.OFSwitch {
	dp.DpManagerMutex.Lock()
	defer dp.DpManagerMutex.Unlock()

	for _, bridgeChain := range dp.BridgeChainMap {
		if bridgeChain[bridgeKeyword].GetName() == bridgeName {
			return bridgeChain[bridgeKeyword].getOfSwitch()
		}
	}
	return nil
}

func genArpRequestPkt(dstIP net.IP, srcMac net.HardwareAddr, vlanID uint16) *protocol.Ethernet {
	arp, _ := protocol.NewARP(protocol.Type_Request)
	arp.IPDst = dstIP
	arp.HWSrc = srcMac

	arpReqPkt := protocol.NewEthernet()
	arpReqPkt.HWSrc = srcMac
	arpReqPkt.HWDst = []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	arpReqPkt.VLANID.VID = vlanID
	arpReqPkt.Ethertype = protocol.ARP_MSG
	arpReqPkt.Data = arp

	return arpReqPkt
}

func netIPFromIP(ip net.IP) netip.Addr {
	return lo.T2(netip.AddrFromSlice(ip)).A
}

func multicastIPv6(targetIP net.IP) net.IP {
	ip, _ := netip.AddrFromSlice(targetIP)
	return net.ParseIP(lo.Must(ndp.SolicitedNodeMulticast(ip)).String())
}

func genNdpNSPkt(dstIP net.IP, srcMac net.HardwareAddr, vlanID uint16) *protocol.Ethernet {
	srcIP, _ := eui64.ParseMAC(net.ParseIP("fe80::"), srcMac)
	icmpv6Pkt := util.NewBuffer(lo.Must(ndp.MarshalMessageChecksum(&ndp.NeighborSolicitation{
		TargetAddress: netIPFromIP(dstIP),
		Options:       []ndp.Option{&ndp.LinkLayerAddress{Direction: ndp.Source, Addr: srcMac}},
	}, netIPFromIP(srcIP), netIPFromIP(multicastIPv6(dstIP)))))

	ipv6Pkt := &protocol.IPv6{
		Version:    6,
		Length:     icmpv6Pkt.Len(),
		NextHeader: protocol.Type_IPv6ICMP,
		HopLimit:   255,
		NWSrc:      srcIP,
		NWDst:      multicastIPv6(dstIP),
		Data:       icmpv6Pkt,
	}

	ethPkt := protocol.NewEthernet()
	ethPkt.HWSrc = srcMac
	ethPkt.HWDst = []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	ethPkt.VLANID.VID = vlanID
	ethPkt.Ethertype = protocol.IPv6_MSG
	ethPkt.Data = ipv6Pkt

	return ethPkt
}

func sendProbeRequest(ofSwitch *ofctrl.OFSwitch, ofPort uint32, vlanID uint16, srcMac net.HardwareAddr, dstIP net.IP) {
	ofPacketOut := openflow13.NewPacketOut()
	ofPacketOut.AddAction(openflow13.NewActionOutput(ofPort))

	if utils.IsIPv4(dstIP.String()) {
		ofPacketOut.Data = genArpRequestPkt(dstIP, srcMac, vlanID)
	}
	if utils.IsIPv6(dstIP.String()) {
		ofPacketOut.Data = genNdpNSPkt(dstIP, srcMac, vlanID)
	}

	_ = ofSwitch.Send(ofPacketOut)
}

func receiveRuleListFromChan(ruleChan <-chan EveroutePolicyRuleForCT) EveroutePolicyRuleList {
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

	externalIDs, err := ovsdbDriver.GetExternalIds()
	if err != nil {
		return nil, fmt.Errorf("failed to get ovsdb externalids: %v", err)
	}

	if len(externalIDs) == 0 {
		klog.Infof("Bridge's external-ids are empty")
		return &RoundInfo{
			curRoundNum: uint64(1),
		}, nil
	}

	roundNum, exists := externalIDs[datapathRestartRound]
	if !exists {
		klog.Infof("Bridge's external-ids don't contain ofnetRestartRound field")
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
	externalIDs, err := ovsdbDriver.GetExternalIds()
	if err != nil {
		return err
	}

	externalIDs[datapathRestartRound] = fmt.Sprint(curRoundNum)

	return ovsdbDriver.SetExternalIds(externalIDs)
}

// ParseIPAddrMaskString Parse IP addr string
func ParseIPAddrMaskString(ipAddr string) (*net.IP, *net.IP, error) {
	if ipAddr == "" {
		return nil, nil, nil
	}

	if strings.Contains(ipAddr, "/") {
		ipDav, ipNet, err := net.ParseCIDR(ipAddr)
		if err != nil {
			return nil, nil, err
		}
		ipMask := net.IP(ipNet.Mask)
		return &ipDav, &ipMask, nil
	}

	ipDa := net.ParseIP(ipAddr)
	if ipDa == nil {
		return nil, nil, errors.New("failed to parse ip address")
	}

	var ipMask net.IP
	if utils.IsIPv4(ipAddr) {
		ipMask = net.IPv4bcast
	} else {
		ipMask = IPv6AllFF
	}

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
		IPFamily:  utils.GetIPFamily(internalIP),
		Action:    EveroutePolicyAllow,
	}
}

// newInternalEgressRule generate a rule allow all egress from internalIP
func newInternalEgressRule(internalIP string) *EveroutePolicyRule {
	return &EveroutePolicyRule{
		RuleID:    fmt.Sprintf("internal.egress.%s", internalIP),
		Priority:  constants.InternalWhitelistPriority,
		SrcIPAddr: internalIP,
		IPFamily:  utils.GetIPFamily(internalIP),
		Action:    EveroutePolicyAllow,
	}
}
