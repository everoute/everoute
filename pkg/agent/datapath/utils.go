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
	"encoding/binary"
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"

	cnitypes "github.com/containernetworking/cni/pkg/types"
	openflow "github.com/contiv/libOpenflow/openflow13"
	"github.com/contiv/ofnet/ofctrl"
	log "github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"

	policycache "github.com/everoute/everoute/pkg/agent/controller/policy/cache"
	"github.com/everoute/everoute/pkg/apis/rpc/v1alpha1"
	cniconst "github.com/everoute/everoute/pkg/constants/cni"
	"github.com/everoute/everoute/pkg/metrics"
	"github.com/everoute/everoute/pkg/types"
)

const (
	SetupBridgeChain = `
		set -o errexit
		set -o nounset
		set -o xtrace

		DEFAULT_BRIDGE=%s
		POLICY_BRIDGE="${DEFAULT_BRIDGE}-policy"
		CLS_BRIDGE="${DEFAULT_BRIDGE}-cls"
		UPLINK_BRIDGE="${DEFAULT_BRIDGE}-uplink"

		LOCAL_TO_POLICY_PATCH="${DEFAULT_BRIDGE}-local-to-policy"
		POLICY_TO_LOCAL_PATCH="${POLICY_BRIDGE}-policy-to-local"
		POLICY_TO_CLS_PATCH="${POLICY_BRIDGE}-policy-to-cls"
		CLS_TO_POLICY_PATCH="${CLS_BRIDGE}-cls-to-policy"
		CLS_TO_UPLINK_PATCH="${CLS_BRIDGE}-cls-to-uplink"
		UPLINK_TO_CLS_PATCH="${UPLINK_BRIDGE}-uplink-to-cls"

		echo "add bridge chain and uplink port"
		ovs-vsctl add-br ${DEFAULT_BRIDGE}
		ovs-vsctl add-br ${POLICY_BRIDGE}
		ovs-vsctl add-br ${CLS_BRIDGE}
		ovs-vsctl add-br ${UPLINK_BRIDGE}

		ovs-vsctl \
		    -- add-port ${DEFAULT_BRIDGE} ${LOCAL_TO_POLICY_PATCH} \
		    -- set interface ${LOCAL_TO_POLICY_PATCH} type=patch options:peer=${POLICY_TO_LOCAL_PATCH} \
		    -- add-port ${POLICY_BRIDGE} ${POLICY_TO_LOCAL_PATCH} \
		    -- set interface ${POLICY_TO_LOCAL_PATCH} type=patch options:peer=${LOCAL_TO_POLICY_PATCH}

		ovs-vsctl \
		    -- add-port ${POLICY_BRIDGE} ${POLICY_TO_CLS_PATCH} \
		    -- set interface ${POLICY_TO_CLS_PATCH} type=patch options:peer=${CLS_TO_POLICY_PATCH} \
		    -- add-port ${CLS_BRIDGE} ${CLS_TO_POLICY_PATCH} \
		    -- set interface ${CLS_TO_POLICY_PATCH} type=patch options:peer=${POLICY_TO_CLS_PATCH} 

		ovs-vsctl \
		    -- add-port ${UPLINK_BRIDGE} ${UPLINK_TO_CLS_PATCH} \
		    -- set interface ${UPLINK_TO_CLS_PATCH} type=patch options:peer=${CLS_TO_UPLINK_PATCH} \
		    -- add-port ${CLS_BRIDGE} ${CLS_TO_UPLINK_PATCH} \
		    -- set interface ${CLS_TO_UPLINK_PATCH} type=patch options:peer=${UPLINK_TO_CLS_PATCH} 

		ovs-ofctl add-flow ${UPLINK_BRIDGE} "table=0,priority=10,actions=normal"
    `
	CleanBridgeChain = `
		DEFAULT_BRIDGE=%s
		POLICY_BRIDGE="${DEFAULT_BRIDGE}-policy"
		CLS_BRIDGE="${DEFAULT_BRIDGE}-cls"
		UPLINK_BRIDGE="${DEFAULT_BRIDGE}-uplink"

		ovs-vsctl \
			-- del-br ${DEFAULT_BRIDGE} \
			-- del-br ${POLICY_BRIDGE} \
			-- del-br ${CLS_BRIDGE} \
			-- del-br ${UPLINK_BRIDGE}
    `

	SetupCNIBridgeChain = `
		set -o errexit
		set -o nounset
		set -o xtrace

		DEFAULT_BRIDGE=%s
		UPLINK_BRIDGE="${DEFAULT_BRIDGE}-uplink"
		GW_IFACE=${DEFAULT_BRIDGE}-gw
		GW_LOCAL_IFACE=${DEFAULT_BRIDGE}-gw-local

		ovs-vsctl add-port ${UPLINK_BRIDGE} ${GW_IFACE} -- set Interface ${GW_IFACE} type=internal
		ovs-vsctl add-port ${DEFAULT_BRIDGE} ${GW_LOCAL_IFACE} -- set Interface ${GW_LOCAL_IFACE} type=internal
	`

	SetupProxyBridgeChain = `
		set -o errexit
		set -o nounset
		set -o xtrace

		DEFAULT_BRIDGE=%s
		NAT_BRIDGE="${DEFAULT_BRIDGE}-nat"
		LOCAL_TO_NAT_PATCH="${DEFAULT_BRIDGE}-local-to-nat"
		NAT_TO_LOCAL_PATCH="${NAT_BRIDGE}-nat-to-local"

		ovs-vsctl add-br ${NAT_BRIDGE} -- set bridge ${NAT_BRIDGE} protocols=OpenFlow10,OpenFlow11,OpenFlow12,OpenFlow13 fail_mode=secure
		ip link set ${NAT_BRIDGE} up
		ovs-vsctl \
			-- add-port ${DEFAULT_BRIDGE} ${LOCAL_TO_NAT_PATCH} \
			-- set interface ${LOCAL_TO_NAT_PATCH} type=patch options:peer=${NAT_TO_LOCAL_PATCH} \
			-- add-port ${NAT_BRIDGE} ${NAT_TO_LOCAL_PATCH} \
			-- set interface ${NAT_TO_LOCAL_PATCH} type=patch options:peer=${LOCAL_TO_NAT_PATCH}
	`

	SetupTunnelBridgeChain = `
		set -o errexit
		set -o nounset
		set -o xtrace

		DEFAULT_BRIDGE=%s
		UPLINK_BRIDGE="${DEFAULT_BRIDGE}-uplink"
		TUNNEL_IFACE="${DEFAULT_BRIDGE}-tunnel"

		ovs-vsctl add-port ${UPLINK_BRIDGE} ${TUNNEL_IFACE} -- set interface ${TUNNEL_IFACE} type=geneve options:key=5000 options:remote_ip=flow
	`

	CleanProxyBridgeChain = `
		NAT_BRIDGE="%s-nat"
		ovs-vsctl -- del-br ${NAT_BRIDGE}
	`
)

func ExcuteCommand(cmdStr, arg string) error {
	commandStr := fmt.Sprintf(cmdStr, arg)
	out, err := exec.Command("/bin/sh", "-c", commandStr).CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to excute cmd: %v, error: %v", string(out), err)
	}

	return nil
}

func InitCNIDpMgrUT(ctx context.Context, brName string, enableProxy bool, enableOverlay bool, enableIPAM bool) (*DpManager, error) {
	var err error
	dpConfig := &DpManagerConfig{
		ManagedVDSMap: map[string]string{brName: brName},
		EnableCNI:     true,
		CNIConfig:     &DpManagerCNIConfig{},
	}
	if enableProxy {
		dpConfig.CNIConfig.EnableProxy = true
	}
	if enableOverlay {
		dpConfig.CNIConfig.EncapMode = cniconst.EncapModeGeneve
	}
	if enableIPAM {
		dpConfig.CNIConfig.IPAMType = cniconst.EverouteIPAM
	}

	updateChan := make(chan *types.EndpointIP, 10)
	datapathManager := NewDatapathManager(dpConfig, updateChan, metrics.NewAgentMetric())
	datapathManager.InitializeDatapath(ctx)

	agentInfo := datapathManager.Info
	agentInfo.NodeName = "testnode"
	podCidr, _ := cnitypes.ParseCIDR("10.0.0.0/24")
	agentInfo.PodCIDR = append(agentInfo.PodCIDR, cnitypes.IPNet(*podCidr))
	cidr, _ := cnitypes.ParseCIDR("10.96.0.0/12")
	cidrNet := cnitypes.IPNet(*cidr)
	agentInfo.ClusterCIDR = &cidrNet
	clusterPodCidr, _ := cnitypes.ParseCIDR("10.0.0.0/16")
	agentInfo.ClusterPodCIDR = clusterPodCidr
	agentInfo.BridgeName = brName
	agentInfo.GatewayName = agentInfo.BridgeName + "-gw"
	agentInfo.LocalGwName = agentInfo.BridgeName + "-gw-local"
	agentInfo.LocalGwOfPort, err = datapathManager.OvsdbDriverMap[brName][LOCAL_BRIDGE_KEYWORD].GetOfpPortNo(agentInfo.LocalGwName)
	if err != nil {
		return nil, err
	}
	agentInfo.LocalGwIP = net.ParseIP("10.0.100.100")
	agentInfo.LocalGwMac, _ = net.ParseMAC("fe:00:5e:00:53:01")
	agentInfo.GatewayIP = net.ParseIP("10.0.0.1")
	agentInfo.GatewayMac, _ = net.ParseMAC("fe:00:5e:00:53:06")
	if enableOverlay {
		agentInfo.GatewayOfPort, err = datapathManager.OvsdbDriverMap[brName][UPLINK_BRIDGE_KEYWORD].GetOfpPortNo(agentInfo.GatewayName)
		if err != nil {
			return nil, err
		}
		agentInfo.TunnelOfPort, err = datapathManager.OvsdbDriverMap[brName][UPLINK_BRIDGE_KEYWORD].GetOfpPortNo(brName + "-tunnel")
		if err != nil {
			return nil, err
		}
	}

	if enableIPAM {
		agentInfo.GatewayIP = net.ParseIP("240.100.0.2")
		agentInfo.GatewayMask = net.IPMask(net.ParseIP("255.255.0.0"))
		clusterPodGw := net.ParseIP("240.100.0.1")
		agentInfo.ClusterPodGw = &clusterPodGw
	}

	datapathManager.InitializeCNI()

	return datapathManager, nil
}

func ParseMacToUint64(b []byte) uint64 {
	_ = b[5]
	return uint64(b[5]) | uint64(b[4])<<8 | uint64(b[3])<<16 | uint64(b[2])<<24 |
		uint64(b[1])<<32 | uint64(b[0])<<40 | 0<<48 | 0<<56
}

func datapathRule2RpcRule(entry *EveroutePolicyRuleEntry) *v1alpha1.RuleEntry {
	rpcRFM := map[string]*v1alpha1.FlowEntry{}
	for k, v := range entry.RuleFlowMap {
		rpcRFM[k] = &v1alpha1.FlowEntry{
			Priority: uint32(v.Priority),
			FlowID:   v.FlowID,
		}
	}
	rpcReference := []*v1alpha1.PolicyRuleReference{}
	for reference := range entry.PolicyRuleReference {
		references := strings.Split(reference.Rule, "/")
		if len(references) < 3 {
			continue
		}
		rpcReference = append(rpcReference, &v1alpha1.PolicyRuleReference{
			NameSpace: references[0],
			Name:      references[1],
			Type:      references[2],
		})
	}
	return &v1alpha1.RuleEntry{
		EveroutePolicyRule: &v1alpha1.PolicyRule{
			RuleID:      entry.EveroutePolicyRule.RuleID,
			Priority:    int32(entry.EveroutePolicyRule.Priority),
			SrcIPAddr:   entry.EveroutePolicyRule.SrcIPAddr,
			DstIPAddr:   entry.EveroutePolicyRule.DstIPAddr,
			IPProtocol:  uint32(entry.EveroutePolicyRule.IPProtocol),
			SrcPort:     uint32(entry.EveroutePolicyRule.SrcPort),
			SrcPortMask: uint32(entry.EveroutePolicyRule.SrcPortMask),
			DstPort:     uint32(entry.EveroutePolicyRule.DstPort),
			DstPortMask: uint32(entry.EveroutePolicyRule.DstPortMask),
			Action:      entry.EveroutePolicyRule.Action,
		},
		Direction:           uint32(entry.Direction),
		Tier:                uint32(entry.Tier),
		Mode:                entry.Mode,
		RuleFlowMap:         rpcRFM,
		PolicyRuleReference: rpcReference,
	}
}

func uintToByteBigEndian(src interface{}) []byte {
	var res []byte

	switch src := src.(type) {
	case uint8:
		res = make([]byte, 1)
		res[0] = src
	case uint16:
		res = make([]byte, 2)
		binary.BigEndian.PutUint16(res, src)
	case uint32:
		res = make([]byte, 4)
		binary.BigEndian.PutUint32(res, src)
	case uint64:
		res = make([]byte, 8)
		binary.BigEndian.PutUint64(res, src)
	default:
		log.Errorf("Not support convert type %T to []byte", src)
	}

	return res
}

// trunk string looks like "1,2,3,10,11,12,13,1000,1001,1002,1003"
func getVlanTrunkMask(trunk []uint16) map[uint16]uint16 {
	var vlanID2MaskMap = make(map[uint16]uint16)
	idRange := toVlanRange(trunk)
	for b, e := range idRange {
		idToMask := vlanRangeToMask(b, e)
		for id, mask := range idToMask {
			vlanID2MaskMap[id] = mask
		}
	}

	return vlanID2MaskMap
}

func vlanRangeToMask(begin, end uint16) map[uint16]uint16 {
	var vlanID2MaskMap = make(map[uint16]uint16)

	if begin == 0 && end == 0 {
		vlanID2MaskMap[0] = 4095
		return vlanID2MaskMap
	}

	var pos int
	for begin <= end && begin != 0 {
		var temp = begin
		pos = 16
		for {
			if temp%2 == 1 {
				break
			}
			temp >>= 1
			pos--
		}
		for i := pos; i <= 16; i++ {
			if end >= begin+(1<<(16-i))-1 {
				vlanID2MaskMap[begin] = posToMask(i)
				begin += 1 << (16 - i)
				break
			}
		}
	}

	return vlanID2MaskMap
}

func toVlanRange(ids []uint16) map[uint16]uint16 {
	var idRange = make(map[uint16]uint16)
	var idBitMap [4096]bool
	for _, id := range ids {
		idBitMap[id] = true
	}

	begin := -1
	end := -1
	for index, bit := range idBitMap {
		if index == 0 && bit {
			idRange[uint16(index)] = uint16(index)
			continue
		}

		if bit && begin == -1 {
			begin = index
		}
		if bit && begin != -1 && index == len(idBitMap)-1 {
			end = index
		}
		if !bit && begin != -1 {
			end = index - 1
		}
		if begin != -1 && end != -1 {
			idRange[uint16(begin)] = uint16(end)
			begin = -1
			end = -1
		}
	}

	return idRange
}

func posToMask(pos int) uint16 {
	var ret uint16 = 0xffff
	for i := 16; i > pos; i-- {
		ret <<= 1
	}

	return ret
}

func toTrunkVlanIDs(trunks string) []uint16 {
	var idList []uint16
	for _, id := range strings.Split(trunks, ",") {
		if vid, err := strconv.ParseUint(id, 10, 16); err == nil {
			idList = append(idList, uint16(vid))
		}
	}

	return idList
}

func ipv4ToUint32(ip net.IP) uint32 {
	ipv4 := ip.To4()
	return binary.BigEndian.Uint32(ipv4)
}

func ipv4ToUint64(ip net.IP) uint64 {
	ipUint32 := ipv4ToUint32(ip)
	return uint64(ipUint32)
}

func k8sProtocolToOvsProtocol(p corev1.Protocol) (uint8, error) {
	switch p {
	case corev1.ProtocolTCP:
		return PROTOCOL_TCP, nil
	case corev1.ProtocolUDP:
		return PROTOCOL_UDP, nil
	default:
		return 0, fmt.Errorf("invalid protocol %s, only support TCP and UDP", p)
	}
}

func setupArpProxyFlowAction(arpProxyFlow *ofctrl.Flow, proxyMac net.HardwareAddr) error {
	if err := arpProxyFlow.SetMacSa(proxyMac); err != nil {
		return err
	}
	if err := arpProxyFlow.MoveField(MacLength, 0, 0, "nxm_of_eth_src", "nxm_of_eth_dst", false); err != nil {
		return err
	}
	if err := arpProxyFlow.LoadField("nxm_of_arp_op", ArpOperReply, openflow.NewNXRange(0, 15)); err != nil {
		return err
	}
	if err := arpProxyFlow.LoadField("nxm_nx_arp_sha", ParseMacToUint64(proxyMac), openflow.NewNXRange(0, 47)); err != nil {
		return err
	}
	if err := arpProxyFlow.MoveField(MacLength, 0, 0, "nxm_nx_arp_sha", "nxm_nx_arp_tha", false); err != nil {
		return err
	}
	return arpProxyFlow.MoveField(IPv4Lenth, 0, 0, "nxm_of_arp_tpa", "nxm_of_arp_spa", false)
}

func setupArpProxyFlow(t *ofctrl.Table, cidr *net.IPNet, next ofctrl.FgraphElem) (*ofctrl.Flow, error) {
	f, _ := t.NewFlow(ofctrl.FlowMatch{
		Ethertype:  PROTOCOL_ARP,
		ArpTpa:     &cidr.IP,
		ArpTpaMask: (*net.IP)(&cidr.Mask),
		ArpOper:    ArpOperRequest,
		Priority:   MID_MATCH_FLOW_PRIORITY,
	})
	fakeMac, _ := net.ParseMAC(FACK_MAC)
	if err := setupArpProxyFlowAction(f, fakeMac); err != nil {
		return nil, fmt.Errorf("failed to setup arp proxy table cidr %s arp proxy flow action, err: %v", cidr, err)
	}
	if err := f.Next(next); err != nil {
		return nil, fmt.Errorf("failed to install arp proxy table cidr %s arp proxy flow, err: %v", cidr, err)
	}
	return f, nil
}

func setupIcmpProxyFlow(t *ofctrl.Table, ip *net.IP, next ofctrl.FgraphElem) (*ofctrl.Flow, error) {
	ipStr := ip.String()
	f, _ := t.NewFlow(ofctrl.FlowMatch{
		Priority:  HIGH_MATCH_FLOW_PRIORITY + FLOW_MATCH_OFFSET,
		Ethertype: PROTOCOL_IP,
		IpProto:   PROTOCOL_ICMP,
		IcmpType:  IcmpTypeRequest,
		IpDa:      ip,
	})
	if err := f.SetMacSa(net.HardwareAddr(FACK_MAC)); err != nil {
		log.Errorf("Failed to add the action that set src mac for icmp proxy ip %s: %v", ipStr, err)
		return nil, err
	}
	if err := f.SetIPField(*ip, "Src"); err != nil {
		log.Errorf("Failed to add the action that set src ip for icmp proxy ip %s: %v", ipStr, err)
		return nil, err
	}
	if err := f.LoadField("nxm_of_icmp_type", uint64(IcmpTypeReply), IcmpTypeRange); err != nil {
		log.Errorf("Failed to add load field: icmp type action for icmp proxy ip %s: %v", ipStr, err)
		return nil, err
	}
	if err := f.MoveField(IPv4Lenth, 0, 0, "nxm_of_ip_src", "nxm_of_ip_dst", false); err != nil {
		log.Errorf("Failed to add the action that move src ip to dst ip for icmp proxy ip %s: %v", ipStr, err)
		return nil, err
	}
	if err := f.MoveField(MacLength, 0, 0, "nxm_of_eth_src", "nxm_of_eth_dst", false); err != nil {
		log.Errorf("Failed to add the action that move src mac to dst mac for icmp proxy ip %s: %v", ipStr, err)
		return nil, err
	}

	if err := f.Next(next); err != nil {
		log.Errorf("Failed to install icmp reply flow for ip %s: %v", ipStr, err)
		return nil, err
	}

	return f, nil
}

func FlowKeyFromRuleName(ruleName string) string {
	// rule name format like: policyname-rulename-namehash-flowkey
	keys := strings.Split(ruleName, "-")
	return keys[len(keys)-1]
}

// func (dm *DpManager) PolicyRuleLimit(policyIDs []string, addList, deleteList []*policycache.PolicyRule) bool {
func (dm *DpManager) PolicyRuleLimit(_ []string, _, _ []*policycache.PolicyRule) bool {
	return false
	/*
		dm.lockflowReplayWithTimeout()
		defer dm.flowReplayMutex.Unlock()

		if !dm.AgentMetric.ShouldLimit(policyIDs) {
			return false
		}

		// count real rule num after changes
		addCnt := 0
		delCnt := 0
		for _, item := range addList {
			if dm.GetRuleEntryByRuleID(FlowKeyFromRuleName(item.Name)) == nil {
				addCnt++
			}
		}
		for _, item := range deleteList {
			entry := dm.GetRuleEntryByRuleID(FlowKeyFromRuleName(item.Name))
			if entry != nil && len(entry.PolicyRuleReference.List()) <= 1 {
				delCnt++
			}
		}

		diffSize := addCnt - delCnt
		return len(dm.ListRuleEntry())*len(dm.BridgeChainMap)+diffSize > RuleEntryCap
	*/
}

func (dm *DpManager) PolicyRuleMetricsUpdate(policyIDs []string, limited bool) {
	for _, k := range policyIDs {
		dm.AgentMetric.SetRuleEntryNum(k, dm.policyRuleNums[k], limited)
	}

	dm.AgentMetric.SetRuleEntryTotalNum(len(dm.Rules))
}
