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
	"os/exec"
	"strings"

	"github.com/vishvananda/netlink"

	"github.com/everoute/everoute/pkg/apis/rpc/v1alpha1"
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
)

func ExcuteCommand(cmdStr, arg string) error {
	commandStr := fmt.Sprintf(cmdStr, arg)
	out, err := exec.Command("/bin/sh", "-c", commandStr).CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to excute cmd: %v, error: %v", string(out), err)
	}

	return nil
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
		references := strings.Split(reference, "/")
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

func (rule EveroutePolicyRule) MatchConntrackFlow(flow *netlink.ConntrackFlow) bool {
	return rule.matchIPTuple(
		flow.Forward.Protocol,
		flow.Forward.SrcIP,
		flow.Forward.DstIP,
		flow.Forward.SrcPort,
		flow.Forward.DstPort,
	) || rule.matchIPTuple(
		flow.Reverse.Protocol,
		flow.Reverse.SrcIP,
		flow.Reverse.DstIP,
		flow.Reverse.SrcPort,
		flow.Reverse.DstPort,
	)
}

func (rule EveroutePolicyRule) matchIPTuple(protocol uint8, srcIP, dstIP net.IP, srcPort, dstPort uint16) bool {
	if rule.IPProtocol != 0 && rule.IPProtocol != protocol {
		return false
	}
	if rule.SrcIPAddr != "" && !matchIP(rule.SrcIPAddr, srcIP) {
		return false
	}
	if rule.DstIPAddr != "" && !matchIP(rule.DstIPAddr, dstIP) {
		return false
	}
	if rule.SrcPort != 0 && !matchPort(rule.SrcPortMask, rule.SrcPort, srcPort) {
		return false
	}
	if rule.DstPort != 0 && !matchPort(rule.DstPortMask, rule.DstPort, dstPort) {
		return false
	}

	return true
}

func matchPort(mask, port1, port2 uint16) bool {
	if mask == 0 {
		return port1 == port2
	}
	return port1&mask == port2&mask
}

func matchIP(ipRaw string, ip net.IP) bool {
	if _, ipNet, err := net.ParseCIDR(ipRaw); err == nil {
		return ipNet.Contains(ip)
	}
	return net.ParseIP(ipRaw).Equal(ip)
}

type EveroutePolicyRuleList []EveroutePolicyRule

func (list EveroutePolicyRuleList) MatchConntrackFlow(flow *netlink.ConntrackFlow) bool {
	for _, rule := range list {
		if rule.MatchConntrackFlow(flow) {
			return true
		}
	}
	return false
}
