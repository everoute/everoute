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

package utils

import (
	"fmt"
	"net"
	"strings"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/klog/v2"

	"github.com/everoute/everoute/pkg/types"
	"github.com/everoute/everoute/third_party/netutil"
)

// EqualIPs return true when two IP set have same IPaddresses.
func EqualIPs(ips1, ips2 []types.IPAddress) bool {
	toset := func(ips []types.IPAddress) sets.Set[string] {
		set := sets.New[string]()
		for _, ip := range ips {
			set.Insert(ip.String())
		}
		return set
	}

	return len(ips1) == len(ips2) && toset(ips1).Equal(toset(ips2))
}

// ParseIPBlock parse ipBlock to list of IPNets.
func ParseIPBlock(ipBlock *networkingv1.IPBlock) ([]*net.IPNet, error) {
	var (
		cidrIPNet    *net.IPNet
		exceptIPNets []*net.IPNet
		err          error
	)

	_, cidrIPNet, err = net.ParseCIDR(ipBlock.CIDR)
	if err != nil {
		return nil, err
	}

	// parse all except into exceptIPNets
	for _, exceptCIDR := range ipBlock.Except {
		_, exceptIPNet, err := net.ParseCIDR(exceptCIDR)
		if err != nil {
			return nil, err
		}
		exceptIPNets = append(exceptIPNets, exceptIPNet)
	}

	return netutil.DiffFromCIDRs(cidrIPNet, exceptIPNets)
}

func IPCopy(src net.IP) net.IP {
	if src == nil {
		return nil
	}
	dst := make(net.IP, len(src))
	copy(dst, src)
	return dst
}

func GetIfaceIP(name string) (net.IP, error) {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return nil, err
	}
	list, err := netlink.AddrList(link, unix.AF_INET)
	if err != nil {
		return nil, err
	}
	return list[0].IP, nil
}

func GetIfaceMAC(name string) (net.HardwareAddr, error) {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return nil, err
	}
	return link.Attrs().HardwareAddr, nil
}

func GetLinkByIP(ip string) (netlink.Link, error) {
	allAddrs, err := netlink.AddrList(nil, unix.AF_INET)
	if err != nil {
		return nil, err
	}

	for i := range allAddrs {
		if allAddrs[i].IP.String() == ip {
			return netlink.LinkByIndex(allAddrs[i].LinkIndex)
		}
	}

	return nil, fmt.Errorf("can't find link by ip %s", ip)
}

func GetIfaceMTUByIP(ip string) (int, error) {
	link, err := GetLinkByIP(ip)
	if err != nil {
		return 0, err
	}
	return link.Attrs().MTU, nil
}

func SetLinkAddr(ifname string, inet *net.IPNet) error {
	link, err := netlink.LinkByName(ifname)
	if err != nil {
		klog.Errorf("failed to lookup %q: %v", ifname, err)
		return err
	}
	if err = netlink.LinkSetUp(link); err != nil {
		klog.Errorf("failed to set %q UP: %v", ifname, err)
		return err
	}
	addr := &netlink.Addr{
		IPNet: inet,
		Label: ""}
	if err = netlink.AddrReplace(link, addr); err != nil {
		klog.Errorf("failed to add IP addr to %s: %v", ifname, err)
		return err
	}
	return nil
}

func IsRuleExist(rule *netlink.Rule, filterMask uint64) (bool, error) {
	rules, err := netlink.RuleListFiltered(unix.AF_INET, rule, filterMask)
	if err != nil {
		klog.Errorf("Failed to list rule %s, err: %s", rule, err)
		return false, err
	}
	if len(rules) == 0 {
		return false, nil
	}
	return true, nil
}

func RuleAdd(rule *netlink.Rule, filterMask uint64) error {
	if rule == nil {
		return fmt.Errorf("param rule is nil")
	}

	exists, err := IsRuleExist(rule, filterMask)
	if err != nil {
		klog.Errorf("Failed to find rule %s, err: %s", rule, err)
		return err
	}
	if exists {
		return nil
	}

	if err := netlink.RuleAdd(rule); err != nil {
		klog.Errorf("Failed to add rule %s, err: %s", rule, err)
		return err
	}
	exists, err = IsRuleExist(rule, filterMask)
	if err != nil {
		klog.Errorf("Failed to find rule %s, err: %s", rule, err)
		return err
	}
	if !exists {
		return fmt.Errorf("can't find rule %s", rule)
	}
	return nil
}

func RuleDel(rule *netlink.Rule, filterMask uint64) error {
	if rule == nil {
		return fmt.Errorf("param rule is nil")
	}

	exists, err := IsRuleExist(rule, filterMask)
	if err != nil {
		klog.Errorf("Failed to find rule %s, err: %s", rule, err)
		return err
	}
	if !exists {
		return nil
	}

	if err := netlink.RuleDel(rule); err != nil {
		klog.Errorf("Failed to delete rule %s, err: %s", rule, err)
		return err
	}
	exists, err = IsRuleExist(rule, filterMask)
	if err != nil {
		klog.Errorf("Failed to find rule %s, err: %s", rule, err)
		return err
	}
	if exists {
		return fmt.Errorf("rule %s still exist", rule)
	}
	return nil
}

func IsSameIPFamily(src, dst string) bool {
	if src == "" || dst == "" {
		return true
	}

	return (strings.Contains(src, ":") && strings.Contains(dst, ":")) ||
		(!strings.Contains(src, ":") && !strings.Contains(dst, ":"))
}

func IsIPv4Pair(src, dst string) bool {
	return (src == "" && dst == "") ||
		(src != "" && !strings.Contains(src, ":")) ||
		(dst != "" && !strings.Contains(dst, ":"))
}

func IsIPv4(ip string) bool {
	return ip == "" || !strings.Contains(ip, ":")
}

func IsIPv6Pair(src, dst string) bool {
	return (src == "" && dst == "") ||
		strings.Contains(src, ":") ||
		strings.Contains(dst, ":")
}

func IsIPv6(ip string) bool {
	return ip == "" || strings.Contains(ip, ":")
}

func GetIPFamily(ip string) uint8 {
	if IsIPv4(ip) {
		return unix.AF_INET
	}
	if IsIPv6(ip) {
		return unix.AF_INET6
	}
	return 0
}

func FormatZeroIP(ipStr string) string {
	if ipStr == "" {
		return ""
	}

	if !strings.Contains(ipStr, "/") {
		return ipStr
	}

	_, ipNet, err := net.ParseCIDR(ipStr)
	if err == nil {
		if ones, _ := ipNet.Mask.Size(); ones == 0 {
			return ""
		}
	}

	return ipStr
}
