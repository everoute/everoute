package main

import (
	"net"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"k8s.io/klog"

	"github.com/everoute/everoute/pkg/agent/datapath"
	"github.com/everoute/everoute/pkg/constants"
	"github.com/everoute/everoute/pkg/utils"
)

func setLinkAddr(agentInfo *datapath.DpManagerInfo) {
	// set gateway ip address
	if err := utils.SetLinkAddr(agentInfo.GatewayName,
		&net.IPNet{
			IP:   agentInfo.GatewayIP,
			Mask: agentInfo.GatewayMask}); err != nil {
		klog.Fatalf("Set gateway ip address error, err:%s", err)
	}

	if opts.IsEnableProxy() {
		return
	}
	// set local gateway ip address
	if err := utils.SetLinkAddr(agentInfo.LocalGwName, &net.IPNet{
		IP:   agentInfo.LocalGwIP,
		Mask: net.CIDRMask(32, 32),
	}); err != nil {
		klog.Fatalf("Set local gateway ip address error, err: %s", err)
	}
}

func setRoute(agentInfo *datapath.DpManagerInfo) {
	if opts.IsEnableProxy() {
		return
	}

	if err := changeLocalRulePriority(); err != nil {
		klog.Fatalf("Failed to change local rule priority: %s", err)
	}
	if err := addRouteForTableLocalGw(agentInfo); err != nil {
		klog.Fatalf("Failed to add route to table that from local gw: %s", err)
	}
}

func changeLocalRulePriority() error {
	newLocalRule := netlink.NewRule()
	newLocalRule.Table = unix.RT_TABLE_LOCAL
	newLocalRule.Priority = constants.LocalRulePriority
	if err := utils.RuleAdd(newLocalRule, netlink.RT_FILTER_PRIORITY|netlink.RT_FILTER_TABLE); err != nil {
		klog.Errorf("Failed to add rule %s, err: %s", newLocalRule, err)
		return err
	}

	oldLocalRule := netlink.NewRule()
	oldLocalRule.Table = unix.RT_TABLE_LOCAL
	// netlink lib default priority is -1, priority 0 won't reassign to rule.Priority when list rule
	oldLocalRule.Priority = -1
	if err := utils.RuleDel(oldLocalRule, netlink.RT_FILTER_PRIORITY|netlink.RT_FILTER_TABLE); err != nil {
		klog.Errorf("Failed to find rule %s, err: %s", oldLocalRule, err)
		return err
	}
	return nil
}

func addRouteForTableLocalGw(agentInfo *datapath.DpManagerInfo) error {
	route := &netlink.Route{
		Table: constants.FromGwLocalRouteTable,
		Gw:    agentInfo.LocalGwIP,
		Dst: &net.IPNet{
			IP:   net.IPv4(0, 0, 0, 0),
			Mask: net.CIDRMask(0, 32),
		},
	}
	if err := netlink.RouteReplace(route); err != nil {
		klog.Errorf("Failed to add route %s, err: %s", route, err)
		return err
	}

	rule := netlink.NewRule()
	rule.IifName = agentInfo.LocalGwName
	rule.Table = constants.FromGwLocalRouteTable
	rule.Priority = constants.FromGwLocalRulePriority
	if err := utils.RuleAdd(rule, netlink.RT_FILTER_IIF|netlink.RT_FILTER_PRIORITY|netlink.RT_FILTER_TABLE); err != nil {
		klog.Errorf("Failed to add rule %s, err: %s", rule, err)
		return err
	}
	return nil
}
