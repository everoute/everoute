package proxy

import (
	"net"
	"sync"

	"github.com/vishvananda/netlink"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/klog/v2"

	"github.com/everoute/everoute/pkg/agent/datapath"
	"github.com/everoute/everoute/pkg/constants"
	"github.com/everoute/everoute/pkg/utils"
)

type OverlayRoute interface {
	Update()
	AddRouteByDst(dstCIDR string) error
	DelRouteByDst(dstCIDR string) error
	InsertPodCIDRs(cidrs ...string)
	DelPodCIDRs(cidrs ...string)
}

type overlayRoute struct {
	lock      sync.RWMutex
	podCIDRs  sets.Set[string]
	gatewayIP net.IP
	dpManger  *datapath.DpManager
}

func NewOverlayRoute(gatewayIP net.IP, clusterPodCIDR string, dpManager *datapath.DpManager) OverlayRoute {
	o := &overlayRoute{
		gatewayIP: gatewayIP,
		podCIDRs:  sets.New[string](),
		dpManger:  dpManager,
	}
	if clusterPodCIDR != "" {
		o.podCIDRs.Insert(clusterPodCIDR)
	}
	return o
}

func (o *overlayRoute) Update() {
	o.setFixRoute()

	o.lock.RLock()
	defer o.lock.RUnlock()

	curRoutes, err := GetRoutesByGW(o.gatewayIP)
	if err != nil {
		klog.Errorf("[ALERT] update route failed when list route: %v", err)
		return
	}
	curCIDRs := sets.New[string]()
	for _, r := range curRoutes {
		curCIDRs.Insert(r.Dst.String())
	}

	delCIDRs := curCIDRs.Difference(o.podCIDRs).UnsortedList()
	addCIDRs := o.podCIDRs.Difference(curCIDRs).UnsortedList()
	for _, c := range addCIDRs {
		if err := o.AddRouteByDst(c); err != nil {
			klog.Errorf("[ALERT] add route item failed, err: %v", err)
		}
	}
	for _, c := range delCIDRs {
		if err := o.DelRouteByDst(c); err != nil {
			klog.Errorf("[ALERT] del route item failed, err: %v", err)
		}
	}
}

func (o *overlayRoute) AddRouteByDst(dstCIDR string) error {
	_, dst, err := net.ParseCIDR(dstCIDR)
	if err != nil {
		klog.Errorf("Parse cidr %s failed: %v", dstCIDR, err)
		return err
	}
	targetRoute := netlink.Route{
		Dst:   dst,
		Gw:    o.gatewayIP,
		Table: defaultRouteTable,
	}

	exists, err := IsRouteExist(&targetRoute)
	if err != nil {
		klog.Errorf("List route %v failed, err: %v", targetRoute, err)
		return err
	}
	if exists {
		return nil
	}

	if err := netlink.RouteAdd(&targetRoute); err != nil {
		klog.Errorf("Add route %v failed: %v", targetRoute, err)
		return err
	}
	klog.Infof("Success to add route %v", targetRoute)
	return nil
}

func (o *overlayRoute) DelRouteByDst(dstCIDR string) error {
	_, dst, err := net.ParseCIDR(dstCIDR)
	if err != nil {
		klog.Errorf("Parse cidr %s failed: %v", dstCIDR, err)
		return err
	}

	delRoute := netlink.Route{
		Dst:   dst,
		Gw:    o.gatewayIP,
		Table: defaultRouteTable,
	}
	exists, err := IsRouteExist(&delRoute)
	if err != nil {
		klog.Errorf("List route %v failed, err: %v", delRoute, err)
		return err
	}
	if !exists {
		return nil
	}

	if err := netlink.RouteDel(&delRoute); err != nil {
		klog.Errorf("Del route %v failed: %v", delRoute, err)
		return err
	}
	klog.Infof("Success to del route %v", delRoute)
	return nil
}

func (o *overlayRoute) InsertPodCIDRs(cidrs ...string) {
	o.lock.Lock()
	defer o.lock.Unlock()

	o.podCIDRs.Insert(cidrs...)
}

func (o *overlayRoute) DelPodCIDRs(cidrs ...string) {
	o.lock.Lock()
	defer o.lock.Unlock()

	o.podCIDRs.Delete(cidrs...)
}

func (o *overlayRoute) setFixRoute() {
	if !o.dpManger.IsEnableProxy() {
		SetFixRouteWhenDisableERProxy(o.dpManger.Info)
	}

	if o.dpManger.IsEnableKubeProxyReplace() {
		if err := ChangeLocalRulePriority(); err != nil {
			klog.Errorf("Failed to change local rule priority: %s", err)
		}
		if err := o.addRouteForSvc(); err != nil {
			klog.Errorf("Failed to add route and rule for svc: %s", err)
		}
	}
}

func (o *overlayRoute) addRouteForSvc() error {
	route := &netlink.Route{
		Table: constants.SvcToGWRouteTable,
		Gw:    o.dpManger.Info.GatewayIP,
		Dst: &net.IPNet{
			IP:   net.IPv4(0, 0, 0, 0),
			Mask: net.CIDRMask(0, 32),
		},
	}
	exists, err := IsRouteExist(route)
	if err != nil {
		klog.Errorf("Failed to get route %s, err: %s", route, err)
		return err
	}
	if !exists {
		if err := netlink.RouteReplace(route); err != nil {
			klog.Errorf("Failed to add route %s, err: %s", route, err)
			return err
		}
	}

	svcRule := netlink.NewRule()
	svcRule.Mark = 1 << constants.ExternalSvcPktMarkBit
	svcRule.Mask = 1 << constants.ExternalSvcPktMarkBit
	svcRule.Table = constants.SvcToGWRouteTable
	svcRule.Priority = constants.SvcRulePriority
	if err := utils.RuleAdd(svcRule, netlink.RT_FILTER_MARK|netlink.RT_FILTER_MASK|netlink.RT_FILTER_PRIORITY|netlink.RT_FILTER_TABLE); err != nil {
		klog.Errorf("Failed to add rule %s, err: %s", svcRule, err)
		return err
	}
	clusterIPRule := netlink.NewRule()
	clusterIPRule.Dst = (*net.IPNet)(o.dpManger.Info.ClusterCIDR)
	clusterIPRule.Table = constants.SvcToGWRouteTable
	clusterIPRule.Priority = constants.ClusterIPSvcRulePriority
	if err := utils.RuleAdd(clusterIPRule, netlink.RT_FILTER_DST|netlink.RT_FILTER_TABLE|netlink.RT_FILTER_PRIORITY); err != nil {
		klog.Errorf("Failed to add rule %s, err: %s", clusterIPRule, err)
		return err
	}
	svcLocalIPRule := netlink.NewRule()
	svcLocalIPRule.Dst = &net.IPNet{
		IP:   o.dpManger.Config.CNIConfig.SvcInternalIP,
		Mask: net.CIDRMask(32, 32),
	}
	svcLocalIPRule.Table = constants.SvcToGWRouteTable
	svcLocalIPRule.Priority = constants.SvcLocalIPRulePriority
	if err := utils.RuleAdd(svcLocalIPRule, netlink.RT_FILTER_DST|netlink.RT_FILTER_TABLE|netlink.RT_FILTER_PRIORITY); err != nil {
		klog.Errorf("Failed to add rule %s, err: %s", svcLocalIPRule, err)
		return err
	}
	return nil
}
