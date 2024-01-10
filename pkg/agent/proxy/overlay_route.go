package proxy

import (
	"net"
	"sync"

	"github.com/vishvananda/netlink"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/klog"
)

type OverlayRoute struct {
	lock      sync.RWMutex
	podCIDRs  sets.Set[string]
	gatewayIP net.IP
}

func NewOverlayRoute(gatewayIP net.IP, clusterPodCIDR string) *OverlayRoute {
	o := &OverlayRoute{
		gatewayIP: gatewayIP,
		podCIDRs:  sets.New[string](),
	}
	if clusterPodCIDR != "" {
		o.podCIDRs.Insert(clusterPodCIDR)
	}
	return o
}

func (o *OverlayRoute) Update() {
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

func (o *OverlayRoute) AddRouteByDst(dstCIDR string) error {
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

func (o *OverlayRoute) DelRouteByDst(dstCIDR string) error {
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

func (o *OverlayRoute) InsertPodCIDRs(cidrs ...string) {
	o.lock.Lock()
	defer o.lock.Unlock()

	o.podCIDRs.Insert(cidrs...)
}

func (o *OverlayRoute) DelPodCIDRs(cidrs ...string) {
	o.lock.Lock()
	defer o.lock.Unlock()

	o.podCIDRs.Delete(cidrs...)
}
