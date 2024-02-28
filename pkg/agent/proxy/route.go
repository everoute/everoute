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

package proxy

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/klog"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/source"

	"github.com/everoute/everoute/pkg/agent/datapath"
	eriptables "github.com/everoute/everoute/pkg/agent/proxy/iptables"
	"github.com/everoute/everoute/pkg/constants"
	"github.com/everoute/everoute/pkg/utils"
)

const (
	defaultRouteTable = 254
)

// NodeReconciler watch node and update route table
type NodeReconciler struct {
	client.Client
	Scheme *runtime.Scheme

	DatapathManager *datapath.DpManager

	StopCtx     context.Context
	updateMutex sync.Mutex

	iptCtrl *eriptables.RouteIPtables
}

func GetNodeInternalIP(node corev1.Node) net.IP {
	ipString := utils.GetNodeInternalIP(&node)
	if ipString != "" {
		return net.ParseIP(ipString)
	}
	return nil
}

func GetRouteByDst(dst *net.IPNet) []netlink.Route {
	var ret []netlink.Route
	// List all route item in current node
	routeList, err := netlink.RouteList(nil, unix.AF_INET)
	if err != nil {
		klog.Errorf("List route table error, err:%s", err)
		return ret
	}
	for _, item := range routeList {
		if item.Dst != nil && item.Dst.String() == dst.String() {
			ret = append(ret, item)
		}
	}
	return ret
}

func GetRoutesByGW(gw net.IP, tables ...int) ([]netlink.Route, error) {
	table := defaultRouteTable
	if len(tables) > 0 {
		table = tables[0]
	}
	filter := &netlink.Route{Gw: gw, Table: table}
	routes, err := netlink.RouteListFiltered(unix.AF_INET, filter, netlink.RT_FILTER_GW|netlink.RT_FILTER_TABLE)
	if err != nil {
		klog.Errorf("Failed to list route by gw %v, err: %v", gw, err)
		return nil, err
	}
	return routes, nil
}

// filter must set dst,gw,table
func IsRouteExist(filter *netlink.Route) (bool, error) {
	filterMask := netlink.RT_FILTER_DST | netlink.RT_FILTER_GW | netlink.RT_FILTER_TABLE
	routes, err := netlink.RouteListFiltered(unix.AF_INET, filter, filterMask)
	if err != nil {
		klog.Errorf("Failed to list route by filter %v, err: %v", *filter, err)
		return false, err
	}
	return len(routes) > 0, nil
}

func RouteEqual(r1, r2 netlink.Route) bool {
	return ((r1.Dst == nil && r2.Dst == nil) ||
		(r1.Dst != nil && r2.Dst != nil && r1.Dst.String() == r2.Dst.String())) &&
		r1.Src.Equal(r2.Src) &&
		r1.Gw.Equal(r2.Gw)
}

func ChangeLocalRulePriority() error {
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

func AddRouteForTableLocalGw(agentInfo *datapath.DpManagerInfo) error {
	route := &netlink.Route{
		Table: constants.FromGwLocalRouteTable,
		Gw:    agentInfo.LocalGwIP,
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

func SetFixRouteWhenDisableERProxy(agentInfo *datapath.DpManagerInfo) {
	if err := ChangeLocalRulePriority(); err != nil {
		klog.Errorf("Failed to change local rule priority: %s", err)
	}

	if err := AddRouteForTableLocalGw(agentInfo); err != nil {
		klog.Errorf("Failed to add route and rule for witch from local gw: %s", err)
	}
}

func (r *NodeReconciler) SetFixRoute() {
	if r.DatapathManager.IsEnableProxy() {
		return
	}

	SetFixRouteWhenDisableERProxy(r.DatapathManager.Info)
}

// UpdateRoute will be called when Node has been updated, or every 100 seconds.
// This function will update route table in linux kernel. Old related route items which are useless will be deleted,
// and new route item will be added.
// In each node, there will be (n-1) * mi route items, n means the num of nodes, mi means m pod cidrs in node i.
// for example, if there are two nodes in cluster and node2 has two pod cidrs, Here are route item in node1:
// ip route add node2-podCIDR-1 via node2
// ip route add node2-podCIDR-2 via node2
func (r *NodeReconciler) UpdateRoute(nodeList corev1.NodeList, thisNode corev1.Node) {
	var oldRoute []netlink.Route
	var targetRoute []netlink.Route
	var err error

	for _, item := range nodeList.Items {
		// ignore current node
		if item.Name == thisNode.Name {
			continue
		}
		gw := GetNodeInternalIP(item)
		if gw == nil {
			klog.Errorf("Fail to get node internal IP in node: %s", item.Name)
			continue
		}
		// multi-podCIDRs will create multi-routeItem
		for _, podCIDR := range item.Spec.PodCIDRs {
			dst, err := netlink.ParseIPNet(podCIDR)
			if err != nil {
				klog.Errorf("Parse podCIDR %s failed, err: %s", podCIDR, err)
			}
			tempRoute := GetRouteByDst(dst)
			if len(tempRoute) != 0 {
				oldRoute = append(oldRoute, tempRoute...)
			}
			targetRoute = append(targetRoute, netlink.Route{
				Dst:   dst,
				Gw:    gw,
				Table: defaultRouteTable,
			})
		}
	}

	var delRoute []netlink.Route
	targetRouteExist := make([]bool, len(targetRoute))
	// calculate route to add and delete
	for _, oldItem := range oldRoute {
		exist := false
		for i, newItem := range targetRoute {
			if RouteEqual(oldItem, newItem) {
				exist = true
				targetRouteExist[i] = true
				break
			}
		}
		if !exist {
			delRoute = append(delRoute, oldItem)
		}
	}

	// add & del route
	for i := range delRoute {
		if err = netlink.RouteDel(&delRoute[i]); err != nil {
			klog.Errorf("delete route item failed, err: %s", err)
		} else {
			klog.Infof("delete route item %s", &delRoute[i])
		}
	}
	for i := range targetRoute {
		// skip existed route
		if targetRouteExist[i] {
			continue
		}
		if err = netlink.RouteAdd(&targetRoute[i]); err != nil {
			klog.Errorf("[ALERT] add route item failed, err: %s", err)
		} else {
			klog.Infof("add route item %s", &targetRoute[i])
		}
	}
}

func (r *NodeReconciler) UpdateNetwork() {
	r.updateMutex.Lock()
	defer r.updateMutex.Unlock()

	// List all nodes in cluster
	nodeList := corev1.NodeList{}
	if err := r.List(context.Background(), &nodeList); err != nil {
		klog.Errorf("List Node error, err: %s", err)
		return
	}
	// Get current node
	var currentNode corev1.Node
	for _, item := range nodeList.Items {
		if item.Name == r.DatapathManager.Info.NodeName {
			currentNode = item
			break
		}
	}

	r.UpdateRoute(nodeList, currentNode)
	r.iptCtrl.Update(nodeList, currentNode)
}

// Reconcile receive node from work queue, synchronize network config
func (r *NodeReconciler) Reconcile(_ context.Context, req ctrl.Request) (ctrl.Result, error) {
	klog.Infof("NodeReconciler received node %s reconcile", req.NamespacedName)

	r.UpdateNetwork()

	return ctrl.Result{}, nil
}

func nodePredicate(localNode string) predicate.Predicate {
	return predicate.Funcs{
		CreateFunc: func(e event.CreateEvent) bool {
			if e.Object.GetName() == localNode {
				return false
			}
			o, ok := e.Object.(*corev1.Node)
			if !ok {
				klog.Errorf("Node create event transform to node resource failed, event: %v", e)
				return false
			}
			if utils.GetNodeInternalIP(o) != "" && len(o.Spec.PodCIDRs) != 0 {
				return true
			}
			return false
		},
		UpdateFunc: func(e event.UpdateEvent) bool {
			if e.ObjectNew.GetName() == localNode {
				return false
			}
			oldObj, oldOk := e.ObjectOld.(*corev1.Node)
			newObj, newOk := e.ObjectNew.(*corev1.Node)
			if !oldOk || !newOk {
				klog.Errorf("Node update event transform to node resource failed, event: %v", e)
				return false
			}
			if utils.GetNodeInternalIP(oldObj) != utils.GetNodeInternalIP(newObj) {
				return true
			}
			if !sets.NewString(oldObj.Spec.PodCIDRs...).Equal(sets.NewString(newObj.Spec.PodCIDRs...)) {
				return true
			}
			return false
		},
		DeleteFunc: func(e event.DeleteEvent) bool {
			return e.Object.GetName() != localNode
		},
	}
}

// SetupWithManager create and add Endpoint Controller to the manager.
func (r *NodeReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if mgr == nil {
		return fmt.Errorf("can't setup with nil manager")
	}

	r.iptCtrl = eriptables.NewRouteIPtables(r.DatapathManager.IsEnableProxy(), &eriptables.Options{
		LocalGwName: r.DatapathManager.Info.LocalGwName,
	})

	c, err := controller.New("node-controller", mgr, controller.Options{
		MaxConcurrentReconciles: constants.DefaultMaxConcurrentReconciles,
		Reconciler:              r,
	})
	if err != nil {
		return err
	}

	err = c.Watch(source.Kind(mgr.GetCache(), &corev1.Node{}), &handler.EnqueueRequestForObject{}, nodePredicate(r.DatapathManager.Info.NodeName))
	if err != nil {
		return err
	}

	// update network config every 100 seconds
	go wait.NonSlidingUntilWithContext(r.StopCtx, func(context.Context) {
		r.SetFixRoute()
		r.UpdateNetwork()
	}, 100*time.Second)

	return nil
}

// SetupRouteAndIPtables setup route and iptables for overlay mode
func SetupRouteAndIPtables(ctx context.Context, datapathManager *datapath.DpManager) (eriptables.OverlayIPtables, OverlayRoute) {
	clusterPodCIDR := datapathManager.Info.ClusterPodCIDR
	clusterPodCIDRString := clusterPodCIDR.String()
	gatewayIP := datapathManager.Info.GatewayIP
	if datapathManager.UseEverouteIPAM() {
		clusterPodCIDRString = ""
		gatewayIP = *datapathManager.Info.ClusterPodGw
	}
	iptCtrl := eriptables.NewOverlayIPtables(datapathManager.IsEnableProxy(), &eriptables.Options{
		LocalGwName:      datapathManager.Info.LocalGwName,
		ClusterPodCIDR:   clusterPodCIDRString,
		KubeProxyReplace: datapathManager.IsEnableKubeProxyReplace(),
		SvcInternalIP:    datapathManager.Config.CNIConfig.SvcInternalIP.String(),
	})
	routeCtrl := NewOverlayRoute(gatewayIP, clusterPodCIDRString, datapathManager)

	// update network config every 100 seconds
	go wait.NonSlidingUntilWithContext(ctx, func(context.Context) {
		routeCtrl.Update()
		iptCtrl.Update()
	}, 100*time.Second)

	return iptCtrl, routeCtrl
}
