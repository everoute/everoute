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
	"k8s.io/klog"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/manager"
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

	StopChan    <-chan struct{}
	updateMutex sync.Mutex

	iptCtrl *eriptables.RouteIPtables
}

func GetNodeInternalIP(node corev1.Node) net.IP {
	ipString := utils.GetNodeInternalIP(node)
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

func RouteEqual(r1, r2 netlink.Route) bool {
	return ((r1.Dst == nil && r2.Dst == nil) ||
		(r1.Dst != nil && r2.Dst != nil && r1.Dst.String() == r2.Dst.String())) &&
		r1.Src.Equal(r2.Src) &&
		r1.Gw.Equal(r2.Gw)
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
	klog.Infof("update network config")
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
func (r *NodeReconciler) Reconcile(req ctrl.Request) (ctrl.Result, error) {
	klog.Infof("NodeReconciler received node %s reconcile", req.NamespacedName)

	r.UpdateNetwork()

	return ctrl.Result{}, nil
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

	err = c.Watch(&source.Kind{Type: &corev1.Node{}}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return err
	}

	// update network config every 100 seconds
	ticker := time.NewTicker(100 * time.Second)
	go func() {
		for {
			select {
			case <-ticker.C:
				r.UpdateNetwork()
			case <-r.StopChan:
				return
			}
		}
	}()

	return nil
}

func updateRouteForOverlay(clusterPodCidr *net.IPNet, gatewayIP net.IP) {
	oldRoutes := GetRouteByDst(clusterPodCidr)
	targetRoute := netlink.Route{
		Dst:   clusterPodCidr,
		Gw:    gatewayIP,
		Table: defaultRouteTable,
	}

	for i := range oldRoutes {
		if RouteEqual(oldRoutes[i], targetRoute) {
			return
		}
	}

	if err := netlink.RouteAdd(&targetRoute); err != nil {
		klog.Errorf("[ALERT] add route item failed, err: %s", err)
	} else {
		klog.Infof("add route item %v", targetRoute)
	}
}

func SetupRouteAndIPtables(mgr manager.Manager, datapathManager *datapath.DpManager, stopChan <-chan struct{}) error {
	// route mode
	if !datapathManager.IsEnableOverlay() {
		if err := (&NodeReconciler{
			Client:          mgr.GetClient(),
			Scheme:          mgr.GetScheme(),
			DatapathManager: datapathManager,
			StopChan:        stopChan,
		}).SetupWithManager(mgr); err != nil {
			klog.Errorf("unable to create node controller: %s", err.Error())
			return err
		}
		return nil
	}

	// overlay mode
	clusterPodCidr := datapathManager.Info.ClusterPodCidr
	clusterPodCidrString := clusterPodCidr.String()
	gatewayIP := datapathManager.Info.GatewayIP
	iptCtrl := eriptables.NewOverlayIPtables(datapathManager.Config.CNIConfig.EnableProxy, &eriptables.Options{
		LocalGwName:    datapathManager.Info.LocalGwName,
		ClusterPodCidr: clusterPodCidrString,
	})
	// update network config every 100 seconds
	ticker := time.NewTicker(100 * time.Second)
	go func() {
		for {
			select {
			case <-ticker.C:
				updateRouteForOverlay(clusterPodCidr, gatewayIP)
				iptCtrl.Update()
			case <-stopChan:
				return
			}
		}
	}()
	return nil
}
