package overlay

import (
	"context"
	"fmt"
	"sync"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	ercache "github.com/everoute/everoute/pkg/agent/controller/overlay/cache"
	"github.com/everoute/everoute/pkg/agent/datapath"
	"github.com/everoute/everoute/pkg/apis/security/v1alpha1"
	ertypes "github.com/everoute/everoute/pkg/types"
	"github.com/everoute/everoute/pkg/utils"
)

type Reconciler struct {
	client.Client
	Scheme *runtime.Scheme
	DpMgr  *datapath.DpManager

	lock      sync.RWMutex
	LocalNode string

	nodeIPsCache cache.Indexer
}

//nolint
func (r *Reconciler) ReconcileEndpoint(req ctrl.Request) (ctrl.Result, error) {
	ctx := context.Background()
	klog.Infof("Received endpoint %v reconcile", req.NamespacedName)

	ep := v1alpha1.Endpoint{}
	err := r.Get(ctx, req.NamespacedName, &ep)
	if client.IgnoreNotFound(err) != nil {
		klog.Errorf("Get endpoint %v failed: %v", req.NamespacedName, err)
		return ctrl.Result{}, err
	}

	r.lock.Lock()
	defer r.lock.Unlock()

	if errors.IsNotFound(err) {
		klog.Infof("Begin to delete endpoint %v", req.NamespacedName)
		if err := r.deleteEndpoint(req.NamespacedName); err != nil {
			klog.Errorf("Delete endpoint %v failed: %v", req.NamespacedName, err)
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	klog.Infof("Begin to create or update endpoint %v", ep)
	if err := r.updateEndpoint(ep); err != nil {
		klog.Errorf("Failed to create or update endpoint: %v, err: %v", ep, err)
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}

//nolint
func (r *Reconciler) ReconcileNode(req ctrl.Request) (ctrl.Result, error) {
	ctx := context.Background()
	klog.Infof("Receive node %v reconcile", req.NamespacedName)

	node := corev1.Node{}
	err := r.Get(ctx, req.NamespacedName, &node)
	if client.IgnoreNotFound(err) != nil {
		klog.Errorf("Failed to get node %v, err: %v", req.NamespacedName, err)
		return ctrl.Result{}, err
	}

	r.lock.RLock()
	defer r.lock.RUnlock()

	if errors.IsNotFound(err) {
		klog.Infof("Begin to delete node %v", req.NamespacedName)
		if err := r.deleteNode(req.NamespacedName); err != nil {
			klog.Errorf("Faield to delete node %v, err: %v", req.NamespacedName, err)
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	klog.Infof("Begin to create or update node %v", node)
	if err := r.updateNode(node); err != nil {
		klog.Errorf("Failed to create or update node %v, err: %v", node, err)
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

func (r *Reconciler) SetupWithManager(mgr ctrl.Manager) error {
	if mgr == nil {
		return fmt.Errorf("can't setup with nil manager")
	}

	if r.LocalNode == "" {
		return fmt.Errorf("can't setup without set param localNode")
	}

	r.nodeIPsCache = ercache.NewNodeIPsCache()

	e, err := controller.New("endpoint controller", mgr, controller.Options{
		Reconciler: reconcile.Func(r.ReconcileEndpoint),
	})
	if err != nil {
		return err
	}
	if err := e.Watch(&source.Kind{Type: &v1alpha1.Endpoint{}}, &handler.EnqueueRequestForObject{}, endpointPredicate()); err != nil {
		return err
	}

	n, err := controller.New("node controller", mgr, controller.Options{
		Reconciler: reconcile.Func(r.ReconcileNode),
	})
	if err != nil {
		return err
	}
	err = n.Watch(&source.Kind{Type: &corev1.Node{}}, &handler.EnqueueRequestForObject{}, nodePredicate(r.LocalNode))
	return err
}

func (r *Reconciler) deleteEndpoint(key types.NamespacedName) error {
	epIndex := ercache.GenEpRefIndex(key.Namespace, key.Name)
	nodeIPsObjs, _ := r.nodeIPsCache.ByIndex(ercache.EpRefIndex, epIndex)
	if len(nodeIPsObjs) == 0 {
		return nil
	}

	for i := range nodeIPsObjs {
		nodeIPs := nodeIPsObjs[i].(*ercache.NodeIPs).DeepCopy()
		ips := nodeIPs.PodIPs[epIndex]
		if len(ips) > 0 && nodeIPs.IP != "" {
			klog.Infof("Delete remote endpoint %v ips %v for node %s with node ip %s in dp", key, ips, nodeIPs.Name, nodeIPs.IP)
			// TODO dp delete remote endpoint
		}
		delete(nodeIPs.PodIPs, epIndex)
		_ = r.nodeIPsCache.Update(nodeIPs)
	}

	return nil
}

func (r *Reconciler) updateEndpoint(ep v1alpha1.Endpoint) error {
	newAgentsSet := r.getEndpointAgentsSet(ep)
	newIPs := ipAddressesToStringSet(ep.Status.IPs)

	epIndex := ercache.GenEpRefIndex(ep.GetNamespace(), ep.GetName())
	nodeIPsObjs, _ := r.nodeIPsCache.ByIndex(ercache.EpRefIndex, epIndex)
	nodeIPsMap := deepCopyNodeIPsObjsToMap(nodeIPsObjs)

	// node add endpoint
	for curNode := range newAgentsSet {
		if _, ok := nodeIPsMap[curNode]; !ok {
			if newIPs.Len() == 0 {
				continue
			}
			obj, exists, _ := r.nodeIPsCache.GetByKey(curNode)
			if !exists {
				// no node ip, only update cache
				klog.Infof("Node %s doesn't has node ip, only update cache for endpoint %v", curNode, ep)
				nodeIPs := ercache.NewNodeIPs(curNode)
				nodeIPs.PodIPs[epIndex] = newIPs
				_ = r.nodeIPsCache.Add(nodeIPs)
			} else {
				nodeIPs := obj.(*ercache.NodeIPs).DeepCopy()
				if nodeIPs.IP != "" {
					klog.Infof("Add remote endpoint %v ips for node %s with node ip %s in dp", ep, curNode, nodeIPs.IP)
					// TODO add remote endpoint to dp
				}
				nodeIPs.PodIPs[epIndex] = newIPs
				_ = r.nodeIPsCache.Update(nodeIPs)
			}
		}
	}

	for nodeName, nodeIPs := range nodeIPsMap {
		if newAgentsSet.Has(nodeName) {
			// update endpoint in this node
			oldIPs := nodeIPs.PodIPs[epIndex]
			if oldIPs.Equal(newIPs) {
				continue
			}
			if nodeIPs.IP != "" {
				for ip := range newIPs {
					if !oldIPs.Has(ip) {
						klog.Infof("Add remote endpoint %s ip %s for node %s with node ip %s in dp", epIndex, ip, nodeName, nodeIPs.IP)
						// TODO add remote endpoint to dp
					}
				}
				for ip := range oldIPs {
					if !newIPs.Has(ip) {
						klog.Infof("Delete remote endpoint %s ip %s for node %s with node ip %s in dp", epIndex, ip, nodeName, nodeIPs.IP)
						// TODO delete remote endpoint to dp
					}
				}
			}
			nodeIPs.PodIPs[epIndex] = newIPs
			_ = r.nodeIPsCache.Update(nodeIPs)
		} else {
			// delete endpoint in this node
			if nodeIPs.IP != "" {
				klog.Infof("Delete remote endpoint %v ips for node %s with node ip %s in dp", ep, nodeName, nodeIPs.IP)
				// TODO delete remote endpoint to dp
			}
			delete(nodeIPs.PodIPs, epIndex)
			_ = r.nodeIPsCache.Update(nodeIPs)
		}
	}

	return nil
}

func (r *Reconciler) getEndpointAgentsSet(ep v1alpha1.Endpoint) sets.String {
	res := sets.NewString(ep.Status.Agents...)
	res.Delete(r.LocalNode)
	return res
}

func (r *Reconciler) deleteNode(key types.NamespacedName) error {
	obj, exists, _ := r.nodeIPsCache.GetByKey(key.Name)
	if !exists {
		return nil
	}

	nodeIPs := obj.(*ercache.NodeIPs).DeepCopy()
	if nodeIPs.IP == "" {
		_ = r.nodeIPsCache.Delete(nodeIPs)
		return nil
	}

	ips := nodeIPs.ListPodIPs()
	klog.Infof("Delete all remote ips %v of node %s with node ip %s", ips, nodeIPs.Name, nodeIPs.IP)
	// TODO delete all remote ips of deleted node in dp
	_ = r.nodeIPsCache.Delete(nodeIPs)
	return nil
}

func (r *Reconciler) updateNode(node corev1.Node) error {
	newNodeIP := utils.GetNodeInternalIP(node)
	nodeName := node.GetName()

	obj, exists, _ := r.nodeIPsCache.GetByKey(nodeName)
	if !exists {
		if newNodeIP != "" {
			nodeIPs := ercache.NewNodeIPs(nodeName)
			nodeIPs.IP = newNodeIP
			_ = r.nodeIPsCache.Add(nodeIPs)
		}
		return nil
	}

	nodeIPs := obj.(*ercache.NodeIPs).DeepCopy()
	if nodeIPs.IP == newNodeIP {
		return nil
	}
	allPodIPs := nodeIPs.ListPodIPs()
	if len(allPodIPs) == 0 {
		nodeIPs.IP = newNodeIP
		_ = r.nodeIPsCache.Update(nodeIPs)
		return nil
	}

	if nodeIPs.IP != "" {
		klog.Infof("Delete all remote ips %v with node ip %s in node %s for update node ip from %s to %s", allPodIPs, nodeIPs.IP, nodeName, nodeIPs.IP, newNodeIP)
		// TODO delete remote ip in dp
	}

	if newNodeIP != "" {
		klog.Infof("all remote ips %v with node ip %s in node %s for update node ip from %s to %s", allPodIPs, newNodeIP, nodeName, nodeIPs.IP, newNodeIP)
		// TODO add remote ip in dp
	}
	nodeIPs.IP = newNodeIP
	_ = r.nodeIPsCache.Update(nodeIPs)
	return nil
}

func deepCopyNodeIPsObjsToMap(in []interface{}) map[string]*ercache.NodeIPs {
	outMap := make(map[string]*ercache.NodeIPs, len(in))
	for i := range in {
		cur := in[i].(*ercache.NodeIPs).DeepCopy()
		outMap[cur.Name] = cur
	}

	return outMap
}

func ipAddressesToStringSet(ips []ertypes.IPAddress) sets.String {
	res := sets.NewString()
	for i := range ips {
		res.Insert(ips[i].String())
	}

	return res
}
