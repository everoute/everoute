package ippool

import (
	"context"
	"fmt"
	"net"
	"os"
	"sync"

	ipamv1alpha1 "github.com/everoute/ipam/api/ipam/v1alpha1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	uerr "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/klog"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/source"

	eproxy "github.com/everoute/everoute/pkg/agent/proxy"
	eipt "github.com/everoute/everoute/pkg/agent/proxy/iptables"
	"github.com/everoute/everoute/pkg/constants"
)

type Reconciler struct {
	client.Client
	IptCtrl   *eipt.OverlayIPtables
	RouteCtrl *eproxy.OverlayRoute

	subnets map[string]sets.Set[types.NamespacedName]
	gws     map[string]sets.Set[types.NamespacedName]
	lock    sync.Mutex
}

func (r *Reconciler) SetupWithManager(mgr ctrl.Manager) error {
	if mgr == nil {
		return fmt.Errorf("can't setup with nil manager")
	}
	if r.IptCtrl == nil {
		return fmt.Errorf("param IptCtrl can't be nil")
	}
	if r.RouteCtrl == nil {
		return fmt.Errorf("param RouteCtrl can't be nil")
	}

	r.subnets = make(map[string]sets.Set[types.NamespacedName])
	r.gws = make(map[string]sets.Set[types.NamespacedName])

	c, err := controller.New("ippool-ctrl", mgr, controller.Options{
		Reconciler: r,
	})
	if err != nil {
		return err
	}

	return c.Watch(source.Kind(mgr.GetCache(), &ipamv1alpha1.IPPool{}), &handler.EnqueueRequestForObject{},
		getPredicateFunc(os.Getenv(constants.NamespaceNameENV)))
}

func (r *Reconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	klog.Infof("Receive ippool %v reconcile", req.NamespacedName)
	pool := ipamv1alpha1.IPPool{}
	err := r.Get(ctx, req.NamespacedName, &pool)
	if err != nil {
		if errors.IsNotFound(err) {
			if err := r.deleteIPPool(req.NamespacedName); err != nil {
				klog.Errorf("Failed to delete ippool %v oldcidrs, err: %v", req.NamespacedName, err)
			}
			return ctrl.Result{}, err
		}
		klog.Errorf("Failed to get ippool %v, err: %v", req.NamespacedName, err)
		return ctrl.Result{}, err
	}

	if err := r.addIPPool(&pool); err != nil {
		klog.Errorf("Failed to add ippool %v cidrs, err: %v", pool, err)
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

func (r *Reconciler) getSubnetByIPPool(n types.NamespacedName) string {
	for k, v := range r.subnets {
		if v.Has(n) {
			return k
		}
	}
	return ""
}

func (r *Reconciler) getGwByIPPool(n types.NamespacedName) string {
	for k, v := range r.gws {
		if v.Has(n) {
			return k
		}
	}
	return ""
}

func (r *Reconciler) deleteCache(n types.NamespacedName, subnet string, gw string) {
	if subnet != "" {
		r.subnets[subnet].Delete(n)
		if r.subnets[subnet].Len() == 0 {
			delete(r.subnets, subnet)
		}
	}

	if gw != "" {
		r.gws[gw].Delete(n)
		if r.gws[gw].Len() == 0 {
			delete(r.gws, gw)
		}
	}
}

func (r *Reconciler) deleteIPPool(n types.NamespacedName) error {
	r.lock.Lock()
	defer r.lock.Unlock()
	var errs []error

	subnet := r.getSubnetByIPPool(n)
	if subnet != "" {
		r.IptCtrl.DelPodCIDRs(subnet)
		if err := r.IptCtrl.DelRuleByCIDR(subnet); err != nil {
			klog.Errorf("Failed to del iptables rule for ippool %v subnet %s: %v", n, subnet, err)
			errs = append(errs, err)
		}

		r.RouteCtrl.DelPodCIDRs(subnet)
		if err := r.RouteCtrl.DelRouteByDst(subnet); err != nil {
			klog.Errorf("Failed to del route for ippool %v subnet %s: %v", n, subnet, err)
			errs = append(errs, err)
		}

		// todo ovsflow for arp and ip
	}

	gw := r.getGwByIPPool(n)
	// todo ovsflow for icmp reply

	if len(errs) > 0 {
		return uerr.NewAggregate(errs)
	}
	r.deleteCache(n, subnet, gw)
	return nil
}

func (r *Reconciler) addIPPool(ippool *ipamv1alpha1.IPPool) error {
	r.lock.Lock()
	defer r.lock.Unlock()
	var errs []error

	n := types.NamespacedName{
		Namespace: ippool.GetNamespace(),
		Name:      ippool.GetName(),
	}
	_, cidr, err := net.ParseCIDR(ippool.Spec.Subnet)
	if err != nil {
		klog.Errorf("Failed to parse ippool %v subnet %s: %v", n, ippool.Spec.Subnet, err)
		return err
	}
	subnet := cidr.String()
	gw := ippool.Spec.Gateway

	if _, ok := r.subnets[subnet]; !ok {
		r.subnets[subnet] = sets.New[types.NamespacedName](n)
	} else {
		r.subnets[subnet].Insert(n)
	}
	r.IptCtrl.InsertPodCIDRs(subnet)
	if err := r.IptCtrl.AddRuleByCIDR(subnet); err != nil {
		klog.Errorf("Failed to add iptables rule for ippool %v subnet %s: %v", n, subnet, err)
		errs = append(errs, err)
	}
	r.RouteCtrl.InsertPodCIDRs(subnet)
	if err := r.RouteCtrl.AddRouteByDst(subnet); err != nil {
		klog.Errorf("Failed to add route to node for ippool %v subnet %s: %v", n, subnet, err)
		errs = append(errs, err)
	}
	// todo add ovsdp flows

	if _, ok := r.gws[gw]; !ok {
		r.gws[gw] = sets.New[types.NamespacedName](n)
	} else {
		r.gws[gw].Insert(n)
	}
	// todo ovsdp flow

	if len(errs) > 0 {
		return uerr.NewAggregate(errs)
	}
	return nil
}

func getPredicateFunc(builtInIPPoolNs string) predicate.Predicate {
	return predicate.Funcs{
		CreateFunc: func(e event.CreateEvent) bool {
			if e.Object.GetNamespace() == builtInIPPoolNs && e.Object.GetName() == constants.GwIPPoolName {
				return false
			}
			return true
		},
		UpdateFunc: func(event.UpdateEvent) bool {
			return false
		},
		DeleteFunc: func(e event.DeleteEvent) bool {
			if e.Object.GetNamespace() == builtInIPPoolNs && e.Object.GetName() == constants.GwIPPoolName {
				return false
			}
			return true
		},
	}
}
