package ipam

import (
	"context"
	"fmt"
	"sync"

	ipamv1alpha1 "github.com/everoute/ipam/api/ipam/v1alpha1"
	"github.com/everoute/ipam/pkg/ipam"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/source"

	"github.com/everoute/everoute/pkg/apis/security/v1alpha1"
	"github.com/everoute/everoute/pkg/constants"
)

func NewEpPredicate(nodeMap *sync.Map) predicate.Predicate {
	return predicate.Funcs{
		CreateFunc: func(e event.CreateEvent) bool {
			o, ok := e.Object.(*v1alpha1.Endpoint)
			if !ok {
				klog.Errorf("Failed to transfer deleted endpoint: %s/%s", e.Object.GetNamespace(), e.Object.GetName())
				return false
			}
			if o.Spec.Reference.ExternalIDName == constants.GwEpExternalIDName {
				nodeMap.Store(types.NamespacedName{Namespace: o.GetNamespace(), Name: o.GetName()}, o.Spec.Reference.ExternalIDValue)
			}
			return false
		},
		UpdateFunc: func(event.UpdateEvent) bool {
			return false
		},
		DeleteFunc: func(e event.DeleteEvent) bool {
			k := types.NamespacedName{
				Namespace: e.Object.GetNamespace(),
				Name:      e.Object.GetName(),
			}
			_, ok := nodeMap.Load(k)
			return ok
		},
	}
}

type Reconciler struct {
	client.Client
	GWIPPoolNs   string
	GWIPPoolName string

	nodeMap *sync.Map
}

func (r *Reconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	klog.Infof("Receive endpoint reconcile %v for ipam", req.NamespacedName)
	ep := v1alpha1.Endpoint{}
	err := r.Client.Get(ctx, req.NamespacedName, &ep)
	if err == nil {
		klog.Infof("Endpoint %v is exists, return", req.NamespacedName)
		return ctrl.Result{}, nil
	}
	if !errors.IsNotFound(err) {
		klog.Errorf("Failed to get endpoint %v: %v", req.NamespacedName, err)
		return ctrl.Result{}, err
	}

	node, exists := r.nodeMap.LoadAndDelete(req.NamespacedName)
	if !exists {
		klog.Errorf("Can't find gw endpoint %v node, can't release it's ip", req.NamespacedName)
		return ctrl.Result{}, nil
	}
	nodeName := node.(string)
	// release gateway ip
	netConf := ipam.NetConf{
		Type:             ipamv1alpha1.AllocateTypeCNIUsed,
		AllocateIdentify: nodeName,
		Pool:             r.GWIPPoolName,
	}
	if err := ipam.InitIpam(r.Client, r.GWIPPoolNs).ExecDel(ctx, &netConf); err != nil {
		klog.Errorf("Failed to release gateway ip for node %s, err: %v", nodeName, err)
		return ctrl.Result{}, err
	}
	klog.Infof("Success release gateway ip for node %s", nodeName)
	return ctrl.Result{}, nil
}

func (r *Reconciler) SetupWithManager(mgr ctrl.Manager) error {
	if r.GWIPPoolNs == "" || r.GWIPPoolName == "" {
		return fmt.Errorf("can't setup ipam endpoint reconciler without gateway ippool namespace and name")
	}
	r.nodeMap = &sync.Map{}

	c, err := controller.New("endpoint-controller", mgr, controller.Options{
		Reconciler: r,
	})
	if err != nil {
		return err
	}

	return c.Watch(source.Kind(mgr.GetCache(), &v1alpha1.Endpoint{}), &handler.EnqueueRequestForObject{}, NewEpPredicate(r.nodeMap))
}
