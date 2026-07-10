package k8s

import (
	"context"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	k8stypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	"github.com/everoute/everoute/pkg/apis/security/v1alpha1"
	cniconst "github.com/everoute/everoute/pkg/constants/cni"
	"github.com/everoute/everoute/pkg/source"
	"github.com/everoute/everoute/pkg/utils"
)

type NodeReconciler struct {
	client.Client
	Scheme *runtime.Scheme

	GwEpNamespace string
}

func (r *NodeReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	klog.Infof("Received node %v reconcile", req.NamespacedName)

	node := &corev1.Node{}
	err := r.Get(ctx, req.NamespacedName, node)
	if err == nil {
		return ctrl.Result{}, nil
	}

	if !errors.IsNotFound(err) {
		klog.Errorf("Can't get node %v info", node)
		return ctrl.Result{}, err
	}

	klog.Infof("Node %v has been deleted", req.NamespacedName)
	epReq := k8stypes.NamespacedName{
		Namespace: r.GwEpNamespace,
		Name:      utils.GetGwEndpointName(req.Name),
	}
	ep := v1alpha1.Endpoint{}
	if err := r.Client.Get(ctx, epReq, &ep); err != nil {
		if errors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		klog.Errorf("Failed to get gw-ep endpoint for node %s", req.Name)
		return ctrl.Result{}, err
	}
	if err := r.Delete(ctx, &ep); err != nil {
		klog.Errorf("Failed to delete gw-ep endpoint for node %s", req.Name)
		return ctrl.Result{}, err
	}
	klog.Infof("Deleted gw-ep endpoint %s/%s for node %s", ep.GetNamespace(), ep.GetName(), req.Name)

	return ctrl.Result{}, nil
}

func (r *NodeReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if mgr == nil {
		return fmt.Errorf("can't setup with nil manager")
	}

	c, err := controller.New("node-controller", mgr, controller.Options{Reconciler: r})
	if err != nil {
		return err
	}

	if err := c.Watch(source.Kind(mgr.GetCache(), &corev1.Node{}), &handler.EnqueueRequestForObject{}, nodePredicate()); err != nil {
		return err
	}
	return c.Watch(
		source.Kind(mgr.GetCache(), &v1alpha1.Endpoint{}),
		handler.EnqueueRequestsFromMapFunc(r.enqueueNodeByGwEndpoint),
		gwEndpointPredicate(r.GwEpNamespace),
	)
}

func nodePredicate() predicate.Predicate {
	return predicate.Funcs{
		CreateFunc: func(event.CreateEvent) bool {
			return false
		},
		UpdateFunc: func(event.UpdateEvent) bool {
			return false
		},
		DeleteFunc: func(event.DeleteEvent) bool {
			return true
		},
		GenericFunc: func(event.GenericEvent) bool {
			return false
		},
	}
}

func (r *NodeReconciler) enqueueNodeByGwEndpoint(_ context.Context, obj client.Object) []ctrl.Request {
	if obj == nil {
		return nil
	}
	nodeName, isGwEp := getGwEndpointNodeName(obj.GetName())
	if !isGwEp {
		return nil
	}
	return []ctrl.Request{{NamespacedName: k8stypes.NamespacedName{Name: nodeName}}}
}

func gwEndpointPredicate(namespace string) predicate.Predicate {
	return predicate.Funcs{
		CreateFunc: func(e event.CreateEvent) bool {
			return isGwEndpointObject(e.Object, namespace)
		},
		UpdateFunc: func(e event.UpdateEvent) bool {
			return isGwEndpointObject(e.ObjectNew, namespace)
		},
		DeleteFunc: func(event.DeleteEvent) bool {
			return false
		},
		GenericFunc: func(event.GenericEvent) bool {
			return false
		},
	}
}

func isGwEndpointObject(obj client.Object, namespace string) bool {
	if obj == nil {
		return false
	}
	if obj.GetNamespace() != namespace {
		return false
	}
	_, isGwEp := getGwEndpointNodeName(obj.GetName())
	return isGwEp
}

func getGwEndpointNodeName(epName string) (string, bool) {
	prefix := cniconst.GwEpNamePrefix + "-"
	if !strings.HasPrefix(epName, prefix) {
		return "", false
	}
	nodeName := strings.TrimPrefix(epName, prefix)
	if nodeName == "" {
		return "", false
	}
	return nodeName, true
}
