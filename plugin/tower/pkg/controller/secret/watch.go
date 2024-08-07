package secret

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	msconst "github.com/everoute/everoute/pkg/constants/ms"
	ersource "github.com/everoute/everoute/pkg/source"
)

type Watch struct {
	Queue               chan event.GenericEvent
	K8sMPKubeconfigName string
	K8sMPKubeconfigNs   string
}

func (w *Watch) Reconcile(ctx context.Context, _ ctrl.Request) (ctrl.Result, error) {
	log := ctrl.LoggerFrom(ctx)
	log.Info("Reconcile start")

	obj := ersource.Event{}
	obj.Name = msconst.K8sMPKubeconfigNameInCloudPlatform
	obj.Namespace = msconst.K8sMPKubeconfigNsInCloudPlatform
	w.Queue <- event.GenericEvent{Object: &obj}
	log.Info("Reconcile end", "addToChannel", obj)
	return ctrl.Result{}, nil
}

func (w *Watch) SetupWithManager(mgr ctrl.Manager, platForm string) error {
	ctrlName := platForm + "-secret-watch"
	if mgr == nil {
		klog.Errorf("Can't setup with nil manager for %s controller", ctrlName)
		return fmt.Errorf("can't setup with nil manager")
	}

	if w.Queue == nil {
		klog.Errorf("Can't setup with nil Queue for %s controller", ctrlName)
		return fmt.Errorf("can't setup with nil Queue")
	}
	c, err := controller.New(ctrlName, mgr, controller.Options{
		Reconciler: w,
	})
	if err != nil {
		klog.Errorf("Failed to new %s controller: %s", ctrlName, err)
		return err
	}
	err = c.Watch(ersource.Kind(mgr.GetCache(), &corev1.Secret{}), &handler.EnqueueRequestForObject{}, predicate.Funcs{
		CreateFunc: func(ce event.CreateEvent) bool {
			return w.isK8sMPKubeconfig(ce.Object)
		},
		UpdateFunc: func(ue event.UpdateEvent) bool {
			return w.isK8sMPKubeconfig(ue.ObjectNew)
		},
		DeleteFunc: func(de event.DeleteEvent) bool {
			return w.isK8sMPKubeconfig(de.Object)
		},
	})
	if err != nil {
		klog.Errorf("Controller %s failed to watch secret: %s", ctrlName, err)
		return err
	}
	return nil
}

func (w *Watch) isK8sMPKubeconfig(obj client.Object) bool {
	return obj.GetName() == w.K8sMPKubeconfigName && obj.GetNamespace() == w.K8sMPKubeconfigNs
}
