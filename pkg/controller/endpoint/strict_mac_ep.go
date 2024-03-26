package endpoint

import (
	"context"
	"fmt"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/klog"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/source"

	securityv1alpha1 "github.com/everoute/everoute/pkg/apis/security/v1alpha1"
	"github.com/everoute/everoute/pkg/constants"
	"github.com/everoute/everoute/pkg/utils"
)

type StrictMacController struct {
	client.Client

	logPre string
}

func (s *StrictMacController) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	klog.Infof("%s receive endpoint %s", s.logPre, req.NamespacedName)
	ep := securityv1alpha1.Endpoint{}
	if err := s.Client.Get(ctx, req.NamespacedName, &ep); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		klog.Errorf("%s failed to get endpoint %s", s.logPre, req.NamespacedName)
		return ctrl.Result{}, err
	}

	if ep.Spec.StrictMac {
		return ctrl.Result{}, nil
	}

	if s.isStrictMacLabel(ep.Labels) {
		ep.Spec.StrictMac = true
		if err := s.Client.Update(ctx, &ep); err != nil {
			klog.Errorf("%s failed to update endpoint %s StrictMac to true, err: %s", s.logPre, req.NamespacedName, err)
			return ctrl.Result{}, err
		}
		klog.Infof("%s success to update endpoint %s StrictMac to true", s.logPre, req.NamespacedName)
	}

	return ctrl.Result{}, nil
}

func (s *StrictMacController) SetupWithManager(mgr ctrl.Manager) error {
	if mgr == nil {
		return fmt.Errorf("can't setup with nil mgr")
	}
	s.logPre = "strict mac endpoint controller,"

	c, err := controller.New("strict mac controller", mgr, controller.Options{
		Reconciler: s,
	})
	if err != nil {
		return err
	}

	return c.Watch(source.Kind(mgr.GetCache(), &securityv1alpha1.Endpoint{}), &handler.EnqueueRequestForObject{}, predicate.Funcs{
		CreateFunc: s.predicateCreate,
		UpdateFunc: s.predicateUpdate,
		DeleteFunc: func(event.DeleteEvent) bool { return false },
	})
}

func (s *StrictMacController) isStrictMacLabel(labels map[string]string) bool {
	for k, v := range labels {
		if k == constants.SksManagedLabelKey && v == constants.SksManagedLabelValue {
			return true
		}
	}
	return false
}

func (s *StrictMacController) predicateCreate(e event.CreateEvent) bool {
	obj, ok := e.Object.(*securityv1alpha1.Endpoint)
	if !ok {
		klog.Error("Failed to transform object to endpoint")
		return false
	}

	if obj.Spec.StrictMac {
		return false
	}

	if obj.Spec.Type != securityv1alpha1.EndpointDynamic {
		return false
	}

	if s.isStrictMacLabel(obj.Labels) {
		return true
	}

	return false
}

func (s *StrictMacController) predicateUpdate(e event.UpdateEvent) bool {
	newObj, newOk := e.ObjectNew.(*securityv1alpha1.Endpoint)
	oldObj, oldOk := e.ObjectOld.(*securityv1alpha1.Endpoint)
	if !newOk || !oldOk {
		klog.Error("Failed to transform object to endpoint")
		return false
	}

	if newObj.Spec.StrictMac {
		return false
	}

	if newObj.Spec.Type != securityv1alpha1.EndpointDynamic {
		return false
	}

	if !s.isStrictMacLabel(newObj.Labels) {
		return false
	}

	if !utils.IsK8sLabelDiff(newObj.Labels, oldObj.Labels) {
		return false
	}

	return true
}
