package policy

import (
	"context"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	securityv1alpha1 "github.com/everoute/everoute/pkg/apis/security/v1alpha1"
	msconst "github.com/everoute/everoute/pkg/constants/ms"
)

type Metric interface {
	Set(namespace, name, displayName string)
	Delete(namespace, name string)
}

func (r *Reconciler) ReconcilePolicyMetric(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	if r == nil || r.PolicyMetric == nil {
		return ctrl.Result{}, nil
	}

	policy := securityv1alpha1.SecurityPolicy{}
	if err := r.Get(ctx, req.NamespacedName, &policy); err != nil {
		if apierrors.IsNotFound(err) {
			r.PolicyMetric.Delete(req.Namespace, req.Name)
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	r.PolicyMetric.Set(policy.Namespace, policy.Name, DisplayName(&policy))
	return ctrl.Result{}, nil
}

func DisplayName(policy *securityv1alpha1.SecurityPolicy) string {
	if policy == nil {
		return ""
	}
	if policy.Spec.Logging != nil {
		if name := policy.Spec.Logging.Tags[msconst.LoggingTagPolicyName]; name != "" {
			return name
		}
	}
	return policy.Name
}

func policyMetricPredicate() predicate.Predicate {
	return predicate.Funcs{
		CreateFunc: func(event.CreateEvent) bool {
			return true
		},
		UpdateFunc: func(e event.UpdateEvent) bool {
			oldPolicy, okOld := e.ObjectOld.(*securityv1alpha1.SecurityPolicy)
			newPolicy, okNew := e.ObjectNew.(*securityv1alpha1.SecurityPolicy)
			if !okOld || !okNew {
				return false
			}
			return DisplayName(oldPolicy) != DisplayName(newPolicy)
		},
		DeleteFunc: func(event.DeleteEvent) bool {
			return true
		},
		GenericFunc: func(event.GenericEvent) bool {
			return false
		},
	}
}
