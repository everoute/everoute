package trafficredirect

import (
	"context"
	"fmt"

	"github.com/everoute/trafficredirect/api/trafficredirect/v1alpha1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"

	"github.com/everoute/everoute/pkg/agent/datapath"
	"github.com/everoute/everoute/pkg/source"
)

type Reconciler struct {
	client.Client
	DpMgr *datapath.DpManager
	cache *ruleCache
}

func (r *Reconciler) SetupWithManager(mgr ctrl.Manager) error {
	if mgr == nil {
		return fmt.Errorf("can't setup with nil manager")
	}
	if r.DpMgr == nil {
		return fmt.Errorf("param DpMgr can't be nil")
	}
	if r.Client == nil {
		r.Client = mgr.GetClient()
	}
	r.cache = newRuleCache()

	c, err := controller.New("tr-rule", mgr, controller.Options{
		Reconciler: r,
	})
	if err != nil {
		return err
	}

	return c.Watch(source.Kind(mgr.GetCache(), &v1alpha1.Rule{}), &handler.EnqueueRequestForObject{})
}

func (r *Reconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := ctrl.LoggerFrom(ctx)
	log.Info("Reconcile start")
	defer log.Info("Reconcile end")

	old := r.cache.get(req.NamespacedName)
	vr := &v1alpha1.Rule{}
	if err := r.Client.Get(ctx, req.NamespacedName, vr); err != nil {
		if errors.IsNotFound(err) {
			if old == nil {
				log.V(4).Info("rule has been deleted, skip process it")
				return ctrl.Result{}, nil
			}
			return ctrl.Result{}, r.delete(ctx, req.NamespacedName, old)
		}
		log.Error(err, "Failed to get rule")
		return ctrl.Result{}, err
	}

	log.Info("success get rule object", "objSpec", vr.Spec)
	newR := toLocalRule(vr)
	if old == nil {
		return ctrl.Result{}, r.add(ctx, req.NamespacedName, newR)
	}
	if !old.DiffFromRuleCR(vr) {
		log.V(4).Info("rule fields of interest doesn't update, skip process it", "ruleCache", old)
		return ctrl.Result{}, nil
	}
	log.Info("begin to update rule", "old", old, "new", newR)
	if err := r.delete(ctx, req.NamespacedName, old); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, r.add(ctx, req.NamespacedName, newR)
}

func (r *Reconciler) delete(ctx context.Context, k types.NamespacedName, old *LocalRule) error {
	if err := r.DpMgr.DelTRRule(ctx, old.toDPTRRuleSpec(), k.String()); err != nil {
		return err
	}
	r.cache.delete(k)
	return nil
}

func (r *Reconciler) add(ctx context.Context, k types.NamespacedName, newR *LocalRule) error {
	if err := r.DpMgr.AddTRRule(ctx, newR.toDPTRRuleSpec(), k.String()); err != nil {
		return err
	}
	r.cache.add(k, newR)
	return nil
}
