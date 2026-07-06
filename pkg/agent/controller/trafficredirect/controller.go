package trafficredirect

import (
	"context"
	"fmt"

	"github.com/everoute/trafficredirect/api/trafficredirect/v1alpha1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	crsource "sigs.k8s.io/controller-runtime/pkg/source"

	"github.com/everoute/everoute/pkg/agent/datapath"
	"github.com/everoute/everoute/pkg/common/startupsync"
	"github.com/everoute/everoute/pkg/source"
)

type Reconciler struct {
	client.Client
	DpMgr           *datapath.DpManager
	StartupFlowSync *datapath.StartupFlowSync
	StartupQueue    chan event.GenericEvent
	cache           *ruleCache

	startupSync *startupsync.Reconciler
}

var startupTRSyncRequest = types.NamespacedName{Name: "__everoute_startup_trafficredirect_sync__"}

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

	if r.StartupFlowSync != nil {
		if r.StartupQueue == nil {
			r.StartupQueue = make(chan event.GenericEvent, 1)
		}
		r.initStartupReconciler()
	}
	c, err := controller.New("tr-rule", mgr, controller.Options{
		Reconciler: r,
	})
	if err != nil {
		return err
	}

	if err = c.Watch(source.Kind(mgr.GetCache(), &v1alpha1.Rule{}), &handler.EnqueueRequestForObject{}); err != nil {
		return err
	}
	if r.StartupFlowSync != nil {
		if err = c.Watch(&crsource.Channel{Source: r.StartupQueue}, &handler.EnqueueRequestForObject{}); err != nil {
			return err
		}
	}
	return nil
}

func (r *Reconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	if r.startupSync != nil {
		return r.startupSync.Reconcile(ctx, req, r.reconcile)
	}
	return r.reconcile(ctx, req)
}

func (r *Reconciler) reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
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
	var err error
	if old == nil {
		err = r.add(ctx, req.NamespacedName, newR)
	} else if !old.DiffFromRuleCR(vr) {
		log.V(4).Info("rule fields of interest doesn't update, skip process it", "ruleCache", old)
	} else {
		log.Info("begin to update rule", "old", old, "new", newR)
		if err = r.delete(ctx, req.NamespacedName, old); err == nil {
			err = r.add(ctx, req.NamespacedName, newR)
		}
	}
	return ctrl.Result{}, err
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

func (r *Reconciler) EnqueueStartupFlowSync(ctx context.Context) {
	r.startupSync.Enqueue(ctx)
}

func (r *Reconciler) initStartupReconciler() {
	r.startupSync = &startupsync.Reconciler{
		Request:  startupTRSyncRequest,
		Queue:    r.StartupQueue,
		Name:     "trafficRedirect",
		Resource: "rule",
		NewObject: func(key types.NamespacedName) client.Object {
			return &v1alpha1.Rule{
				ObjectMeta: metav1.ObjectMeta{Namespace: key.Namespace, Name: key.Name},
			}
		},
		Completion: &startupsync.Completion{
			ListExpected:        r.listStartupRuleKeys,
			MarkDone:            r.StartupFlowSync.MarkTrafficRedirectDone,
			RequeueOnCheckError: true,
		},
	}
}

func (r *Reconciler) listStartupRuleKeys(ctx context.Context) (sets.Set[string], error) {
	ruleList := v1alpha1.RuleList{}
	if err := r.List(ctx, &ruleList); err != nil {
		return nil, err
	}
	expected := sets.New[string]()
	for i := range ruleList.Items {
		key := client.ObjectKeyFromObject(&ruleList.Items[i])
		expected.Insert(key.String())
	}
	return expected, nil
}
