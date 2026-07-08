/*
Copyright 2026 The Everoute Authors.

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

package startupsync

import (
	"context"

	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/event"

	"github.com/everoute/everoute/pkg/common/initsync"
	"github.com/everoute/everoute/pkg/source"
)

type Reconciler struct {
	Queue chan event.GenericEvent
	// ListExpected should return resources that can enter reconcile. If a
	// controller uses predicates to filter out part of the watched resources,
	// this function must apply the same filter to avoid waiting for resources
	// that will never be marked processed.
	ListExpected func(context.Context) (sets.Set[string], error)
	MarkDone     func()

	tracker *initsync.Tracker
}

var request = types.NamespacedName{Name: "__everoute_startup_sync__"}

func (r *Reconciler) Reconcile(
	ctx context.Context,
	req ctrl.Request,
	reconcile func(context.Context, ctrl.Request) (ctrl.Result, error),
) (ctrl.Result, error) {
	if r == nil {
		// Startup sync is disabled for this controller.
		return reconcile(ctx, req)
	}
	if r.IsDone() {
		if req.NamespacedName == request {
			return ctrl.Result{}, nil
		}
		return reconcile(ctx, req)
	}

	if req.NamespacedName == request {
		ctrl.LoggerFrom(ctx).Info("Received startup sync request, checking startup completion")
		r.checkDone(ctx)
		return ctrl.Result{}, nil
	}

	res, err := reconcile(ctx, req)
	if err == nil && !res.Requeue && res.RequeueAfter == 0 {
		r.markProcessed(ctx, req.NamespacedName)
	}
	return res, err
}

func (r *Reconciler) Enqueue(ctx context.Context) {
	if r == nil || r.Queue == nil {
		return
	}

	select {
	case r.Queue <- source.NewResourceEvent(request.Name, request.Namespace):
		ctrl.LoggerFrom(ctx).Info("Enqueued startup sync request")
	case <-ctx.Done():
	default:
	}
}

func (r *Reconciler) checkDone(ctx context.Context) {
	if r == nil || r.ListExpected == nil {
		return
	}
	expected, err := r.ListExpected(ctx)
	if err != nil {
		ctrl.LoggerFrom(ctx).Error(err, "Failed to list startup resources")
		r.Enqueue(contextWithLogger(context.Background(), ctx))
		return
	}

	_, justDone, processed := r.initTracker().CheckDone(expected)
	if justDone {
		ctrl.LoggerFrom(ctx).Info("Startup flow sync completed", "processedCount", len(processed))
		if r.MarkDone != nil {
			r.MarkDone()
		}
	}
}

func (r *Reconciler) markProcessed(ctx context.Context, key types.NamespacedName) {
	if r == nil || r.IsDone() {
		return
	}

	isNew, processed, recorded := r.initTracker().MarkProcessed(key.String())
	if !recorded {
		return
	}
	ctrl.LoggerFrom(ctx).Info("Startup resource processed", "key", key, "isNew", isNew, "processedCount", len(processed))
	r.checkDone(ctx)
}

func (r *Reconciler) IsDone() bool {
	return r != nil && r.initTracker().IsDone()
}

func contextWithLogger(ctx, from context.Context) context.Context {
	return ctrl.LoggerInto(ctx, ctrl.LoggerFrom(from))
}

func (r *Reconciler) initTracker() *initsync.Tracker {
	if r.tracker == nil {
		r.tracker = initsync.NewTracker()
	}
	return r.tracker
}
