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
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"

	"github.com/everoute/everoute/pkg/common/initsync"
)

type Reconciler struct {
	Request    types.NamespacedName
	Queue      chan event.GenericEvent
	NewObject  func(types.NamespacedName) client.Object
	Completion *Completion
	Name       string
	Resource   string
}

type Completion struct {
	tracker *initsync.Tracker

	ListExpected        func(context.Context) (sets.Set[string], error)
	MarkDone            func()
	RequeueOnCheckError bool
}

func (r *Reconciler) Reconcile(
	ctx context.Context,
	req ctrl.Request,
	reconcile func(context.Context, ctrl.Request) (ctrl.Result, error),
) (ctrl.Result, error) {
	if r == nil {
		// Startup sync is disabled for this controller.
		return reconcile(ctx, req)
	}
	syncCtx := r.withLogValues(ctx)
	if r.Completion == nil || r.Completion.IsDone() {
		if req.NamespacedName == r.Request {
			return ctrl.Result{}, nil
		}
		return reconcile(ctx, req)
	}

	if req.NamespacedName == r.Request {
		ctrl.LoggerFrom(syncCtx).Info("Received startup sync request, checking startup completion")
		r.Completion.CheckDone(syncCtx, r.Enqueue)
		return ctrl.Result{}, nil
	}

	res, err := reconcile(ctx, req)
	if err == nil && !res.Requeue && res.RequeueAfter == 0 {
		r.Completion.MarkProcessed(syncCtx, req.NamespacedName, r.Enqueue)
	}
	return res, err
}

func (r *Reconciler) Enqueue(ctx context.Context) {
	if r == nil || r.Queue == nil || r.NewObject == nil {
		return
	}
	ctx = r.withLogValues(ctx)

	select {
	case r.Queue <- event.GenericEvent{Object: r.NewObject(r.Request)}:
		ctrl.LoggerFrom(ctx).Info("Enqueued startup sync request")
	case <-ctx.Done():
	default:
	}
}

func (r *Reconciler) withLogValues(ctx context.Context) context.Context {
	log := ctrl.LoggerFrom(ctx)
	if r.Name != "" {
		log = log.WithValues("startupSync", r.Name)
	}
	if r.Resource != "" {
		log = log.WithValues("resource", r.Resource)
	}
	return ctrl.LoggerInto(ctx, log)
}

func (c *Completion) CheckDone(ctx context.Context, enqueue func(context.Context)) {
	if c == nil || c.ListExpected == nil {
		return
	}
	expected, err := c.ListExpected(ctx)
	if err != nil {
		ctrl.LoggerFrom(ctx).Error(err, "Failed to list startup resources")
		if c.RequeueOnCheckError && enqueue != nil {
			enqueue(contextWithLogger(context.Background(), ctx))
		}
		return
	}

	_, justDone, processed := c.initTracker().CheckDone(expected)
	if justDone {
		ctrl.LoggerFrom(ctx).Info("Startup flow sync completed", "processed", processed)
		if c.MarkDone != nil {
			c.MarkDone()
		}
	}
}

func (c *Completion) MarkProcessed(ctx context.Context, key types.NamespacedName, enqueue func(context.Context)) {
	if c == nil || c.IsDone() {
		return
	}

	isNew, processed, recorded := c.initTracker().MarkProcessed(key.String())
	if !recorded {
		return
	}
	ctrl.LoggerFrom(ctx).Info("Startup resource processed", "key", key, "isNew", isNew, "allProcessed", processed)
	c.CheckDone(ctx, enqueue)
}

func (c *Completion) IsDone() bool {
	return c != nil && c.initTracker().IsDone()
}

func contextWithLogger(ctx, from context.Context) context.Context {
	return ctrl.LoggerInto(ctx, ctrl.LoggerFrom(from))
}

func (c *Completion) initTracker() *initsync.Tracker {
	if c.tracker == nil {
		c.tracker = initsync.NewTracker()
	}
	return c.tracker
}
