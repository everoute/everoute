package startupsync

import (
	"context"
	"errors"
	"testing"

	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/event"
)

func TestReconcileStartupRequestChecksDone(t *testing.T) {
	markDoneCount := 0
	reconciler := &Reconciler{
		ListExpected: func(context.Context) (sets.Set[string], error) {
			return sets.New[string](), nil
		},
		MarkDone: func() {
			markDoneCount++
		},
	}

	res, err := reconciler.Reconcile(context.Background(), ctrl.Request{NamespacedName: request}, func(context.Context, ctrl.Request) (ctrl.Result, error) {
		t.Fatalf("business reconcile should not be called for startup request")
		return ctrl.Result{}, nil
	})
	if err != nil || res != (ctrl.Result{}) {
		t.Fatalf("unexpected reconcile result, res=%+v err=%v", res, err)
	}
	if markDoneCount != 1 {
		t.Fatalf("expected MarkDone called once, got %d", markDoneCount)
	}
	if !reconciler.IsDone() {
		t.Fatalf("reconciler should be done after empty expected startup check")
	}
}

func TestReconcileMarksProcessedAfterSuccessfulBusinessReconcile(t *testing.T) {
	key := types.NamespacedName{Namespace: "ns", Name: "rule-a"}
	markDoneCount := 0
	reconciler := &Reconciler{
		ListExpected: func(context.Context) (sets.Set[string], error) {
			return sets.New[string](key.String()), nil
		},
		MarkDone: func() {
			markDoneCount++
		},
	}

	res, err := reconciler.Reconcile(context.Background(), ctrl.Request{NamespacedName: key}, func(context.Context, ctrl.Request) (ctrl.Result, error) {
		return ctrl.Result{}, nil
	})
	if err != nil || res != (ctrl.Result{}) {
		t.Fatalf("unexpected reconcile result, res=%+v err=%v", res, err)
	}
	if markDoneCount != 1 {
		t.Fatalf("expected MarkDone called once, got %d", markDoneCount)
	}
	if !reconciler.IsDone() {
		t.Fatalf("reconciler should be done after expected key processed")
	}
}

func TestReconcileDoesNotMarkProcessedWhenBusinessReconcileRequeues(t *testing.T) {
	key := types.NamespacedName{Namespace: "ns", Name: "rule-a"}
	reconciler := &Reconciler{
		ListExpected: func(context.Context) (sets.Set[string], error) {
			return sets.New[string](key.String()), nil
		},
		MarkDone: func() {
			t.Fatalf("MarkDone should not be called when business reconcile requeues")
		},
	}

	res, err := reconciler.Reconcile(context.Background(), ctrl.Request{NamespacedName: key}, func(context.Context, ctrl.Request) (ctrl.Result, error) {
		return ctrl.Result{Requeue: true}, nil
	})
	if err != nil || !res.Requeue {
		t.Fatalf("unexpected reconcile result, res=%+v err=%v", res, err)
	}
	if reconciler.IsDone() {
		t.Fatalf("reconciler should not be done after requeued business reconcile")
	}
}

func TestCheckDoneListErrorRequeuesStartupRequest(t *testing.T) {
	queue := make(chan event.GenericEvent, 1)
	reconciler := &Reconciler{
		Queue: queue,
		ListExpected: func(context.Context) (sets.Set[string], error) {
			return nil, errors.New("list failed")
		},
	}

	_, err := reconciler.Reconcile(context.Background(), ctrl.Request{NamespacedName: request}, func(context.Context, ctrl.Request) (ctrl.Result, error) {
		t.Fatalf("business reconcile should not be called for startup request")
		return ctrl.Result{}, nil
	})
	if err != nil {
		t.Fatalf("unexpected reconcile error: %v", err)
	}

	select {
	case event := <-queue:
		if event.Object.GetName() != request.Name || event.Object.GetNamespace() != request.Namespace {
			t.Fatalf("unexpected startup event object %s/%s", event.Object.GetNamespace(), event.Object.GetName())
		}
	default:
		t.Fatalf("expected startup request requeued after list error")
	}
}
