package policy

import (
	"context"
	"fmt"
	"testing"

	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/event"

	ertypes "github.com/everoute/everoute/pkg/types"
)

func TestIsGroupMembersNotFoundErr(t *testing.T) {
	cases := []struct {
		name string
		err  error
		exp  bool
	}{
		{
			name: "groupmembers err",
			err:  NewGroupMembersNotFoundErr("test"),
			exp:  true,
		},
		{
			name: "other rsInCacheNotFoundErr",
			err:  ertypes.NewRscInCacheNotFoundErr("test", types.NamespacedName{Namespace: "ns", Name: "name"}),
			exp:  false,
		},
		{
			name: "other err",
			err:  fmt.Errorf("test groupmembers err"),
			exp:  false,
		},
	}

	for _, c := range cases {
		res := IsGroupMembersNotFoundErr(c.err)
		if res != c.exp {
			t.Errorf("test %s failed, exp is %v, real is %v", c.name, c.exp, res)
		}
	}
}

func TestSkipGlobalPolicyWaitNormal(t *testing.T) {
	r := &Reconciler{
		StartupGlobalPolicyQueue: make(chan event.GenericEvent, 1),
	}

	if r.GetReadyToProcessGlobalRule() {
		t.Fatalf("expected global policy ready flag to default to false")
	}

	changed := r.SkipGlobalPolicyWaitNormal(context.Background())
	if !changed {
		t.Fatalf("expected first skip request to change runtime state")
	}
	if !r.GetReadyToProcessGlobalRule() {
		t.Fatalf("expected global policy ready flag to be true after skip request")
	}

	select {
	case <-r.StartupGlobalPolicyQueue:
	default:
		t.Fatalf("expected global policy reconcile request to be enqueued")
	}

	changed = r.SkipGlobalPolicyWaitNormal(context.Background())
	if changed {
		t.Fatalf("expected repeated skip request to keep runtime state unchanged")
	}
}
