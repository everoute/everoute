package metrics

import (
	"context"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestControllerActiveMetric(t *testing.T) {
	metric := NewControllerActiveMetric()

	metric.SetActive(true)
	expectedActive := `
# HELP everoute_ms_controller_active Whether this controller instance is active
# TYPE everoute_ms_controller_active gauge
everoute_ms_controller_active 1
`
	if err := testutil.CollectAndCompare(metric.data, strings.NewReader(expectedActive)); err != nil {
		t.Fatalf("unexpected active metric: %s", err)
	}

	metric.SetActive(false)
	expectedInactive := `
# HELP everoute_ms_controller_active Whether this controller instance is active
# TYPE everoute_ms_controller_active gauge
everoute_ms_controller_active 0
`
	if err := testutil.CollectAndCompare(metric.data, strings.NewReader(expectedInactive)); err != nil {
		t.Fatalf("unexpected inactive metric: %s", err)
	}
}

func TestControllerActiveMetricStart(t *testing.T) {
	metric := NewControllerActiveMetric()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})

	go func() {
		defer close(done)
		_ = metric.Start(ctx)
	}()
	cancel()
	<-done

	expected := `
# HELP everoute_ms_controller_active Whether this controller instance is active
# TYPE everoute_ms_controller_active gauge
everoute_ms_controller_active 0
`
	if err := testutil.CollectAndCompare(metric.data, strings.NewReader(expected)); err != nil {
		t.Fatalf("unexpected stopped active metric: %s", err)
	}
	if !metric.NeedLeaderElection() {
		t.Fatalf("expected controller active metric to need leader election")
	}
}
