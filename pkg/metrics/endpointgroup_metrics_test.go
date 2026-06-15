package metrics

import (
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestEndpointGroupInfoMetricSetDeletesOldLabelState(t *testing.T) {
	metric := NewEndpointGroupInfoMetric()

	metric.Set("group-a", EndpointGroupTargetTypePod, "old")
	metric.Set("group-a", EndpointGroupTargetTypeVMLabel, "new")

	if len(metric.last) != 1 {
		t.Fatalf("expected one cached label set, got %d", len(metric.last))
	}
	got := metric.last["group-a"]
	if got.targetType != EndpointGroupTargetTypeVMLabel || got.targetDisplay != "new" {
		t.Fatalf("unexpected cached labels: %+v", got)
	}

	metric.Delete("group-a")
	if len(metric.last) != 0 {
		t.Fatalf("expected cached labels to be deleted, got %d", len(metric.last))
	}
}

func TestEndpointGroupSecurityGroupMetricSetReplacesSecurityGroupMappings(t *testing.T) {
	metric := NewEndpointGroupSecurityGroupMetric()

	metric.SetSecurityGroup("sg-a", []string{"group-a", "group-b", "group-a"})
	if got := len(metric.last["sg-a"]); got != 2 {
		t.Fatalf("expected duplicate endpointgroups to be deduplicated, got %d", got)
	}

	metric.SetSecurityGroup("sg-a", []string{"group-c"})
	if got := len(metric.last["sg-a"]); got != 1 {
		t.Fatalf("expected one endpointgroup after replace, got %d", got)
	}
	if _, ok := metric.last["sg-a"]["group-c"]; !ok {
		t.Fatalf("expected group-c mapping after replace")
	}

	expected := `
# HELP everoute_ms_securitygroup_info The Tower SecurityGroup to EndpointGroup mapping for policy guard alerts
# TYPE everoute_ms_securitygroup_info gauge
everoute_ms_securitygroup_info{name="group-c",securitygroup_id="sg-a",securitygroup_type="pod"} 1
`
	if err := testutil.CollectAndCompare(metric.data, strings.NewReader(expected)); err != nil {
		t.Fatalf("unexpected securitygroup info metric: %s", err)
	}

	metric.DeleteSecurityGroup("sg-a")
	if _, ok := metric.last["sg-a"]; ok {
		t.Fatalf("expected securitygroup mapping to be deleted")
	}
}
