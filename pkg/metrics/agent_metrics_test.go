package metrics

import (
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestPolicyRuleEstimateRejectedValueMetric(t *testing.T) {
	metric := NewAgentMetric()

	metric.SetPolicyRuleEstimateRejectedValue("policy", "tower-space", "policy-a", "add", "rule_estimate_exceeded", 20020)
	metric.SetPolicyRuleEstimateRejectedValue("group_members", "tower-space", "group-a", "update", "rule_estimate_exceeded", 20021)

	expected := `
# HELP everoute_ms_policy_rule_estimate_rejected_value The estimated rule count for policy objects rejected by rule estimate admission
# TYPE everoute_ms_policy_rule_estimate_rejected_value gauge
everoute_ms_policy_rule_estimate_rejected_value{name="group-a",namespace="tower-space",operation="update",reason="rule_estimate_exceeded",resource="group_members"} 20021
everoute_ms_policy_rule_estimate_rejected_value{name="policy-a",namespace="tower-space",operation="add",reason="rule_estimate_exceeded",resource="policy"} 20020
`
	if err := testutil.CollectAndCompare(&metric.policyRuleEstimateRejectedValue, strings.NewReader(expected)); err != nil {
		t.Fatalf("unexpected rejected value metric: %s", err)
	}

	metric.DeletePolicyRuleEstimateRejectedValue("policy", "tower-space", "policy-a", "add", "rule_estimate_exceeded")
	metric.DeletePolicyRuleEstimateRejectedValue("group_members", "tower-space", "group-a", "update", "rule_estimate_exceeded")
	if count := testutil.CollectAndCount(&metric.policyRuleEstimateRejectedValue); count != 0 {
		t.Fatalf("expected rejected value metric to be deleted, got %d metrics", count)
	}
}
