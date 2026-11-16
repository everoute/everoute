package metrics

import (
	"fmt"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	securityv1alpha1 "github.com/everoute/everoute/pkg/apis/security/v1alpha1"
	constants "github.com/everoute/everoute/pkg/constants/ms"
)

func TestPolicyRuleEstimateRejectedValueMetric(t *testing.T) {
	metric := NewAgentMetric()

	metric.SetPolicyRuleEstimateRejectedValue("policy", "tower-space", "policy-a", "tower-policy-a", "add", "rule_estimate_exceeded", 20020)
	metric.SetPolicyRuleEstimateRejectedValue("group_members", "tower-space", "group-a", "", "update", "rule_estimate_exceeded", 20021)

	expected := `
# HELP everoute_ms_policy_rule_estimate_rejected_value The estimated rule count for policy objects rejected by rule estimate admission
# TYPE everoute_ms_policy_rule_estimate_rejected_value gauge
everoute_ms_policy_rule_estimate_rejected_value{name="group-a",namespace="tower-space",operation="update",reason="rule_estimate_exceeded",resource="group_members",tower_id=""} 20021
everoute_ms_policy_rule_estimate_rejected_value{name="policy-a",namespace="tower-space",operation="add",reason="rule_estimate_exceeded",resource="policy",tower_id="tower-policy-a"} 20020
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

func TestStartupPreviousRoundFlowDeletedMetric(t *testing.T) {
	metric := NewAgentMetric()

	expectedUndeleted := `
# HELP everoute_ms_startup_previous_round_flow_deleted Whether previous round flows have been deleted during startup cleanup
# TYPE everoute_ms_startup_previous_round_flow_deleted gauge
everoute_ms_startup_previous_round_flow_deleted 0
`
	if err := testutil.CollectAndCompare(metric.startupPreviousRoundFlowDeleted, strings.NewReader(expectedUndeleted)); err != nil {
		t.Fatalf("unexpected undeleted startup flow metric: %s", err)
	}

	metric.SetStartupPreviousRoundFlowDeleted(true)

	expectedDeleted := `
# HELP everoute_ms_startup_previous_round_flow_deleted Whether previous round flows have been deleted during startup cleanup
# TYPE everoute_ms_startup_previous_round_flow_deleted gauge
everoute_ms_startup_previous_round_flow_deleted 1
`
	if err := testutil.CollectAndCompare(metric.startupPreviousRoundFlowDeleted, strings.NewReader(expectedDeleted)); err != nil {
		t.Fatalf("unexpected deleted startup flow metric: %s", err)
	}
}

func TestUpdatePolicyNameFallbackToCRName(t *testing.T) {
	const policyID = "default/custom-policy"
	crName := "custom-policy"

	tests := []struct {
		name   string
		policy *securityv1alpha1.SecurityPolicy
		want   string
	}{
		{
			name: "use logging tag name",
			policy: &securityv1alpha1.SecurityPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: crName},
				Spec: securityv1alpha1.SecurityPolicySpec{
					Logging: &securityv1alpha1.Logging{
						Tags: map[string]string{constants.LoggingTagPolicyName: "policy-name"},
					},
				},
			},
			want: "policy-name",
		},
		{
			name: "use empty logging name when logging tag name is empty",
			policy: &securityv1alpha1.SecurityPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: crName},
				Spec: securityv1alpha1.SecurityPolicySpec{
					Logging: &securityv1alpha1.Logging{
						Tags: map[string]string{constants.LoggingTagPolicyName: ""},
					},
				},
			},
			want: "",
		},
		{
			name: "fallback to policy id when logging tag name is missing",
			policy: &securityv1alpha1.SecurityPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: crName},
				Spec: securityv1alpha1.SecurityPolicySpec{
					Logging: &securityv1alpha1.Logging{
						Tags: map[string]string{constants.LoggingTagPolicyID: "tower-id"},
					},
				},
			},
			want: policyID,
		},
		{
			name: "fallback to policy id when logging names are missing",
			policy: &securityv1alpha1.SecurityPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: crName},
				Spec: securityv1alpha1.SecurityPolicySpec{
					Logging: &securityv1alpha1.Logging{
						Tags: map[string]string{},
					},
				},
			},
			want: policyID,
		},
		{
			name: "fallback to policy id when logging is nil",
			policy: &securityv1alpha1.SecurityPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: crName},
			},
			want: policyID,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			metric := NewAgentMetric()
			metric.UpdatePolicyName(policyID, tt.policy)
			if got := metric.policyNameMap[policyID]; got != tt.want {
				t.Fatalf("policy name = %q, want %q", got, tt.want)
			}

			metric.SetRuleEntryNum(policyID, 2)
			expected := fmt.Sprintf(`
# HELP everoute_ms_rule_entry_num The count of datapath policy rule for each policy
# TYPE everoute_ms_rule_entry_num gauge
everoute_ms_rule_entry_num{name=%q} 2
`, tt.want)
			if err := testutil.CollectAndCompare(&metric.ruleEntryNum, strings.NewReader(expected)); err != nil {
				t.Fatalf("unexpected rule entry metric: %s", err)
			}
		})
	}
}

func TestUpdatePolicyNameForSKSNetworkPolicy(t *testing.T) {
	const policyID = "sks-sync-object/np.sks-policy"

	metric := NewAgentMetric()
	metric.UpdatePolicyName(policyID, &securityv1alpha1.SecurityPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "sks-sync-object",
			Name:      "np.sks-policy",
			Labels: map[string]string{
				constants.SKSLabelKeyCluster:         "cluster-a",
				constants.SKSLabelKeyObjectName:      "network-policy",
				constants.SKSLabelKeyObjectNamespace: "default",
			},
		},
	})

	const want = "cluster-a/network-policy/default"
	if got := metric.policyNameMap[policyID]; got != want {
		t.Fatalf("policy name = %q, want %q", got, want)
	}
}
