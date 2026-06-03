package cache

import (
	"context"
	"testing"

	"golang.org/x/sys/unix"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"

	groupv1alpha1 "github.com/everoute/everoute/pkg/apis/group/v1alpha1"
	securityv1alpha1 "github.com/everoute/everoute/pkg/apis/security/v1alpha1"
	"github.com/everoute/everoute/pkg/types"
)

func TestEstimateCompleteRuleMatchesGeneratedRules(t *testing.T) {
	ctx := context.Background()
	groupCache := NewGroupCache()
	group := &groupv1alpha1.GroupMembers{
		ObjectMeta: metav1.ObjectMeta{Name: "dst-group"},
		GroupMembers: []groupv1alpha1.GroupMember{
			{
				IPs: []types.IPAddress{"10.0.0.2", "fe80::2"},
			},
			{
				IPs: []types.IPAddress{"10.0.0.3"},
				Ports: []securityv1alpha1.NamedPort{
					{Name: "web", Protocol: securityv1alpha1.ProtocolTCP, Port: 8080},
					{Name: "web", Protocol: securityv1alpha1.ProtocolUDP, Port: 8081},
				},
			},
		},
	}
	groupCache.UpdateGroupMembership(group)

	rule := &CompleteRule{
		RuleID:          "ns/policy/normal/ingress.rule1",
		Policy:          "ns/policy",
		Tier:            "tier2",
		EnforcementMode: "work",
		Action:          RuleActionAllow,
		Direction:       RuleDirectionIn,
		SrcIPs:          sets.New[string](""),
		DstGroups:       sets.New[string](group.Name),
		Ports: []RulePort{
			{Protocol: securityv1alpha1.ProtocolTCP, DstPort: 80, DstPortMask: 0xffff},
			{Protocol: securityv1alpha1.ProtocolTCP, DstPortName: "web"},
		},
	}

	estimate, err := rule.EstimateRuleCount(ctx, groupCache, sets.New[string]())
	if err != nil {
		t.Fatalf("estimate complete rule: %v", err)
	}
	generated := rule.ListRules(ctx, groupCache, sets.New[string]())
	if estimate != uint64(len(generated)) {
		t.Fatalf("expected estimate %d to match generated rule count %d: %#v", estimate, len(generated), generated)
	}
	if len(generated) == 0 {
		t.Fatal("expected generated rules to be non-empty")
	}
	for _, item := range generated {
		if item.IPFamily != unix.AF_INET && item.IPFamily != unix.AF_INET6 {
			t.Fatalf("unexpected generated rule IP family: %d", item.IPFamily)
		}
	}
}
