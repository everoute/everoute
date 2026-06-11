package policy

import (
	"context"
	"testing"

	"github.com/agiledragon/gomonkey/v2"

	"github.com/everoute/everoute/pkg/metrics"
)

func TestRuleEstimateGuardAdmit(t *testing.T) {
	guard := newRuleEstimateGuard(metrics.NewAgentMetric(), 10)
	req := newAdmissionRequest(policyGuardResourcePolicy, "ns", "policy-a", policyGuardOperationAdd)
	req.Estimate = 11

	res := guard.admit(context.Background(), req)
	if res.Allowed {
		t.Fatalf("expected rule estimate guard to reject request")
	}
	if res.Reason != policyGuardReasonRuleEstimateExceeded {
		t.Fatalf("unexpected reject reason %q", res.Reason)
	}
	if res.RequeueAfter != policyAdmissionRequeueAfter {
		t.Fatalf("unexpected requeue after %s", res.RequeueAfter)
	}
	if len(guard.rejectedByRule) != 1 {
		t.Fatalf("expected rejected object to be recorded, got %d", len(guard.rejectedByRule))
	}

	req.Estimate = 10
	res = guard.admit(context.Background(), req)
	if !res.Allowed {
		t.Fatalf("expected request within rule estimate limit to be allowed: %+v", res)
	}
	if len(guard.rejectedByRule) != 0 {
		t.Fatalf("expected rejected object to be reset, got %d", len(guard.rejectedByRule))
	}
}

func TestRuleEstimateGuardDisabledOrUnlimitedResetsRejectedObject(t *testing.T) {
	guard := newRuleEstimateGuard(metrics.NewAgentMetric(), 10)
	req := newAdmissionRequest(policyGuardResourceGroupMembers, "ns", "group-a", policyGuardOperationUpdate)
	key := req.key(policyGuardReasonRuleEstimateExceeded)
	guard.rejectedByRule[key] = struct{}{}

	guard.setEnabled(false)
	res := guard.admit(context.Background(), req)
	if !res.Allowed {
		t.Fatalf("expected disabled rule estimate guard to allow request: %+v", res)
	}
	if len(guard.rejectedByRule) != 0 {
		t.Fatalf("expected disabled rule estimate guard to reset rejected objects, got %d", len(guard.rejectedByRule))
	}

	guard.setEnabled(true)
	guard.rejectedByRule[key] = struct{}{}
	guard.setRuleEstimateLimit(0)
	res = guard.admit(context.Background(), req)
	if !res.Allowed {
		t.Fatalf("expected unlimited rule estimate guard to allow request: %+v", res)
	}
	if len(guard.rejectedByRule) != 0 {
		t.Fatalf("expected unlimited rule estimate guard to reset rejected objects, got %d", len(guard.rejectedByRule))
	}
}

func TestMemoryGuardAdmitRejectAndDisableReset(t *testing.T) {
	patches := gomonkey.ApplyFuncReturn(readMemoryUsage, uint64(200))
	defer patches.Reset()

	guard := newMemoryGuard(metrics.NewAgentMetric(), 100)
	req := newAdmissionRequest(policyGuardResourcePolicy, "ns", "policy-a", policyGuardOperationUpdate)

	res := guard.admit(context.Background(), req)
	if res.Allowed {
		t.Fatalf("expected memory guard to reject request")
	}
	if res.Reason != policyGuardReasonMemoryBreakerOpen {
		t.Fatalf("unexpected reject reason %q", res.Reason)
	}
	if res.RequeueAfter != policyAdmissionRequeueAfter {
		t.Fatalf("unexpected requeue after %s", res.RequeueAfter)
	}
	if !guard.isOpen() {
		t.Fatalf("expected memory breaker to be open")
	}
	if len(guard.rejectedByMemory) != 1 {
		t.Fatalf("expected rejected object to be recorded, got %d", len(guard.rejectedByMemory))
	}

	prev, current := guard.setEnabled(false)
	if !prev || current {
		t.Fatalf("unexpected enabled transition prev=%t current=%t", prev, current)
	}
	if guard.isOpen() {
		t.Fatalf("expected disabled memory guard to close breaker")
	}
	if len(guard.rejectedByMemory) != 0 {
		t.Fatalf("expected disabled memory guard to reset rejected objects, got %d", len(guard.rejectedByMemory))
	}

	res = guard.admit(context.Background(), req)
	if !res.Allowed {
		t.Fatalf("expected disabled memory guard to allow request: %+v", res)
	}
}

func TestMemoryGuardUnlimitedThresholdAllowsAndClosesBreaker(t *testing.T) {
	patches := gomonkey.ApplyFuncReturn(readMemoryUsage, uint64(200))
	defer patches.Reset()

	guard := newMemoryGuard(metrics.NewAgentMetric(), 100)
	req := newAdmissionRequest(policyGuardResourcePolicy, "ns", "policy-a", policyGuardOperationAdd)

	res := guard.admit(context.Background(), req)
	if res.Allowed {
		t.Fatalf("expected memory guard to reject request before threshold reset")
	}
	if !guard.isOpen() {
		t.Fatalf("expected memory breaker to be open")
	}

	prev, current := guard.setMemoryThreshold(0)
	if prev != 100 || current != 0 {
		t.Fatalf("unexpected threshold transition prev=%d current=%d", prev, current)
	}
	if guard.isOpen() {
		t.Fatalf("expected zero threshold to close memory breaker")
	}

	res = guard.admit(context.Background(), req)
	if !res.Allowed {
		t.Fatalf("expected zero memory threshold to allow request: %+v", res)
	}
}

func TestResetGuardResetsMemoryAndRuleRejectedObjects(t *testing.T) {
	reconciler := &Reconciler{
		memoryGuard:       newMemoryGuard(metrics.NewAgentMetric(), 0),
		ruleEstimateGuard: newRuleEstimateGuard(metrics.NewAgentMetric(), 10),
	}
	req := newAdmissionRequest(policyGuardResourcePolicy, "ns", "policy-a", policyGuardOperationDelete)
	memoryKey := req.key(policyGuardReasonMemoryBreakerOpen)
	ruleKey := req.key(policyGuardReasonRuleEstimateExceeded)
	reconciler.memoryGuard.rejectedByMemory[memoryKey] = struct{}{}
	reconciler.ruleEstimateGuard.rejectedByRule[ruleKey] = struct{}{}

	reconciler.resetGuard(req)
	if len(reconciler.memoryGuard.rejectedByMemory) != 0 {
		t.Fatalf("expected memory rejected object to be reset, got %d", len(reconciler.memoryGuard.rejectedByMemory))
	}
	if len(reconciler.ruleEstimateGuard.rejectedByRule) != 0 {
		t.Fatalf("expected rule rejected object to be reset, got %d", len(reconciler.ruleEstimateGuard.rejectedByRule))
	}
}

func TestGuardStatus(t *testing.T) {
	reconciler := &Reconciler{
		memoryGuard:       newMemoryGuard(metrics.NewAgentMetric(), 300),
		ruleEstimateGuard: newRuleEstimateGuard(metrics.NewAgentMetric(), 20),
	}
	reconciler.memoryGuard.markOpen(policyGuardReasonMemoryExceeded)
	reconciler.ruleEstimateGuard.setEnabled(false)

	status := reconciler.GetGuardStatus()
	if !status.MemoryEnabled {
		t.Fatalf("expected memory guard to be enabled")
	}
	if !status.MemoryBreakerOpen {
		t.Fatalf("expected memory breaker to be open")
	}
	if status.MemoryThreshold != 300 {
		t.Fatalf("unexpected memory threshold %d", status.MemoryThreshold)
	}
	if status.RuleEnabled {
		t.Fatalf("expected rule guard to be disabled")
	}
	if status.RuleEstimateLimit != 20 {
		t.Fatalf("unexpected rule estimate limit %d", status.RuleEstimateLimit)
	}
}

func TestNormalizeGuardType(t *testing.T) {
	for _, guardType := range []string{policyGuardTypeMemory, policyGuardTypeRule} {
		normalized, err := normalizeGuardType(guardType)
		if err != nil {
			t.Fatalf("expected guard type %q to be valid: %v", guardType, err)
		}
		if normalized != guardType {
			t.Fatalf("expected normalized guard type %q, got %q", guardType, normalized)
		}
	}

	if _, err := normalizeGuardType("invalid"); err == nil {
		t.Fatalf("expected invalid guard type to return error")
	}
}
