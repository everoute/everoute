package policy

import (
	"context"
	"os"
	"reflect"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"k8s.io/apimachinery/pkg/util/sets"
	ctrl "sigs.k8s.io/controller-runtime"

	policycache "github.com/everoute/everoute/pkg/agent/controller/policy/cache"
	"github.com/everoute/everoute/pkg/apis/group/v1alpha1"
	"github.com/everoute/everoute/pkg/metrics"
)

const (
	// DefaultPolicyRuleEstimateLimit is the default rule count limit for policy admission.
	DefaultPolicyRuleEstimateLimit uint64 = 20000
	policyMemoryOpenRatio                 = 0.80
	policyMemoryRecoverRatio              = 0.70
	policyAdmissionRequeueAfter           = 5 * time.Minute

	policyMemoryLimitExtraBytes = 50 * 1024 * 1024

	policyGuardResourcePolicy       = "policy"
	policyGuardResourceGroupMembers = "group_members"

	policyGuardOperationAdd    = "add"
	policyGuardOperationUpdate = "update"
	policyGuardOperationDelete = "delete"

	policyGuardReasonRuleEstimateExceeded = "rule_estimate_exceeded"
	policyGuardReasonMemoryBreakerOpen    = "memory_breaker_open"
	policyGuardReasonMemoryExceeded       = "memory_usage_exceeded"
	policyGuardReasonMemoryRecovered      = "memory_usage_recovered"
)

type guardObjectKey struct {
	Resource  string
	Namespace string
	Name      string
	Operation string
	Reason    string
}

type admissionResult struct {
	Allowed      bool
	RequeueAfter time.Duration
	Reason       string
	Err          error
}

type admissionRequest struct {
	Resource  string
	Namespace string
	Name      string
	Operation string
	Estimate  uint64
}

func newAdmissionRequest(resource, namespace, name, operation string) admissionRequest {
	return admissionRequest{
		Resource:  resource,
		Namespace: namespace,
		Name:      name,
		Operation: operation,
	}
}

func (req admissionRequest) key(reason string) guardObjectKey {
	return guardObjectKey{
		Resource:  req.Resource,
		Namespace: req.Namespace,
		Name:      req.Name,
		Operation: req.Operation,
		Reason:    reason,
	}
}

func (req admissionRequest) sameObject(key guardObjectKey) bool {
	return req.Resource == key.Resource && req.Namespace == key.Namespace && req.Name == key.Name
}

// MemoryGuard rejects policy admission when process memory is risky.
type MemoryGuard struct {
	metric *metrics.AgentMetric

	memoryLimitLock        sync.RWMutex
	memoryLimit            uint64
	memoryOpenThreshold    uint64
	memoryRecoverThreshold uint64

	memoryOpen       bool
	rejectedByMemory map[guardObjectKey]struct{}
}

func newMemoryGuard(metric *metrics.AgentMetric, staticMemoryLimit uint64) *MemoryGuard {
	guard := &MemoryGuard{
		metric:           metric,
		rejectedByMemory: make(map[guardObjectKey]struct{}),
	}
	guard.setMemoryLimit(staticMemoryLimit)
	return guard
}

func (g *MemoryGuard) admit(ctx context.Context, req admissionRequest) admissionResult {
	if g == nil {
		return admissionResult{Allowed: true}
	}

	log := ctrl.LoggerFrom(ctx)
	if g.memoryRisky() {
		key := req.key(policyGuardReasonMemoryBreakerOpen)
		g.rejectedByMemory[key] = struct{}{}
		g.metric.SetPolicyMemoryBreakerRejectedObject(key.Resource, key.Namespace, key.Name, key.Operation, key.Reason, true)
		log.Info("Reject policy reconcile by memory breaker", "resource", req.Resource, "namespace", req.Namespace,
			"name", req.Name, "operation", req.Operation)
		return admissionResult{Allowed: false, RequeueAfter: policyAdmissionRequeueAfter, Reason: policyGuardReasonMemoryBreakerOpen}
	}

	g.resetRejectedObject(req)
	return admissionResult{Allowed: true}
}

func (g *MemoryGuard) memoryRisky() bool {
	memoryLimit, openThreshold, recoverThreshold := g.memoryLimitSnapshot()
	if memoryLimit == 0 {
		return false
	}

	usage := readMemoryUsage()
	g.recordMemoryUsage(usage, memoryLimit, openThreshold, recoverThreshold)

	if usage > openThreshold {
		if !g.memoryOpen {
			g.openMemoryBreaker(policyGuardReasonMemoryExceeded)
		}
		return true
	}

	if usage < recoverThreshold {
		if g.memoryOpen {
			g.recoverMemoryBreaker()
		}
		return false
	}

	// Keep the current breaker state inside the hysteresis window to avoid flapping.
	return g.memoryOpen
}

func (g *MemoryGuard) recordMemoryUsage(usage, limit, openThreshold, recoverThreshold uint64) {
	g.metric.SetPolicyMemoryInfo(
		usage,
		limit,
		openThreshold,
		recoverThreshold)
}

func (g *MemoryGuard) recoverMemoryBreaker() {
	g.memoryOpen = false
	g.metric.SetPolicyMemoryBreakerOpen(false)
	g.metric.IncPolicyMemoryBreakerRecover(policyGuardReasonMemoryRecovered)
}

func (g *MemoryGuard) openMemoryBreaker(reason string) {
	g.memoryOpen = true
	g.metric.SetPolicyMemoryBreakerOpen(true)
	g.metric.IncPolicyMemoryBreakerOpen(reason)
}

func (g *MemoryGuard) resetRejectedObject(req admissionRequest) {
	if g == nil {
		return
	}
	for key := range g.rejectedByMemory {
		if req.sameObject(key) {
			// TODO: Consider deleting recovered object label values instead of setting them to 0.
			g.metric.SetPolicyMemoryBreakerRejectedObject(key.Resource, key.Namespace, key.Name, key.Operation, key.Reason, false)
			delete(g.rejectedByMemory, key)
		}
	}
}

func (g *MemoryGuard) setMemoryLimit(limit uint64) (uint64, uint64) {
	if g == nil {
		return 0, 0
	}
	g.memoryLimitLock.Lock()

	prev := g.memoryLimit
	g.memoryLimit = limit
	g.memoryOpenThreshold = uint64(float64(limit) * policyMemoryOpenRatio)
	g.memoryRecoverThreshold = uint64(float64(limit) * policyMemoryRecoverRatio)
	current := g.memoryLimit
	openThreshold := g.memoryOpenThreshold
	recoverThreshold := g.memoryRecoverThreshold
	g.memoryLimitLock.Unlock()

	g.recordMemoryUsage(readMemoryUsage(), current, openThreshold, recoverThreshold)
	return prev, current
}

func (g *MemoryGuard) memoryLimitSnapshot() (uint64, uint64, uint64) {
	if g == nil {
		return 0, 0, 0
	}
	g.memoryLimitLock.RLock()
	defer g.memoryLimitLock.RUnlock()
	return g.memoryLimit, g.memoryOpenThreshold, g.memoryRecoverThreshold
}

func memoryLimitFromGOMemLimit(goMemLimit int64) uint64 {
	if goMemLimit <= 0 {
		return 0
	}
	return uint64(goMemLimit) + policyMemoryLimitExtraBytes
}

// RuleEstimateGuard rejects policy admission when estimated rules exceed the configured limit.
type RuleEstimateGuard struct {
	metric *metrics.AgentMetric

	ruleEstimateLimit atomic.Uint64
	rejectedByRule    map[guardObjectKey]struct{}
}

func newRuleEstimateGuard(metric *metrics.AgentMetric, ruleEstimateLimit uint64) *RuleEstimateGuard {
	guard := &RuleEstimateGuard{
		metric:         metric,
		rejectedByRule: make(map[guardObjectKey]struct{}),
	}
	guard.setRuleEstimateLimit(ruleEstimateLimit)
	return guard
}

func (g *RuleEstimateGuard) admit(ctx context.Context, req admissionRequest) admissionResult {
	if g == nil {
		return admissionResult{Allowed: true}
	}
	ruleEstimateLimit := g.ruleEstimateLimit.Load()
	if ruleEstimateLimit == 0 {
		g.resetRejectedObject(req)
		return admissionResult{Allowed: true}
	}

	log := ctrl.LoggerFrom(ctx)
	if req.Estimate > ruleEstimateLimit {
		key := req.key(policyGuardReasonRuleEstimateExceeded)
		if _, exists := g.rejectedByRule[key]; exists {
			g.metric.IncPolicyRuleEstimateRequeue(key.Resource, key.Namespace, key.Name, key.Operation, key.Reason)
		}
		g.rejectedByRule[key] = struct{}{}
		g.metric.IncPolicyRuleEstimateReject(key.Resource, key.Namespace, key.Name, key.Operation, key.Reason)
		g.metric.SetPolicyRuleEstimateRejectedObject(key.Resource, key.Namespace, key.Name, key.Operation, key.Reason, true)
		g.metric.SetPolicyRuleEstimateRejectedValue(key.Resource, key.Namespace, key.Name, key.Operation, key.Reason, req.Estimate)
		log.Info("Reject policy reconcile by rule estimate", "resource", req.Resource, "namespace", req.Namespace,
			"name", req.Name, "operation", req.Operation, "estimate", req.Estimate, "limit", ruleEstimateLimit)
		return admissionResult{Allowed: false, RequeueAfter: policyAdmissionRequeueAfter, Reason: policyGuardReasonRuleEstimateExceeded}
	}

	g.resetRejectedObject(req)
	return admissionResult{Allowed: true}
}

func (g *RuleEstimateGuard) ruleEstimateLimitValue() uint64 {
	if g == nil {
		return DefaultPolicyRuleEstimateLimit
	}
	return g.ruleEstimateLimit.Load()
}

func (g *RuleEstimateGuard) setRuleEstimateLimit(limit uint64) (uint64, uint64) {
	if g == nil {
		return 0, 0
	}
	prev := g.ruleEstimateLimit.Swap(limit)
	current := g.ruleEstimateLimit.Load()
	g.metric.SetPolicyRuleEstimateLimit(current)
	return prev, current
}

func (g *RuleEstimateGuard) resetRejectedObject(req admissionRequest) {
	if g == nil {
		return
	}
	for key := range g.rejectedByRule {
		if req.sameObject(key) {
			// TODO: Consider deleting recovered object label values instead of setting them to 0.
			g.metric.SetPolicyRuleEstimateRejectedObject(key.Resource, key.Namespace, key.Name, key.Operation, key.Reason, false)
			g.metric.SetPolicyRuleEstimateRejectedValue(key.Resource, key.Namespace, key.Name, key.Operation, key.Reason, 0)
			g.metric.IncPolicyRuleEstimateRetrySuccess(key.Resource, key.Namespace, key.Name, key.Operation, key.Reason)
			delete(g.rejectedByRule, key)
		}
	}
}

func isPureCompleteRuleDelete(oldRules, newRules []*policycache.CompleteRule) bool {
	oldRuleByID := make(map[string]*policycache.CompleteRule, len(oldRules))
	newRuleByID := make(map[string]*policycache.CompleteRule, len(newRules))
	for _, rule := range oldRules {
		oldRuleByID[rule.RuleID] = rule
	}
	for _, rule := range newRules {
		newRuleByID[rule.RuleID] = rule
	}

	hasDeletedRule := false
	for ruleID, newRule := range newRuleByID {
		oldRule, exists := oldRuleByID[ruleID]
		if !exists || completeRuleChanged(oldRule, newRule) {
			return false
		}
	}
	for ruleID := range oldRuleByID {
		if _, exists := newRuleByID[ruleID]; !exists {
			hasDeletedRule = true
		}
	}

	return hasDeletedRule
}

func completeRuleInterfacesToRules(items []interface{}) []*policycache.CompleteRule {
	res := make([]*policycache.CompleteRule, 0, len(items))
	for _, item := range items {
		res = append(res, item.(*policycache.CompleteRule))
	}
	return res
}

func groupMembersPureShrink(groupCache *policycache.GroupCache, gm *v1alpha1.GroupMembers) bool {
	oldMembers, exists := groupCache.GetGroupMembership(gm.Name)
	if !exists {
		return len(gm.GroupMembers) == 0
	}
	oldKeys := groupMemberKeys(oldMembers)
	newKeys := groupMemberKeys(gm.GroupMembers)
	return oldKeys.IsSuperset(newKeys)
}

func groupMemberKeys(members []v1alpha1.GroupMember) sets.Set[string] {
	res := sets.New[string]()
	for _, member := range members {
		ips := make([]string, 0, len(member.IPs))
		for _, ip := range member.IPs {
			ips = append(ips, string(ip))
		}
		sort.Strings(ips)
		agents := append([]string{}, member.EndpointAgent...)
		sort.Strings(agents)
		ports := make([]string, 0, len(member.Ports))
		for _, port := range member.Ports {
			ports = append(ports, port.ToString())
		}
		sort.Strings(ports)
		res.Insert(strings.Join([]string{
			member.EndpointReference.ExternalIDName,
			member.EndpointReference.ExternalIDValue,
			strings.Join(ips, ","),
			strings.Join(agents, ","),
			member.VDSID,
			strings.Join(ports, ","),
		}, "|"))
	}
	return res
}

func completeRuleChanged(oldRule, newRule *policycache.CompleteRule) bool {
	return !reflect.DeepEqual(completeRuleComparable(oldRule), completeRuleComparable(newRule))
}

type comparableCompleteRule struct {
	RuleID            string
	Policy            string
	Tier              string
	Priority          int32
	EnforcementMode   string
	Action            policycache.RuleAction
	Direction         policycache.RuleDirection
	SymmetricMode     bool
	DefaultPolicyRule bool
	FullIsolation     bool
	SrcGroups         []string
	DstGroups         []string
	SrcIPs            []string
	DstIPs            []string
	Ports             []policycache.RulePort
}

func completeRuleComparable(rule *policycache.CompleteRule) comparableCompleteRule {
	return comparableCompleteRule{
		RuleID:            rule.RuleID,
		Policy:            rule.Policy,
		Tier:              rule.Tier,
		Priority:          rule.Priority,
		EnforcementMode:   rule.EnforcementMode,
		Action:            rule.Action,
		Direction:         rule.Direction,
		SymmetricMode:     rule.SymmetricMode,
		DefaultPolicyRule: rule.DefaultPolicyRule,
		FullIsolation:     rule.FullIsolationPolicy,
		SrcGroups:         sortedSet(rule.SrcGroups),
		DstGroups:         sortedSet(rule.DstGroups),
		SrcIPs:            sortedSet(rule.SrcIPs),
		DstIPs:            sortedSet(rule.DstIPs),
		Ports:             append([]policycache.RulePort{}, rule.Ports...),
	}
}

func sortedSet(in sets.Set[string]) []string {
	res := in.UnsortedList()
	sort.Strings(res)
	return res
}

func readMemoryUsage() uint64 {
	if usage, ok := readProcessRSS(); ok {
		return usage
	}
	return runtimeMemoryUsage()
}

func readProcessRSS() (uint64, bool) {
	raw, err := os.ReadFile("/proc/self/statm")
	if err != nil {
		return 0, false
	}
	fields := strings.Fields(string(raw))
	if len(fields) < 2 {
		return 0, false
	}
	residentPages, err := strconv.ParseUint(fields[1], 10, 64)
	if err != nil {
		return 0, false
	}
	return residentPages * uint64(os.Getpagesize()), true
}

func runtimeMemoryUsage() uint64 {
	var stat runtime.MemStats
	runtime.ReadMemStats(&stat)
	return stat.Sys - stat.HeapReleased
}
