package policy

import (
	"context"
	"fmt"
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
	policyAdmissionRequeueAfter           = 2 * time.Minute

	policyMemoryRecoverInterval = 5 * time.Second
	policyMemoryProbeInterval   = 5 * time.Minute

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

const (
	policyGuardTypeMemory = "memory"
	policyGuardTypeRule   = "rule"
)

type guardObjectKey struct {
	Resource  string
	Namespace string
	Name      string
	Operation string
	Reason    string
}

// GuardRuntimeSetter updates policy admission guard limits at runtime.
type GuardRuntimeSetter interface {
	GetRuleEstimateLimit() uint64
	SetRuleEstimateLimit(limit uint64) (uint64, uint64)
	SetMemoryThreshold(threshold uint64) (uint64, uint64)
	SetGuardEnabled(guardType string, enabled bool) (bool, bool, error)
	GetGuardStatus() GuardStatus
}

// GuardStatus records runtime status for policy admission guards.
type GuardStatus struct {
	MemoryEnabled     bool
	MemoryBreakerOpen bool
	MemoryThreshold   uint64
	RuleEnabled       bool
	RuleEstimateLimit uint64
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
	TowerID   string
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

	memoryThresholdLock sync.RWMutex
	memoryThreshold     uint64

	memoryOpenLock       sync.RWMutex
	memoryOpen           bool
	enabled              atomic.Bool
	rejectedByMemoryLock sync.Mutex
	rejectedByMemory     map[guardObjectKey]struct{}
}

func newMemoryGuard(metric *metrics.AgentMetric, staticMemoryThreshold uint64) *MemoryGuard {
	guard := &MemoryGuard{
		metric:           metric,
		rejectedByMemory: make(map[guardObjectKey]struct{}),
	}
	guard.enabled.Store(true)
	guard.metric.SetPolicyGuardEnabled(policyGuardTypeMemory, true)
	guard.setMemoryThreshold(staticMemoryThreshold)
	return guard
}

func (g *MemoryGuard) Start(ctx context.Context) error {
	if g == nil {
		return nil
	}
	ticker := time.NewTicker(policyMemoryProbeInterval)
	defer ticker.Stop()

	log := ctrl.LoggerFrom(ctx)
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if !g.enabled.Load() {
				continue
			}
			if _, err := g.refresh(policyGuardReasonMemoryExceeded); err != nil {
				log.Error(err, "Failed to refresh policy memory breaker by periodic probe")
			}
		}
	}
}

func (g *MemoryGuard) admit(ctx context.Context, req admissionRequest) admissionResult {
	if g == nil {
		return admissionResult{Allowed: true}
	}
	if !g.enabled.Load() {
		g.resetRejectedObject(req)
		return admissionResult{Allowed: true}
	}

	log := ctrl.LoggerFrom(ctx)
	memoryRisky, err := g.memoryRisky()
	if err != nil {
		return admissionResult{Err: err}
	}
	if memoryRisky {
		key := req.key(policyGuardReasonMemoryBreakerOpen)
		g.rejectedByMemoryLock.Lock()
		g.rejectedByMemory[key] = struct{}{}
		g.metric.SetPolicyMemoryBreakerRejectedObject(key.Resource, key.Namespace, key.Name, key.Operation, key.Reason, true)
		g.rejectedByMemoryLock.Unlock()
		log.Info("Reject policy reconcile by memory breaker", "resource", req.Resource, "namespace", req.Namespace,
			"name", req.Name, "operation", req.Operation)
		return admissionResult{Allowed: false, RequeueAfter: policyAdmissionRequeueAfter, Reason: policyGuardReasonMemoryBreakerOpen}
	}

	g.resetRejectedObject(req)
	return admissionResult{Allowed: true}
}

func (g *MemoryGuard) memoryRisky() (bool, error) {
	return g.refresh(policyGuardReasonMemoryExceeded)
}

func (g *MemoryGuard) refresh(reason string) (bool, error) {
	threshold := g.memoryThresholdSnapshot()
	if threshold == 0 {
		return false, nil
	}

	usage := readMemoryUsage()
	g.recordMemoryUsage(usage, threshold)

	if usage > threshold {
		return g.markOpen(reason), nil
	}

	if !g.isOpen() {
		return false, nil
	}

	time.Sleep(policyMemoryRecoverInterval)

	threshold = g.memoryThresholdSnapshot()
	if threshold == 0 {
		return false, nil
	}

	usage = readMemoryUsage()
	g.recordMemoryUsage(usage, threshold)
	if usage > threshold {
		return g.markOpen(reason), nil
	}

	return g.markClosed(), nil
}

func (g *MemoryGuard) recordMemoryUsage(usage, threshold uint64) {
	g.metric.SetPolicyMemoryInfo(usage, threshold)
}

func (g *MemoryGuard) markOpen(reason string) bool {
	g.memoryOpenLock.Lock()
	defer g.memoryOpenLock.Unlock()

	if !g.memoryOpen {
		g.memoryOpen = true
		ctrl.Log.Info("Open policy memory breaker", "reason", reason)
		g.metric.SetPolicyMemoryBreakerOpen(true)
		g.metric.IncPolicyMemoryBreakerOpen(reason)
	}
	return true
}

func (g *MemoryGuard) markClosed() bool {
	g.memoryOpenLock.Lock()
	defer g.memoryOpenLock.Unlock()

	if g.memoryOpen {
		g.memoryOpen = false
		ctrl.Log.Info("Close policy memory breaker", "reason", policyGuardReasonMemoryRecovered)
		g.metric.SetPolicyMemoryBreakerOpen(false)
		g.metric.IncPolicyMemoryBreakerRecover(policyGuardReasonMemoryRecovered)
	}
	return false
}

func (g *MemoryGuard) closeWithoutRecoverMetric() {
	g.memoryOpenLock.Lock()
	defer g.memoryOpenLock.Unlock()

	if g.memoryOpen {
		g.memoryOpen = false
		ctrl.Log.Info("Close policy memory breaker without recording recovery")
		g.metric.SetPolicyMemoryBreakerOpen(false)
	}
}

func (g *MemoryGuard) isOpen() bool {
	g.memoryOpenLock.RLock()
	defer g.memoryOpenLock.RUnlock()
	return g.memoryOpen
}

func (g *MemoryGuard) setEnabled(enabled bool) (bool, bool) {
	if g == nil {
		return false, false
	}
	prev := g.enabled.Swap(enabled)
	g.metric.SetPolicyGuardEnabled(policyGuardTypeMemory, enabled)
	if !enabled {
		g.closeWithoutRecoverMetric()
		g.resetAllRejectedObjects()
	}
	return prev, enabled
}

func (g *MemoryGuard) enabledValue() bool {
	if g == nil {
		return false
	}
	return g.enabled.Load()
}

func (g *MemoryGuard) resetRejectedObject(req admissionRequest) {
	if g == nil {
		return
	}
	g.rejectedByMemoryLock.Lock()
	defer g.rejectedByMemoryLock.Unlock()
	for key := range g.rejectedByMemory {
		if req.sameObject(key) {
			// TODO: Consider deleting recovered object label values instead of setting them to 0.
			g.metric.SetPolicyMemoryBreakerRejectedObject(key.Resource, key.Namespace, key.Name, key.Operation, key.Reason, false)
			delete(g.rejectedByMemory, key)
		}
	}
}

func (g *MemoryGuard) resetAllRejectedObjects() {
	if g == nil {
		return
	}
	g.rejectedByMemoryLock.Lock()
	defer g.rejectedByMemoryLock.Unlock()
	for key := range g.rejectedByMemory {
		g.metric.SetPolicyMemoryBreakerRejectedObject(key.Resource, key.Namespace, key.Name, key.Operation, key.Reason, false)
		delete(g.rejectedByMemory, key)
	}
}

func (g *MemoryGuard) setMemoryThreshold(threshold uint64) (uint64, uint64) {
	if g == nil {
		return 0, 0
	}
	g.memoryThresholdLock.Lock()

	prev := g.memoryThreshold
	g.memoryThreshold = threshold
	current := g.memoryThreshold
	g.memoryThresholdLock.Unlock()

	g.recordMemoryUsage(readMemoryUsage(), current)
	if current == 0 {
		g.closeWithoutRecoverMetric()
	}
	return prev, current
}

func (g *MemoryGuard) memoryThresholdSnapshot() uint64 {
	if g == nil {
		return 0
	}
	g.memoryThresholdLock.RLock()
	defer g.memoryThresholdLock.RUnlock()
	return g.memoryThreshold
}

// RuleEstimateGuard rejects policy admission when estimated rules exceed the configured limit.
type RuleEstimateGuard struct {
	metric *metrics.AgentMetric

	ruleEstimateLimit  atomic.Uint64
	enabled            atomic.Bool
	rejectedByRuleLock sync.Mutex
	rejectedByRule     map[guardObjectKey]struct{}
}

func newRuleEstimateGuard(metric *metrics.AgentMetric, ruleEstimateLimit uint64) *RuleEstimateGuard {
	guard := &RuleEstimateGuard{
		metric:         metric,
		rejectedByRule: make(map[guardObjectKey]struct{}),
	}
	guard.enabled.Store(true)
	guard.metric.SetPolicyGuardEnabled(policyGuardTypeRule, true)
	guard.setRuleEstimateLimit(ruleEstimateLimit)
	return guard
}

func (g *RuleEstimateGuard) admit(ctx context.Context, req admissionRequest) admissionResult {
	if g == nil {
		return admissionResult{Allowed: true}
	}
	if !g.enabled.Load() {
		g.resetRejectedObject(req)
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
		g.rejectedByRuleLock.Lock()
		g.rejectedByRule[key] = struct{}{}
		if g.metric != nil {
			g.metric.SetPolicyRuleEstimateRejectedValue(key.Resource, key.Namespace, key.Name, req.TowerID, key.Operation, key.Reason, req.Estimate)
		}
		g.rejectedByRuleLock.Unlock()
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

func (g *RuleEstimateGuard) setEnabled(enabled bool) (bool, bool) {
	if g == nil {
		return false, false
	}
	prev := g.enabled.Swap(enabled)
	g.metric.SetPolicyGuardEnabled(policyGuardTypeRule, enabled)
	if !enabled {
		g.resetAllRejectedObjects()
	}
	return prev, enabled
}

func (g *RuleEstimateGuard) enabledValue() bool {
	if g == nil {
		return false
	}
	return g.enabled.Load()
}

func (g *RuleEstimateGuard) resetRejectedObject(req admissionRequest) {
	if g == nil {
		return
	}
	g.rejectedByRuleLock.Lock()
	defer g.rejectedByRuleLock.Unlock()
	for key := range g.rejectedByRule {
		if req.sameObject(key) {
			if g.metric != nil {
				g.metric.DeletePolicyRuleEstimateRejectedValue(key.Resource, key.Namespace, key.Name, key.Operation, key.Reason)
			}
			delete(g.rejectedByRule, key)
		}
	}
}

func (g *RuleEstimateGuard) resetAllRejectedObjects() {
	if g == nil {
		return
	}
	g.rejectedByRuleLock.Lock()
	defer g.rejectedByRuleLock.Unlock()
	for key := range g.rejectedByRule {
		if g.metric != nil {
			g.metric.DeletePolicyRuleEstimateRejectedValue(key.Resource, key.Namespace, key.Name, key.Operation, key.Reason)
		}
		delete(g.rejectedByRule, key)
	}
}

func normalizeGuardType(guardType string) (string, error) {
	switch guardType {
	case policyGuardTypeMemory:
		return policyGuardTypeMemory, nil
	case policyGuardTypeRule:
		return policyGuardTypeRule, nil
	default:
		return "", fmt.Errorf("unsupported policy guard type %q", guardType)
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
