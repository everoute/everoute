package metrics

import (
	"fmt"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/samber/lo"
	klog "k8s.io/klog/v2"

	securityv1alpha1 "github.com/everoute/everoute/pkg/apis/security/v1alpha1"
	"github.com/everoute/everoute/pkg/config"
	agentconst "github.com/everoute/everoute/pkg/constants"
	constants "github.com/everoute/everoute/pkg/constants/ms"
	"github.com/everoute/everoute/plugin/tower/pkg/controller/policy"
)

const (
	MetricTRNicMount  = "tr_nic_mount"
	MetricTRHealthy   = "tr_healthy"
	MetrucTRNicStatus = "tr_nic_status"
	BridgeLabel       = "ovs_bridge"
	TypeLabel         = "type"
)

var limitTowerPolicyPrefix = []string{
	policy.SecurityPolicyPrefix,
	policy.IsolationPolicyPrefix,
	policy.IsolationPolicyIngressPrefix,
	policy.IsolationPolicyEgressPrefix,
	policy.SecurityPolicyCommunicablePrefix,
}

type AgentMetric struct {
	reg *prometheus.Registry

	arpCount       prometheus.Counter
	arpRejectCount prometheus.Counter

	ruleEntryTotalNum prometheus.Gauge
	ruleEntryNum      prometheus.GaugeVec

	policyNameMap map[string]string

	flowIDUsedCount                 prometheus.GaugeVec
	flowIDExhaust                   prometheus.GaugeVec
	startupPreviousRoundFlowDeleted prometheus.Gauge

	trNicMount  prometheus.GaugeVec
	trNicStatus prometheus.GaugeVec
	trHealthy   prometheus.GaugeVec

	policyGuardEnabled                 prometheus.GaugeVec
	policyMemoryBreakerOpen            prometheus.GaugeVec
	policyMemoryBreakerOpenTotal       prometheus.CounterVec
	policyMemoryBreakerRecoverTotal    prometheus.CounterVec
	policyMemoryBreakerRejectedObjects prometheus.GaugeVec
	policyMemoryUsageBytes             prometheus.GaugeVec
	policyMemoryThresholdBytes         prometheus.GaugeVec

	policyRuleEstimateLimit         prometheus.GaugeVec
	policyRuleEstimateRejectedValue prometheus.GaugeVec
}

func newAgentCounterOpt(name, help string) prometheus.CounterOpts {
	return prometheus.CounterOpts{
		Namespace: constants.MetricNamespace,
		Subsystem: constants.MetricSubSystem,
		Name:      name,
		Help:      help,
	}
}

func newAgentGaugeOpt(name, help string) prometheus.GaugeOpts {
	return prometheus.GaugeOpts{
		Namespace: constants.MetricNamespace,
		Subsystem: constants.MetricSubSystem,
		Name:      name,
		Help:      help,
	}
}

func NewAgentMetric() *AgentMetric {
	m := &AgentMetric{
		reg: prometheus.NewRegistry(),
		arpCount: prometheus.NewCounter(newAgentCounterOpt(
			constants.MetricArpCount,
			"The count for arp receive from datapath")),
		arpRejectCount: prometheus.NewCounter(newAgentCounterOpt(
			constants.MetricArpCountReject,
			"The count for arp receive from datapath but rejected by limiter")),
		ruleEntryTotalNum: prometheus.NewGauge(newAgentGaugeOpt(
			constants.MetricRuleEntryNumTotal,
			"The total count for datapath policy rule stored in agent"),
		),
		ruleEntryNum: *prometheus.NewGaugeVec(newAgentGaugeOpt(
			constants.MetricRuleEntryNum,
			"The count of datapath policy rule for each policy",
		), []string{constants.MetricRuleEntryPolicyNameLabel}),
		policyNameMap: map[string]string{},
		flowIDUsedCount: *prometheus.NewGaugeVec(newAgentGaugeOpt(
			agentconst.MetricFlowIDUsedCount,
			"the count flow seq id has allocated",
		), []string{agentconst.MetricFlowIDLabel}),
		flowIDExhaust: *prometheus.NewGaugeVec(newAgentGaugeOpt(
			agentconst.MetricFlowIDExhaust,
			"flow seq ids has exhaust or not",
		), []string{agentconst.MetricFlowIDLabel}),
		startupPreviousRoundFlowDeleted: prometheus.NewGauge(newAgentGaugeOpt(
			"startup_previous_round_flow_deleted",
			"Whether previous round flows have been deleted during startup cleanup",
		)),
		trNicMount: *prometheus.NewGaugeVec(newAgentGaugeOpt(
			MetricTRNicMount,
			"trafficredirect nic mount status",
		), []string{BridgeLabel, TypeLabel}),
		trHealthy: *prometheus.NewGaugeVec(newAgentGaugeOpt(
			MetricTRHealthy,
			"trafficredirect healthy",
		), []string{BridgeLabel, TypeLabel}),
		trNicStatus: *prometheus.NewGaugeVec(newAgentGaugeOpt(
			MetrucTRNicStatus,
			"trafficredirect nic link status",
		), []string{BridgeLabel, TypeLabel}),
	}
	m.startupPreviousRoundFlowDeleted.Set(0)
	m.initPolicyGuardMetrics()

	return m
}

func (m *AgentMetric) initPolicyGuardMetrics() {
	policyObjectLabels := []string{"resource", "namespace", "name", "operation", "reason"}
	policyRuleObjectLabels := []string{"resource", "namespace", "name", "tower_id", "operation", "reason"}
	memoryEventLabels := []string{"reason"}
	guardLabels := []string{"type"}

	m.policyGuardEnabled = *prometheus.NewGaugeVec(newAgentGaugeOpt(
		"policy_guard_enabled",
		"Whether agent policy admission guard is enabled",
	), guardLabels)
	m.policyMemoryBreakerOpen = *prometheus.NewGaugeVec(newAgentGaugeOpt(
		"policy_memory_breaker_open",
		"Whether agent policy controller memory breaker is open",
	), nil)
	m.policyMemoryBreakerOpenTotal = *prometheus.NewCounterVec(newAgentCounterOpt(
		"policy_memory_breaker_open_total",
		"The count of agent policy controller memory breaker open events",
	), memoryEventLabels)
	m.policyMemoryBreakerRecoverTotal = *prometheus.NewCounterVec(newAgentCounterOpt(
		"policy_memory_breaker_recover_total",
		"The count of agent policy controller memory breaker recover events",
	), memoryEventLabels)
	m.policyMemoryBreakerRejectedObjects = *prometheus.NewGaugeVec(newAgentGaugeOpt(
		"policy_memory_breaker_rejected_objects",
		"The policy objects currently rejected by memory breaker",
	), policyObjectLabels)
	m.policyMemoryUsageBytes = *prometheus.NewGaugeVec(newAgentGaugeOpt(
		"policy_memory_usage_bytes",
		"The memory usage bytes used by agent policy memory breaker",
	), nil)
	m.policyMemoryThresholdBytes = *prometheus.NewGaugeVec(newAgentGaugeOpt(
		"policy_memory_threshold_bytes",
		"The memory usage threshold bytes used by agent policy memory breaker",
	), nil)
	m.policyRuleEstimateLimit = *prometheus.NewGaugeVec(newAgentGaugeOpt(
		"policy_rule_estimate_limit",
		"The current policy rule estimate admission limit",
	), nil)
	m.policyRuleEstimateRejectedValue = *prometheus.NewGaugeVec(newAgentGaugeOpt(
		"policy_rule_estimate_rejected_value",
		"The estimated rule count for policy objects rejected by rule estimate admission",
	), policyRuleObjectLabels)
}

func (m *AgentMetric) UpdatePolicyName(policyID string, policy *securityv1alpha1.SecurityPolicy) {
	// clear metrix if policy deleted
	if policy == nil {
		if v, ok := m.policyNameMap[policyID]; ok {
			m.ruleEntryNum.DeleteLabelValues(v)
		}
		delete(m.policyNameMap, policyID)
		return
	}

	// for user-defined networkpolicy from sks
	if policy.Namespace == constants.SKSObjectNamespace &&
		strings.HasPrefix(policy.Name, constants.SKSNetworkpolicyPrefix) {
		clusterName := policy.Labels[constants.SKSLabelKeyCluster]
		objName := policy.Labels[constants.SKSLabelKeyCluster]
		objNamespace := policy.Labels[constants.SKSLabelKeyCluster]
		m.policyNameMap[policyID] = fmt.Sprintf("%s/%s/%s", clusterName, objName, objNamespace)
		return
	}

	// for tower UI policy
	if policy.Spec.Logging != nil &&
		lo.CountBy(limitTowerPolicyPrefix, func(item string) bool { return strings.HasPrefix(policy.Name, item) }) != 0 {
		if name, ok := policy.Spec.Logging.Tags[constants.LoggingTagPolicyName]; ok {
			m.policyNameMap[policyID] = name
		} else {
			m.policyNameMap[policyID] = policyID
		}
	}
}

func (m *AgentMetric) ArpInc() {
	m.arpCount.Inc()
}

func (m *AgentMetric) ArpRejectInc() {
	m.arpRejectCount.Inc()
}

func (m *AgentMetric) SetRuleEntryNum(policyID string, num int) {
	name, ok := m.policyNameMap[policyID]
	if !ok {
		return
	}
	m.ruleEntryNum.WithLabelValues(name).Set(float64(num))
}

func (m *AgentMetric) SetRuleEntryTotalNum(num int) {
	m.ruleEntryTotalNum.Set(float64(num))
}

func (m *AgentMetric) GetCollectors() []prometheus.Collector {
	res := []prometheus.Collector{m.flowIDUsedCount, m.flowIDExhaust, m.startupPreviousRoundFlowDeleted}
	if config.EnableMs {
		klog.Infof("Register ms metrics for enabled ms")
		res = append(res, m.arpCount, m.arpRejectCount, m.ruleEntryTotalNum, m.ruleEntryNum,
			m.policyGuardEnabled,
			m.policyMemoryBreakerOpen,
			m.policyMemoryBreakerOpenTotal,
			m.policyMemoryBreakerRecoverTotal,
			m.policyMemoryBreakerRejectedObjects,
			m.policyMemoryUsageBytes,
			m.policyMemoryThresholdBytes,
			m.policyRuleEstimateLimit,
			m.policyRuleEstimateRejectedValue)
	}
	if config.EnableTR {
		klog.Infof("Register tr metrics for enabled tr")
		res = append(res, m.trHealthy, m.trNicMount, m.trNicStatus)
	}
	return res
}

func (m *AgentMetric) SetPolicyMemoryBreakerOpen(open bool) {
	m.policyMemoryBreakerOpen.WithLabelValues().Set(boolToFloat64(open))
}

func (m *AgentMetric) SetStartupPreviousRoundFlowDeleted(deleted bool) {
	m.startupPreviousRoundFlowDeleted.Set(boolToFloat64(deleted))
}

func (m *AgentMetric) IncPolicyMemoryBreakerOpen(reason string) {
	m.policyMemoryBreakerOpenTotal.WithLabelValues(reason).Inc()
}

func (m *AgentMetric) IncPolicyMemoryBreakerRecover(reason string) {
	m.policyMemoryBreakerRecoverTotal.WithLabelValues(reason).Inc()
}

func (m *AgentMetric) SetPolicyMemoryBreakerRejectedObject(resource, namespace, name, operation, reason string, rejected bool) {
	m.policyMemoryBreakerRejectedObjects.WithLabelValues(resource, namespace, name, operation, reason).Set(boolToFloat64(rejected))
}

func (m *AgentMetric) SetPolicyMemoryInfo(usage, threshold uint64) {
	m.policyMemoryUsageBytes.WithLabelValues().Set(float64(usage))
	m.policyMemoryThresholdBytes.WithLabelValues().Set(float64(threshold))
}

func (m *AgentMetric) SetPolicyRuleEstimateLimit(limit uint64) {
	m.policyRuleEstimateLimit.WithLabelValues().Set(float64(limit))
}

func (m *AgentMetric) SetPolicyGuardEnabled(guardType string, enabled bool) {
	m.policyGuardEnabled.WithLabelValues(guardType).Set(boolToFloat64(enabled))
}

func (m *AgentMetric) SetPolicyRuleEstimateRejectedValue(resource, namespace, name, towerID, operation, reason string, value uint64) {
	m.policyRuleEstimateRejectedValue.WithLabelValues(resource, namespace, name, towerID, operation, reason).Set(float64(value))
}

func (m *AgentMetric) DeletePolicyRuleEstimateRejectedValue(resource, namespace, name, operation, reason string) {
	m.policyRuleEstimateRejectedValue.DeletePartialMatch(prometheus.Labels{
		"resource":  resource,
		"namespace": namespace,
		"name":      name,
		"operation": operation,
		"reason":    reason,
	})
}

func (m *AgentMetric) SetSeqIDInfo(module string, exhaust bool, used int) {
	exhF := float64(0)
	if exhaust {
		exhF = 1
	}
	m.flowIDExhaust.WithLabelValues(module).Set(exhF)
	m.flowIDUsedCount.WithLabelValues(module).Set(float64(used))
}

func (m *AgentMetric) SetTRNicInfo(bridge string, trNic TRNicInfo, allHealthy bool) {
	m.trNicMount.WithLabelValues(bridge, "nic_in").Set(float64(trNic.NicInMount))
	m.trNicMount.WithLabelValues(bridge, "nic_out").Set(float64(trNic.NicOutMount))
	m.trNicMount.WithLabelValues(bridge, "nic_all").Set(float64(trNic.NicMount))
	m.trNicStatus.WithLabelValues(bridge, "nic_in").Set(float64(trNic.NicInStatus))
	m.trNicStatus.WithLabelValues(bridge, "nic_out").Set(float64(trNic.NicOutStatus))
	m.trHealthy.WithLabelValues(bridge, "all").Set(boolToFloat64(allHealthy))
}

func (m *AgentMetric) SetTRHealthy(bridge string, dpi, all bool) {
	m.trHealthy.WithLabelValues(bridge, "dpi").Set(boolToFloat64(dpi))
	m.trHealthy.WithLabelValues(bridge, "all").Set(boolToFloat64(all))
}

func boolToFloat64(in bool) float64 {
	res := float64(0)
	if in {
		res = 1
	}
	return res
}

type TRNicInfo struct {
	NicInMount   int
	NicOutMount  int
	NicMount     int
	NicInStatus  uint8
	NicOutStatus uint8
}
