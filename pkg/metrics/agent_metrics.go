package metrics

import (
	"fmt"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/samber/lo"
	klog "k8s.io/klog/v2"

	securityv1alpha1 "github.com/everoute/everoute/pkg/apis/security/v1alpha1"
	"github.com/everoute/everoute/pkg/constants"
	"github.com/everoute/everoute/plugin/tower/pkg/controller/policy"
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
	ruleEntryLimitNum prometheus.GaugeVec

	policyNameMap map[string]string
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
		ruleEntryLimitNum: *prometheus.NewGaugeVec(newAgentGaugeOpt(
			constants.MetricRuleEntryNumLimit,
			"The count of datapath policy rule for each policy currently limited",
		), []string{constants.MetricRuleEntryPolicyNameLabel}),
		policyNameMap: map[string]string{},
	}
	if err := m.reg.Register(m.arpCount); err != nil {
		klog.Fatalf("Failed to init arp count metric %s", err)
	}

	return m
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

func (m *AgentMetric) ShouldLimit(policyID []string) bool {
	for _, item := range policyID {
		_, ok := m.policyNameMap[item]
		if ok {
			return true
		}
	}
	return false
}

func (m *AgentMetric) ArpInc() {
	m.arpCount.Inc()
}

func (m *AgentMetric) ArpRejectInc() {
	m.arpRejectCount.Inc()
}

func (m *AgentMetric) SetRuleEntryNum(policyID string, num int, limited bool) {
	name, ok := m.policyNameMap[policyID]
	if !ok {
		return
	}
	if limited {
		m.ruleEntryLimitNum.WithLabelValues(name).Set(float64(num))
	} else {
		m.ruleEntryNum.WithLabelValues(name).Set(float64(num))
		m.ruleEntryLimitNum.DeleteLabelValues(name)
	}
}

func (m *AgentMetric) SetRuleEntryTotalNum(num int) {
	m.ruleEntryTotalNum.Set(float64(num))
}

func (m *AgentMetric) GetCollectors() []prometheus.Collector {
	return []prometheus.Collector{m.arpCount, m.arpRejectCount,
		m.ruleEntryTotalNum, m.ruleEntryNum}
}
