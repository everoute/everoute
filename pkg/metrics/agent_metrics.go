package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	klog "k8s.io/klog/v2"

	"github.com/everoute/everoute/pkg/constants"
)

type AgentMetric struct {
	reg *prometheus.Registry

	arpCount       prometheus.Counter
	arpRejectCount prometheus.Counter
}

func newAgentCounterOpt(name, help string) prometheus.CounterOpts {
	return prometheus.CounterOpts{
		Namespace: constants.MetricNamespace,
		Subsystem: constants.MetricSubSystem,
		Name:      name,
		Help:      help,
	}
}

func NewAgentMetric() *AgentMetric {
	m := &AgentMetric{
		reg: prometheus.NewRegistry(),
		arpCount: prometheus.NewCounter(
			newAgentCounterOpt(constants.MetricArpCountName,
				"The count for arp receive from datapath")),
		arpRejectCount: prometheus.NewCounter(
			newAgentCounterOpt(constants.MetricArpRejectCountName,
				"The count for arp receive from datapath but rejected by limiter")),
	}
	if err := m.reg.Register(m.arpCount); err != nil {
		klog.Fatalf("Failed to init arp count metric %s", err)
	}

	return m
}

func (m *AgentMetric) ArpInc() {
	m.arpCount.Inc()
}

func (m *AgentMetric) ArpRejectInc() {
	m.arpRejectCount.Inc()
}

func (m *AgentMetric) GetCollectors() []prometheus.Collector {
	return []prometheus.Collector{m.arpCount, m.arpRejectCount}
}
