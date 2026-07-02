package metrics

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"

	constants "github.com/everoute/everoute/pkg/constants/ms"
)

const (
	EndpointGroupTargetTypePod     = "pod"
	EndpointGroupTargetTypeVNIC    = "vnic"
	EndpointGroupTargetTypeVMLabel = "vm_label"
	EndpointGroupTargetTypeUnknown = "unknown"

	SecurityGroupTypePod = "pod"
)

type endpointGroupInfoLabels struct {
	name          string
	targetType    string
	targetDisplay string
}

type EndpointGroupInfoMetric struct {
	lock sync.Mutex
	data *prometheus.GaugeVec
	last map[string]endpointGroupInfoLabels
}

func NewEndpointGroupInfoMetric() *EndpointGroupInfoMetric {
	return &EndpointGroupInfoMetric{
		data: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: constants.MetricNamespace,
			Subsystem: constants.MetricSubSystem,
			Name:      "endpointgroup_info",
			Help:      "The display information of EndpointGroup for policy guard alerts",
		}, []string{"name", "target_type", "target_display"}),
		last: make(map[string]endpointGroupInfoLabels),
	}
}

func (m *EndpointGroupInfoMetric) Set(name, targetType, targetDisplay string) {
	if m == nil {
		return
	}
	m.lock.Lock()
	defer m.lock.Unlock()

	if old, ok := m.last[name]; ok && old != (endpointGroupInfoLabels{name: name, targetType: targetType, targetDisplay: targetDisplay}) {
		m.data.DeleteLabelValues(old.name, old.targetType, old.targetDisplay)
	}

	labels := endpointGroupInfoLabels{name: name, targetType: targetType, targetDisplay: targetDisplay}
	m.data.WithLabelValues(labels.name, labels.targetType, labels.targetDisplay).Set(1)
	m.last[name] = labels
}

func (m *EndpointGroupInfoMetric) Delete(name string) {
	if m == nil {
		return
	}
	m.lock.Lock()
	defer m.lock.Unlock()

	if old, ok := m.last[name]; ok {
		m.data.DeleteLabelValues(old.name, old.targetType, old.targetDisplay)
		delete(m.last, name)
	}
}

type EndpointGroupSecurityGroupMetric struct {
	lock sync.Mutex
	data *prometheus.GaugeVec
	last map[string]map[string]struct{}
}

func NewEndpointGroupSecurityGroupMetric() *EndpointGroupSecurityGroupMetric {
	return &EndpointGroupSecurityGroupMetric{
		data: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: constants.MetricNamespace,
			Subsystem: constants.MetricSubSystem,
			Name:      "securitygroup_info",
			Help:      "The Tower SecurityGroup to EndpointGroup mapping for policy guard alerts",
		}, []string{"name", "securitygroup_id", "securitygroup_type"}),
		last: make(map[string]map[string]struct{}),
	}
}

func (m *EndpointGroupSecurityGroupMetric) SetSecurityGroup(securityGroupID string, endpointGroupNames []string) {
	if m == nil {
		return
	}
	m.lock.Lock()
	defer m.lock.Unlock()

	if oldNames, ok := m.last[securityGroupID]; ok {
		for name := range oldNames {
			m.data.DeleteLabelValues(name, securityGroupID, SecurityGroupTypePod)
		}
	}

	nextNames := make(map[string]struct{}, len(endpointGroupNames))
	for _, name := range endpointGroupNames {
		if name == "" {
			continue
		}
		if _, ok := nextNames[name]; ok {
			continue
		}
		m.data.WithLabelValues(name, securityGroupID, SecurityGroupTypePod).Set(1)
		nextNames[name] = struct{}{}
	}
	if len(nextNames) == 0 {
		delete(m.last, securityGroupID)
		return
	}
	m.last[securityGroupID] = nextNames
}

func (m *EndpointGroupSecurityGroupMetric) DeleteSecurityGroup(securityGroupID string) {
	if m == nil {
		return
	}
	m.SetSecurityGroup(securityGroupID, nil)
}
