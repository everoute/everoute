package metrics

import (
	"context"
	"sync"

	"github.com/prometheus/client_golang/prometheus"

	constants "github.com/everoute/everoute/pkg/constants/ms"
)

type PolicyInfoMetric struct {
	lock sync.Mutex
	data *prometheus.GaugeVec
}

func NewPolicyInfoMetric() *PolicyInfoMetric {
	return &PolicyInfoMetric{
		data: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: constants.MetricNamespace,
			Subsystem: constants.MetricSubSystem,
			Name:      "policy_info",
			Help:      "The display information of SecurityPolicy for policy guard alerts",
		}, []string{"namespace", "name", "display_name"}),
	}
}

func (m *PolicyInfoMetric) Set(namespace, name, displayName string) {
	if m == nil {
		return
	}
	if displayName == "" {
		displayName = name
	}

	m.lock.Lock()
	defer m.lock.Unlock()

	m.delete(namespace, name)
	m.data.WithLabelValues(namespace, name, displayName).Set(1)
}

func (m *PolicyInfoMetric) Delete(namespace, name string) {
	if m == nil {
		return
	}
	m.lock.Lock()
	defer m.lock.Unlock()

	m.delete(namespace, name)
}

func (m *PolicyInfoMetric) delete(namespace, name string) {
	m.data.DeletePartialMatch(prometheus.Labels{
		"namespace": namespace,
		"name":      name,
	})
}

type ControllerActiveMetric struct {
	data *prometheus.GaugeVec
}

func NewControllerActiveMetric() *ControllerActiveMetric {
	return &ControllerActiveMetric{
		data: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: constants.MetricNamespace,
			Subsystem: constants.MetricSubSystem,
			Name:      "controller_active",
			Help:      "Whether this controller instance is active",
		}, nil),
	}
}

func (m *ControllerActiveMetric) SetActive(active bool) {
	if m == nil {
		return
	}
	m.data.WithLabelValues().Set(boolToFloat64(active))
}

func (m *ControllerActiveMetric) Start(ctx context.Context) error {
	m.SetActive(true)
	<-ctx.Done()
	m.SetActive(false)
	return nil
}

func (m *ControllerActiveMetric) NeedLeaderElection() bool {
	return true
}
