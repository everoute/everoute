package metrics

import (
	"context"

	"github.com/prometheus/client_golang/prometheus"

	constants "github.com/everoute/everoute/pkg/constants/ms"
)

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
