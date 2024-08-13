package metrics

import (
	"context"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	klog "k8s.io/klog/v2"

	constants "github.com/everoute/everoute/pkg/constants/ms"
)

type ControllerMetric struct {
	reg *prometheus.Registry
	ipM *IPMigrateCount
}

func NewControllerMetric() *ControllerMetric {
	return &ControllerMetric{
		reg: prometheus.NewRegistry(),
		ipM: NewIPMigrateCount(),
	}
}

func (c *ControllerMetric) Init() {
	if err := c.reg.Register(c.ipM.data); err != nil {
		klog.Fatalf("Failed to init controllerMetric %s", err)
	}
}

func (c *ControllerMetric) GetIPMigrateCount() *IPMigrateCount {
	return c.ipM
}

func (c *ControllerMetric) InstallHandler(registryFunc func(path string, handler http.Handler)) {
	registryFunc(constants.MetricPath, promhttp.HandlerFor(c.reg, promhttp.HandlerOpts{
		ErrorHandling: promhttp.HTTPErrorOnError}))
}

func (c *ControllerMetric) Run(ctx context.Context) {
	c.ipM.Run(ctx)
}
