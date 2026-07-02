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
	reg                        *prometheus.Registry
	ipM                        *IPMigrateCount
	endpointGroupInfo          *EndpointGroupInfoMetric
	endpointGroupSecurityGroup *EndpointGroupSecurityGroupMetric
	controllerActive           *ControllerActiveMetric
}

func NewControllerMetric() *ControllerMetric {
	return &ControllerMetric{
		reg:                        prometheus.NewRegistry(),
		ipM:                        NewIPMigrateCount(),
		endpointGroupInfo:          NewEndpointGroupInfoMetric(),
		endpointGroupSecurityGroup: NewEndpointGroupSecurityGroupMetric(),
		controllerActive:           NewControllerActiveMetric(),
	}
}

func (c *ControllerMetric) Init() {
	if err := c.reg.Register(c.ipM.data); err != nil {
		klog.Fatalf("Failed to init controllerMetric %s", err)
	}
	if err := c.reg.Register(c.endpointGroupInfo.data); err != nil {
		klog.Fatalf("Failed to init endpointGroupInfo metric %s", err)
	}
	if err := c.reg.Register(c.endpointGroupSecurityGroup.data); err != nil {
		klog.Fatalf("Failed to init endpointGroupSecurityGroup metric %s", err)
	}
	if err := c.reg.Register(c.controllerActive.data); err != nil {
		klog.Fatalf("Failed to init controllerActive metric %s", err)
	}
}

func (c *ControllerMetric) GetIPMigrateCount() *IPMigrateCount {
	return c.ipM
}

func (c *ControllerMetric) GetEndpointGroupInfo() *EndpointGroupInfoMetric {
	return c.endpointGroupInfo
}

func (c *ControllerMetric) GetEndpointGroupSecurityGroup() *EndpointGroupSecurityGroupMetric {
	return c.endpointGroupSecurityGroup
}

func (c *ControllerMetric) GetControllerActive() *ControllerActiveMetric {
	return c.controllerActive
}

func (c *ControllerMetric) InstallHandler(registryFunc func(path string, handler http.Handler)) {
	registryFunc(constants.MetricPath, promhttp.HandlerFor(c.reg, promhttp.HandlerOpts{
		ErrorHandling: promhttp.HTTPErrorOnError}))
}

func (c *ControllerMetric) Run(ctx context.Context) {
	c.ipM.Run(ctx)
}
