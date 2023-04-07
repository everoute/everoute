package cache

import (
	"k8s.io/client-go/tools/cache"

	everoutesvc "github.com/everoute/everoute/pkg/apis/service/v1alpha1"
)

const PortNameIndex = "PortNameIndex"

type SvcPort struct {
	Name      string
	Namespace string
	PortName  string
	SvcName   string
}

func NewSvcPortCache() cache.Indexer {
	return cache.NewIndexer(
		svcPortKeyFunc,
		cache.Indexers{
			PortNameIndex: portNameIndexFunc,
		},
	)
}

func GenSvcPortKey(ns, name string) string {
	return ns + "/" + name
}

func GenSvcPortFromServicePort(servicePort *everoutesvc.ServicePort) *SvcPort {
	if servicePort == nil {
		return nil
	}

	return &SvcPort{
		Name:      servicePort.GetName(),
		Namespace: servicePort.GetNamespace(),
		PortName:  servicePort.Spec.PortName,
		SvcName:   servicePort.Spec.SvcRef,
	}
}

func svcPortKeyFunc(obj interface{}) (string, error) {
	return obj.(*SvcPort).Namespace + "/" + obj.(*SvcPort).Name, nil
}

func portNameIndexFunc(obj interface{}) ([]string, error) {
	o := obj.(*SvcPort)
	return []string{o.Namespace + "/" + o.SvcName + "/" + o.PortName}, nil
}
