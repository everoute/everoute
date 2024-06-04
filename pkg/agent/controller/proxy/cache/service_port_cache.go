package cache

import (
	"k8s.io/client-go/tools/cache"

	everoutesvc "github.com/everoute/everoute/pkg/apis/service/v1alpha1"
)

type SvcPort struct {
	Name      string
	Namespace string
	PortName  string
	SvcName   string
}

func (s *SvcPort) DeepCopy() *SvcPort {
	res := &SvcPort{}
	*res = *s
	return res
}

func NewSvcPortCache() cache.Indexer {
	return cache.NewIndexer(
		svcPortKeyFunc,
		cache.Indexers{
			SvcPortIndex: portNameIndexFunc,
			SvcIDIndex: func(obj interface{}) ([]string, error) {
				return []string{obj.(*SvcPort).SvcName}, nil
			},
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
	return []string{GenSvcPortIndex(o.Namespace, o.SvcName, o.PortName)}, nil
}
