package cache

import (
	"strconv"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/tools/cache"
)

type Backend struct {
	IP              string
	Protocol        corev1.Protocol
	Port            int32
	Node            string
	ServicePortRefs sets.Set[string]
}

func GenServicePortRef(svcNs, svcName, portName string) string {
	// portName is service port name in service spec
	return GenSvcPortIndex(svcNs, svcName, portName)
}

func GenBackendKey(ip string, port int32, protocol corev1.Protocol) string {
	return ip + "-" + strconv.Itoa(int(port)) + "-" + string(protocol)
}

func NewBackendCache() cache.Indexer {
	return cache.NewIndexer(
		backendCacheKeyFunc,
		cache.Indexers{
			SvcPortIndex: servicePortRefIndexFunc,
		},
	)
}

func (b *Backend) DeepCopy() *Backend {
	res := &Backend{
		IP:              b.IP,
		Protocol:        b.Protocol,
		Port:            b.Port,
		Node:            b.Node,
		ServicePortRefs: b.ServicePortRefs.Clone(),
	}
	return res
}

func backendCacheKeyFunc(obj interface{}) (string, error) {
	o := obj.(*Backend)
	return o.IP + "-" + strconv.Itoa(int(o.Port)) + "-" + string(o.Protocol), nil
}

func servicePortRefIndexFunc(obj interface{}) ([]string, error) {
	o := obj.(*Backend)
	return o.ServicePortRefs.UnsortedList(), nil
}
