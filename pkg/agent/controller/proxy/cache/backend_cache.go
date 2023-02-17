package cache

import (
	"strconv"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/tools/cache"
)

const ServicePortIndex = "ServicePortIndex"

type Backend struct {
	IP              string
	Protocol        corev1.Protocol
	Port            int32
	Node            string
	ServicePortRefs sets.String
}

func GenBackendKey(ip string, port int32, protocol corev1.Protocol) string {
	return ip + "-" + strconv.Itoa(int(port)) + "-" + string(protocol)
}

func GenServicePortRef(svcNs, svcName, portName string) string {
	return svcNs + "/" + svcName + "/" + portName
}

func NewBackendCache() cache.Indexer {
	return cache.NewIndexer(
		backendCacheKeyFunc,
		cache.Indexers{
			ServicePortIndex: servicePortRefIndexFunc,
		},
	)
}

func backendCacheKeyFunc(obj interface{}) (string, error) {
	o := obj.(*Backend)
	return o.IP + "-" + strconv.Itoa(int(o.Port)) + "-" + string(o.Protocol), nil
}

func servicePortRefIndexFunc(obj interface{}) ([]string, error) {
	o := obj.(*Backend)
	return o.ServicePortRefs.List(), nil
}
