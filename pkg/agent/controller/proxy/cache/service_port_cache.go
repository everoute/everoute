package cache

import "k8s.io/client-go/tools/cache"

type SvcPort struct {
	Name      string
	Namespace string
	PortName  string
	SvcName   string
}

func NewSvcPortCache() cache.Indexer {
	return cache.NewIndexer(
		svcPortKeyFunc,
		cache.Indexers{},
	)
}

func GenSvcPortKey(ns, name string) string {
	return ns + "/" + name
}

func svcPortKeyFunc(obj interface{}) (string, error) {
	return obj.(*SvcPort).Namespace + "/" + obj.(*SvcPort).Name, nil
}
