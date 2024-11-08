package cache

import (
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/tools/cache"
)

type NodeIPs struct {
	Name   string
	IP     string
	PodIPs map[string]sets.Set[string]
}

const EpRefIndex = "EpRefIndex"

func NewNodeIPsCache() cache.Indexer {
	return cache.NewIndexer(
		keyFunc,
		cache.Indexers{
			EpRefIndex: epRefIndexFunc,
		},
	)
}

func NewNodeIPs(name string) *NodeIPs {
	return &NodeIPs{
		Name:   name,
		PodIPs: make(map[string]sets.Set[string]),
	}
}

func GenEpRefIndex(ns, name string) string {
	return ns + "/" + name
}

func (n *NodeIPs) ListPodIPs() []string {
	res := make([]string, 0, len(n.PodIPs))
	for _, v := range n.PodIPs {
		res = append(res, v.UnsortedList()...)
	}

	return res
}

func (n *NodeIPs) DeepCopy() *NodeIPs {
	res := NewNodeIPs(n.Name)
	res.IP = n.IP
	for k, v := range n.PodIPs {
		res.PodIPs[k] = v.Clone()
	}

	return res
}

func epRefIndexFunc(obj interface{}) ([]string, error) {
	o := obj.(*NodeIPs)
	eps := make([]string, 0, len(o.PodIPs))
	for k := range o.PodIPs {
		eps = append(eps, k)
	}

	return eps, nil
}

func keyFunc(obj interface{}) (string, error) {
	o := obj.(*NodeIPs)
	return o.Name, nil
}
