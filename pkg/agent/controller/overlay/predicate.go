package overlay

import (
	corev1 "k8s.io/api/core/v1"
	"k8s.io/klog"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	"github.com/everoute/everoute/pkg/apis/security/v1alpha1"
	"github.com/everoute/everoute/pkg/types"
	"github.com/everoute/everoute/pkg/utils"
)

func endpointPredicate() predicate.Predicate {
	return predicate.Funcs{
		CreateFunc: func(e event.CreateEvent) bool {
			o, ok := e.Object.(*v1alpha1.Endpoint)
			if !ok {
				klog.Errorf("Endpoint create event transform to endpoint resource failed, event: %v", e)
				return false
			}
			if len(o.Status.IPs) != 0 && len(o.Status.Agents) != 0 {
				return true
			}
			return false
		},
		UpdateFunc: func(e event.UpdateEvent) bool {
			newObj, newOk := e.ObjectNew.(*v1alpha1.Endpoint)
			oldObj, oldOk := e.ObjectOld.(*v1alpha1.Endpoint)
			if !newOk || !oldOk {
				klog.Errorf("Endpoint update event transform to endpoint resource failed, event: %v", e)
				return false
			}

			if !endpointIPsEqual(newObj.Status.IPs, oldObj.Status.IPs) {
				return true
			}
			if !endpointAgentsEqual(newObj.Status.Agents, oldObj.Status.Agents) {
				return true
			}
			return false
		},
	}
}

func nodePredicate(localNode string) predicate.Predicate {
	return predicate.Funcs{
		CreateFunc: func(e event.CreateEvent) bool {
			if e.Meta.GetName() == localNode {
				return false
			}
			o, ok := e.Object.(*corev1.Node)
			if !ok {
				klog.Errorf("Node create event transform to node resource failed, event: %v", e)
				return false
			}
			if utils.GetNodeInternalIP(o) != "" {
				return true
			}
			return false
		},
		UpdateFunc: func(e event.UpdateEvent) bool {
			if e.MetaNew.GetName() == localNode {
				return false
			}
			oldObj, oldOk := e.ObjectOld.(*corev1.Node)
			newObj, newOk := e.ObjectNew.(*corev1.Node)
			if !oldOk || !newOk {
				klog.Errorf("Node update event transform to node resource failed, event: %v", e)
				return false
			}
			if utils.GetNodeInternalIP(oldObj) != utils.GetNodeInternalIP(newObj) {
				return true
			}
			return false
		},
		DeleteFunc: func(e event.DeleteEvent) bool {
			return e.Meta.GetName() != localNode
		},
	}
}

func endpointIPsEqual(newIPs, oldIPs []types.IPAddress) bool {
	if len(newIPs) != len(oldIPs) {
		return false
	}

	if len(newIPs) == 0 {
		return true
	}

	for _, new := range newIPs {
		equal := false
		for _, old := range oldIPs {
			if new.String() == old.String() {
				equal = true
				break
			}
		}
		if !equal {
			return false
		}
	}

	return true
}

func endpointAgentsEqual(newAgents, oldAgents []string) bool {
	if len(newAgents) != len(oldAgents) {
		return false
	}

	if len(newAgents) == 0 {
		return true
	}

	for _, new := range newAgents {
		equal := false
		for _, old := range oldAgents {
			if new == old {
				equal = true
				break
			}
		}
		if !equal {
			return false
		}
	}

	return true
}
