package proxy

import (
	"net"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/sets"
)

func isNodePortSvc(svc *corev1.Service) bool {
	if svc.Spec.Type == corev1.ServiceTypeNodePort || svc.Spec.Type == corev1.ServiceTypeLoadBalancer {
		return true
	}

	return false
}

func isLbSvc(svc *corev1.Service) bool {
	return svc.Spec.Type == corev1.ServiceTypeLoadBalancer
}

func getNodePortsByProtocol(svc *corev1.Service, protocol corev1.Protocol) sets.Set[int32] {
	res := sets.New[int32]()
	for i := range svc.Spec.Ports {
		if svc.Spec.Ports[i].Protocol == protocol {
			// svc may not be allocated nodeport
			if svc.Spec.Ports[i].NodePort != 0 {
				res.Insert(svc.Spec.Ports[i].NodePort)
			}
		}
	}
	return res
}

func getLBIPPorts(svc *corev1.Service) sets.Set[IPPort] {
	res := sets.New[IPPort]()
	for _, lbIngress := range svc.Status.LoadBalancer.Ingress {
		ipStr := lbIngress.IP
		ip := net.ParseIP(ipStr)
		if ip == nil || ip.To4() == nil {
			continue
		}
		for _, p := range svc.Spec.Ports {
			if p.Protocol != corev1.ProtocolTCP && p.Protocol != corev1.ProtocolUDP {
				continue
			}
			res.Insert(*NewIPPort(ipStr, p.Protocol, p.Port))
		}
	}

	return res
}
