package k8s

import (
	corev1 "k8s.io/api/core/v1"

	"github.com/everoute/everoute/pkg/apis/security/v1alpha1"
)

func toNamedPorts(containerPorts []corev1.ContainerPort) []v1alpha1.NamedPort {
	namedPorts := make([]v1alpha1.NamedPort, 0, len(containerPorts))
	for _, item := range containerPorts {
		if item.Protocol == corev1.ProtocolSCTP {
			continue
		}
		namedPort := v1alpha1.NamedPort{
			Name:     item.Name,
			Port:     item.ContainerPort,
			Protocol: v1alpha1.Protocol(item.Protocol),
		}
		namedPorts = append(namedPorts, namedPort)
	}
	return namedPorts
}
