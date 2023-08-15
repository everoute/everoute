package utils

import (
	corev1 "k8s.io/api/core/v1"

	"github.com/everoute/everoute/pkg/constants"
)

func GetGwEndpointName(nodeName string) string {
	return constants.GwEndpointName + "-" + nodeName
}

func GetNodeInternalIP(node corev1.Node) string {
	for _, item := range node.Status.Addresses {
		if item.Type == corev1.NodeInternalIP {
			return item.Address
		}
	}
	return ""
}
