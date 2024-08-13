package utils

import (
	corev1 "k8s.io/api/core/v1"

	constants "github.com/everoute/everoute/pkg/constants/cni"
)

func GetGwEndpointName(nodeName string) string {
	return constants.GwEpNamePrefix + "-" + nodeName
}

func GetNodeInternalIP(node *corev1.Node) string {
	if node == nil {
		return ""
	}
	for _, item := range node.Status.Addresses {
		if item.Type == corev1.NodeInternalIP {
			return item.Address
		}
	}
	return ""
}
