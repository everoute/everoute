package utils

import (
	cnitypes "github.com/containernetworking/cni/pkg/types"
	corev1 "k8s.io/api/core/v1"

	"github.com/everoute/everoute/pkg/constants"
)

type CNIArgs struct {
	cnitypes.CommonArgs
	K8S_POD_NAME               cnitypes.UnmarshallableString //nolint
	K8S_POD_NAMESPACE          cnitypes.UnmarshallableString //nolint
	K8S_POD_INFRA_CONTAINER_ID cnitypes.UnmarshallableString //nolint
}

func GetGwEndpointName(nodeName string) string {
	return constants.GwEndpointName + "-" + nodeName
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
