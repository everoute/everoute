package types

import (
	cnitypes "github.com/containernetworking/cni/pkg/types"
)

type CNIArgs struct {
	cnitypes.CommonArgs
	K8S_POD_NAME               cnitypes.UnmarshallableString //nolint
	K8S_POD_NAMESPACE          cnitypes.UnmarshallableString //nolint
	K8S_POD_INFRA_CONTAINER_ID cnitypes.UnmarshallableString //nolint
}
