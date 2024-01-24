package ipam

import (
	"context"

	"github.com/containernetworking/cni/pkg/types"
	cnitypes "github.com/containernetworking/cni/pkg/types/100"

	etypes "github.com/everoute/everoute/pkg/types"
)

type IPAM interface {
	ExecAdd(context.Context, *types.NetConf, *etypes.CNIArgs) (*cnitypes.Result, error)
	ExecDel(context.Context, *types.NetConf, *etypes.CNIArgs) error
	ExecCheck(context.Context, *types.NetConf, *etypes.CNIArgs) error
}
