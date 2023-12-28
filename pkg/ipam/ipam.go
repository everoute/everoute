package ipam

import (
	"context"

	"github.com/containernetworking/cni/pkg/types"
	cnitypes "github.com/containernetworking/cni/pkg/types/100"

	"github.com/everoute/everoute/pkg/utils"
)

type IPAM interface {
	ExecAdd(context.Context, *types.NetConf, *utils.CNIArgs) (*cnitypes.Result, error)
	ExecDel(context.Context, *types.NetConf, *utils.CNIArgs) error
	ExecCheck(context.Context, *types.NetConf, *utils.CNIArgs) error
}
