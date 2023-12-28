package ipam

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/containernetworking/cni/pkg/types"
	cnitypes "github.com/containernetworking/cni/pkg/types/100"
	"github.com/containernetworking/plugins/pkg/ipam"
	"github.com/containernetworking/plugins/plugins/ipam/host-local/backend/allocator"
	"k8s.io/klog"

	"github.com/everoute/everoute/pkg/utils"
)

type HostLocalIPAM struct {
	podCIDR []types.IPNet
}

func NewHostLocalIPAM(cidrs []types.IPNet) IPAM {
	return &HostLocalIPAM{
		podCIDR: append([]types.IPNet{}, cidrs...),
	}
}

func (i *HostLocalIPAM) ExecAdd(_ context.Context, conf *types.NetConf, _ *utils.CNIArgs) (*cnitypes.Result, error) {
	r, err := ipam.ExecAdd("host-local", i.GetIpamConfByte(conf))
	if err != nil {
		return nil, err
	}
	ipamResult, err := cnitypes.NewResultFromResult(r)
	if err != nil {
		klog.Errorf("could not convert result, err: %s", err)
		return nil, fmt.Errorf("could not convert ipam result")
	}
	return ipamResult, nil
}

func (i *HostLocalIPAM) ExecDel(_ context.Context, conf *types.NetConf, _ *utils.CNIArgs) error {
	return ipam.ExecDel("host-local", i.GetIpamConfByte(conf))
}

func (i *HostLocalIPAM) ExecCheck(_ context.Context, conf *types.NetConf, _ *utils.CNIArgs) error {
	return ipam.ExecCheck("host-local", i.GetIpamConfByte(conf))
}

func (i *HostLocalIPAM) GetIpamConfByte(conf *types.NetConf) []byte {
	var ipamRanges allocator.RangeSet
	for _, item := range i.podCIDR {
		ipamRanges = append(ipamRanges, allocator.Range{Subnet: item})
	}

	ipamConf := allocator.Net{
		Name:       conf.Name,
		CNIVersion: conf.CNIVersion,
		IPAM: &allocator.IPAMConfig{
			Type:   "host-local",
			Ranges: []allocator.RangeSet{ipamRanges},
		},
		Args: nil,
	}
	ipamByte, _ := json.Marshal(ipamConf)

	return ipamByte
}
