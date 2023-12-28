package ipam

import (
	"context"
	"net"

	"github.com/containernetworking/cni/pkg/types"
	cnitypes "github.com/containernetworking/cni/pkg/types/100"
	ipamv1alpha1 "github.com/everoute/ipam/api/ipam/v1alpha1"
	ipam "github.com/everoute/ipam/pkg/ipam"
	"k8s.io/klog"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/everoute/everoute/pkg/utils"
)

type EverouteIPAM struct {
	ipam      *ipam.Ipam
	gateway   net.IP
	k8sClient client.Client
}

func NewEverouteIPAM(k8sclient client.Client, ippoolNs string, gateway net.IP) IPAM {
	return &EverouteIPAM{
		ipam:      ipam.InitIpam(k8sclient, ippoolNs),
		gateway:   gateway,
		k8sClient: k8sclient,
	}
}

func (i *EverouteIPAM) ExecAdd(ctx context.Context, _ *types.NetConf, args *utils.CNIArgs) (*cnitypes.Result, error) {
	ipamConf := &ipam.NetConf{
		Type:             ipamv1alpha1.AllocateTypePod,
		AllocateIdentify: string(args.K8S_POD_INFRA_CONTAINER_ID),
		K8sPodName:       string(args.K8S_POD_NAME),
		K8sPodNs:         string(args.K8S_POD_NAMESPACE),
	}
	if err := ipamConf.Complete(ctx, i.k8sClient, i.ipam.GetNamespace()); err != nil {
		klog.Errorf("Failed to complete ipam conf, err: %v", err)
		return nil, err
	}

	r, err := i.ipam.ExecAdd(ctx, ipamConf)
	if err != nil {
		klog.Errorf("Failed to allocate ip, err: %v", err)
		return nil, err
	}
	r.IPs[0].Gateway = i.gateway
	return r, nil
}

func (i *EverouteIPAM) ExecDel(ctx context.Context, _ *types.NetConf, args *utils.CNIArgs) error {
	// release ips
	ipamConf := &ipam.NetConf{
		Type:             ipamv1alpha1.AllocateTypePod,
		AllocateIdentify: string(args.K8S_POD_INFRA_CONTAINER_ID),
		K8sPodName:       string(args.K8S_POD_NAME),
		K8sPodNs:         string(args.K8S_POD_NAMESPACE),
	}
	if err := i.ipam.ExecDel(ctx, ipamConf); err != nil {
		klog.Errorf("Failed to release ip, err: %v", err)
		return err
	}
	return nil
}

func (*EverouteIPAM) ExecCheck(context.Context, *types.NetConf, *utils.CNIArgs) error { return nil }
