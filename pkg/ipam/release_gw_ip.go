package ipam

import (
	"context"

	ipamv1alpha1 "github.com/everoute/ipam/api/ipam/v1alpha1"
	"github.com/everoute/ipam/pkg/cron"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/klog/v2"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/everoute/everoute/pkg/apis/security/v1alpha1"
	"github.com/everoute/everoute/pkg/utils"
)

var _ cron.ProcessFun = (&CleanGwStaleIP{}).Process

type CleanGwStaleIP struct {
	PoolNs   string
	PoolName string
	GwEpNs   string
}

func NewCleanStaleIP(poolNs, poolName, gwEpNs string) *CleanGwStaleIP {
	return &CleanGwStaleIP{
		PoolNs:   poolNs,
		PoolName: poolName,
		GwEpNs:   gwEpNs,
	}
}

func (c *CleanGwStaleIP) Process(ctx context.Context, k8sClient client.Client, k8sReader client.Reader) {
	req := types.NamespacedName{
		Namespace: c.PoolNs,
		Name:      c.PoolName,
	}
	pool := ipamv1alpha1.IPPool{}
	if err := k8sClient.Get(ctx, req, &pool); err != nil {
		klog.Errorf("Failed to get ippool %v, err: %v", req, err)
		return
	}
	if len(pool.Status.AllocatedIPs) == 0 {
		return
	}

	delIPs := []string{}
	for ip, a := range pool.Status.AllocatedIPs {
		if a.Type != ipamv1alpha1.AllocateTypeCNIUsed {
			continue
		}
		if c.needReleaseForGw(ctx, k8sClient, k8sReader, a.ID) {
			klog.Infof("Try to release gateway ip %s for node %s", ip, a.ID)
			delIPs = append(delIPs, ip)
		}
	}
	if len(delIPs) == 0 {
		return
	}

	for _, ip := range delIPs {
		delete(pool.Status.AllocatedIPs, ip)
	}
	if err := k8sClient.Status().Update(ctx, &pool); err != nil {
		klog.Errorf("Release gateway ips %v failed: %v", delIPs, err)
		return
	}
	klog.Infof("Success to release gateway ips %v", delIPs)
}

func (c *CleanGwStaleIP) needReleaseForGw(ctx context.Context, k8sClient client.Client, k8sReader client.Reader, nodeName string) bool {
	epReq := types.NamespacedName{
		Namespace: c.GwEpNs,
		Name:      utils.GetGwEndpointName(nodeName),
	}
	ep := v1alpha1.Endpoint{}
	err := k8sClient.Get(ctx, epReq, &ep)
	if err == nil {
		return false
	}
	if !errors.IsNotFound(err) {
		klog.Errorf("Failed to get endpoint %v, err: %v", epReq, err)
		return false
	}

	// is endpoint doesn't exist without cache
	ep = v1alpha1.Endpoint{}
	err = k8sReader.Get(ctx, epReq, &ep)
	if err == nil {
		return false
	}
	if !errors.IsNotFound(err) {
		klog.Errorf("Failed to get endpoint %v, err: %v", epReq, err)
		return false
	}

	// perhaps endpoint wasn't create when the agent start just now
	nodeReq := types.NamespacedName{
		Name: nodeName,
	}
	node := corev1.Node{}
	err = k8sReader.Get(ctx, nodeReq, &node)
	if err == nil {
		return false
	}
	if !errors.IsNotFound(err) {
		klog.Errorf("Failed to get node %v, err: %v", nodeReq, err)
		return false
	}

	return true
}
