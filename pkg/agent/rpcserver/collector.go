/*
Copyright 2021 The Everoute Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package rpcserver

import (
	"context"

	"google.golang.org/protobuf/types/known/emptypb"
	"k8s.io/klog"

	"github.com/everoute/everoute/pkg/agent/datapath"
	"github.com/everoute/everoute/pkg/apis/rpc/v1alpha1"
)

type Collector struct {
	dpManager *datapath.DpManager
	stopChan  <-chan struct{}
}

func (c *Collector) ArpStream(req *emptypb.Empty, srv v1alpha1.Collector_ArpStreamServer) error {
	klog.Info("receive collector client, start arp stream")
	for {
		select {
		case arp := <-c.dpManager.ArpChan:
			b, err := arp.MarshalBinary()
			if err != nil {
				continue
			}
			resp := v1alpha1.ArpResponse{
				Pkt: b,
			}
			if err := srv.Send(&resp); err != nil {
				klog.Infof("send error %v", err)
				return nil
			}

		case <-c.stopChan:
			return nil
		}
	}
}

func (c *Collector) GetChainBridge(ctx context.Context, req *emptypb.Empty) (*v1alpha1.ChainBridgeResp, error) {
	resp := &v1alpha1.ChainBridgeResp{
		Bridge: c.dpManager.GetChainBridge(),
	}

	return resp, nil
}

func (c *Collector) Policy(ctx context.Context, req *v1alpha1.PolicyRequest) (*v1alpha1.PolicyResponse, error) {
	policies := c.dpManager.GetPolicyByFlowID(req.FlowIDs...)
	var policyList []*v1alpha1.PolicyList

	for _, p := range policies {
		policy := &v1alpha1.PolicyList{
			Dir:    uint32(p.Dir),
			Action: p.Action,
			Mode:   p.Mode,
		}
		for _, item := range p.Item {
			policy.Items = append(policy.Items, &v1alpha1.PolicyItem{
				Name:       item.Name,
				Namespace:  item.Namespace,
				PolicyType: string(item.PolicyType),
			})
		}
		policyList = append(policyList, policy)
	}

	return &v1alpha1.PolicyResponse{List: policyList}, nil
}

func NewCollectorServer(datapathManager *datapath.DpManager, stopChan <-chan struct{}) *Collector {
	c := &Collector{
		dpManager: datapathManager,
		stopChan:  stopChan,
	}

	return c
}
