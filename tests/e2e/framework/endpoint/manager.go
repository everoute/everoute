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

package endpoint

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"

	"k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/klog"

	"github.com/everoute/everoute/pkg/client/clientset_generated/clientset"
	"github.com/everoute/everoute/tests/e2e/framework/config"
	"github.com/everoute/everoute/tests/e2e/framework/endpoint/netns"
	"github.com/everoute/everoute/tests/e2e/framework/endpoint/tower"
	"github.com/everoute/everoute/tests/e2e/framework/ipam"
	"github.com/everoute/everoute/tests/e2e/framework/model"
	"github.com/everoute/everoute/tests/e2e/framework/node"
)

type Manager struct {
	model.EndpointProvider
}

func NewManager(pool ipam.Pool, namespace string, nodeManager *node.Manager, config *config.EndpointConfig) *Manager {
	var provider model.EndpointProvider

	switch {
	case config.Provider == nil, *config.Provider == "netns":
		crdClient := clientset.NewForConfigOrDie(config.KubeConfig)
		provider = netns.NewProvider(pool, namespace, nodeManager, crdClient)

	case *config.Provider == "tower":
		provider = tower.NewProvider(pool, nodeManager, config.TowerClient, *config.VMTemplateID, *config.VdsID)

	default:
		panic("unknown provider " + *config.Provider)
	}

	return &Manager{EndpointProvider: provider}
}

func (m *Manager) SetupMany(ctx context.Context, endpoints ...*model.Endpoint) error {
	return m.concurrentVisit(func(endpoint *model.Endpoint) error {
		klog.Infof("create endpoint %s: %+v", endpoint.Name, endpoint)
		_, err := m.Create(ctx, endpoint)
		return err
	}, endpoints)
}

func (m *Manager) CleanMany(ctx context.Context, endpoints ...*model.Endpoint) error {
	return m.concurrentVisit(func(endpoint *model.Endpoint) error {
		klog.Infof("delete endpoint %s: %+v", endpoint.Name, endpoint)
		return m.Delete(ctx, endpoint.Name)
	}, endpoints)
}

func (m *Manager) UpdateMany(ctx context.Context, endpoints ...*model.Endpoint) error {
	return m.concurrentVisit(func(endpoint *model.Endpoint) error {
		klog.Infof("update endpoint %s: %+v", endpoint.Name, endpoint)
		_, err := m.Update(ctx, endpoint)
		return err
	}, endpoints)
}

func (m *Manager) MigrateMany(ctx context.Context, endpoints ...*model.Endpoint) error {
	return m.concurrentVisit(func(endpoint *model.Endpoint) error {
		klog.Infof("migrate endpoint %s: %+v", endpoint.Name, endpoint)
		ep, err := m.Migrate(ctx, endpoint.Name)
		if err == nil {
			// update request endpoint status
			endpoint.Status = ep.Status
		}
		return err
	}, endpoints)
}

func (m *Manager) RenewIPMany(ctx context.Context, endpoints ...*model.Endpoint) error {
	return m.concurrentVisit(func(endpoint *model.Endpoint) error {
		klog.Infof("renew endpoint %s ip: %+v", endpoint.Name, endpoint)
		ep, err := m.RenewIP(ctx, endpoint.Name)
		if err == nil {
			// update request endpoint status
			endpoint.Status = ep.Status
		}
		return err
	}, endpoints)
}

func (m *Manager) ResetResource(ctx context.Context) error {
	var epList []*model.Endpoint
	var err error
	if epList, err = m.List(ctx); err != nil {
		return err
	}
	return m.CleanMany(ctx, epList...)
}

func (m *Manager) Reachable(ctx context.Context, src string, dst string, protocol string, port int) (bool, error) {
	var cmd = `net-utils`
	var args []string

	dstEp, err := m.Get(ctx, dst)
	if err != nil {
		return false, fmt.Errorf("unable get dest endpoint: %s", err)
	}

	ip, _, err := net.ParseCIDR(dstEp.Status.IPAddr)
	if err != nil {
		return false, fmt.Errorf("unexpect ipaddr %s of %s", dstEp.Status.IPAddr, dstEp.Name)
	}

	switch strings.ToUpper(protocol) {
	case "TCP", "UDP":
		args = []string{`connect`, `--protocol`, protocol, `--timeout`, "1s", `--server`, fmt.Sprintf("%s:%d", ip, port)}
	case "ICMP":
		args = []string{`connect`, `--protocol`, protocol, `--timeout`, "1s", `--server`, ip.String()}
	case "FTP":
		args = []string{`connect`, `--protocol`, protocol, `--server`, ip.String()}
	default:
		return false, fmt.Errorf("unknow protocol %s", protocol)
	}

	rc, out, err := m.RunCommand(ctx, src, cmd, args...)
	klog.Infof("connect from %s to %s, command: net-utils %s, result: %s", src, dst, strings.Join(args, " "), string(out))

	return rc == 0, err
}

func (m *Manager) ReachTruthTable(ctx context.Context, protocol string, port int) (*model.TruthTable, error) {
	// The concurrency depends on the number of sessions configured by sshd
	var limitChan = make(chan struct{}, 6)

	endpoints, err := m.List(ctx)
	if err != nil {
		return nil, err
	}
	endpointNames := make([]string, 0, len(endpoints))
	for _, ep := range endpoints {
		endpointNames = append(endpointNames, ep.Name)
	}
	tt := model.NewTruthTableFromItems(endpointNames, nil)

	err = m.concurrentVisit(func(srcEp *model.Endpoint) error {
		return m.concurrentVisit(func(dstEp *model.Endpoint) error {
			limitChan <- struct{}{}
			defer func() { <-limitChan }()

			reach, err := m.Reachable(ctx, srcEp.Name, dstEp.Name, protocol, port)
			tt.Set(srcEp.Name, dstEp.Name, err == nil && reach)
			return err
		}, endpoints)
	}, endpoints)

	return tt, err
}

func (m *Manager) concurrentVisit(visitor func(*model.Endpoint) error, endpoints []*model.Endpoint) error {
	var errList = make([]error, len(endpoints))
	var wg = sync.WaitGroup{}

	for index, endpoint := range endpoints {
		wg.Add(1)
		go func(index int, endpoint *model.Endpoint) {
			defer wg.Done()
			errList[index] = visitor(endpoint)
		}(index, endpoint)
	}

	wg.Wait()
	return errors.NewAggregate(errList)
}
