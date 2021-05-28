/*
Copyright 2021 The Lynx Authors.

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

package tower

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/klog"

	"github.com/smartxworks/lynx/plugin/tower/pkg/client"
	"github.com/smartxworks/lynx/tests/e2e/framework/ipam"
	"github.com/smartxworks/lynx/tests/e2e/framework/model"
	"github.com/smartxworks/lynx/tests/e2e/framework/node"
)

// provider provide virtual machine from tower as endpoint
type provider struct {
	ipPool      ipam.Pool
	nodeManager *node.Manager

	// towerClient connect to [tower](https://www.smartx.com/cloud-tower/)
	towerClient *client.Client

	// template for create vm. A valid template should meet the following conditions:
	// 1. Template with binary net-utils (build from tests/e2e/tools/net-utils).
	// 2. VMTools has been installed on the vm template.
	// 3. At least one network card should be provide (need vlan info).
	vmTemplateID         string
	vmTemplateCachedLock sync.Mutex
	vmTemplateCached     *VMTemplate

	// vmKeyFunc get vm's tower id from endpoint name
	vmKeyFunc func(name string) string

	// concurrent mutation labels cause mistakes
	mutationLabelLock sync.Mutex
}

func NewProvider(pool ipam.Pool, nodeManager *node.Manager, towerClient *client.Client, vmTemplateID string) model.EndpointProvider {
	return &provider{
		ipPool:       pool,
		nodeManager:  nodeManager,
		towerClient:  towerClient,
		vmTemplateID: vmTemplateID,
		vmKeyFunc:    vmKeyFuncDefault,
	}
}

func (m *provider) Name() string {
	return "tower"
}

func (m *provider) Get(ctx context.Context, name string) (*model.Endpoint, error) {
	var vmID = m.vmKeyFunc(name)

	vm, err := queryVM(m.towerClient, &VMWhereUniqueInput{ID: &vmID})
	if err != nil {
		return nil, err
	}

	return m.endpointFromDescription(vm.Description)
}

func (m *provider) List(ctx context.Context) ([]*model.Endpoint, error) {
	var vmList []VM
	var epList []*model.Endpoint
	var err error

	if vmList, err = queryVMs(m.towerClient); err != nil {
		return nil, err
	}

	for _, vm := range vmList {
		endpoint, err := m.endpointFromDescription(vm.Description)
		if err != nil {
			// not all vm are created for lynx testing
			continue
		}
		epList = append(epList, endpoint)
	}

	return epList, nil
}

func (m *provider) Create(ctx context.Context, endpoint *model.Endpoint) (*model.Endpoint, error) {
	var err error
	var description string

	if err = m.completeRandomStatus(endpoint); err != nil {
		return nil, err
	}

	if description, err = m.endpointIntoDescription(endpoint); err != nil {
		return nil, err
	}

	_, err = m.newFromTemplate(endpoint.Name, endpoint.Status.Host, description)
	if err != nil {
		return nil, fmt.Errorf("create %s from template %s: %s", endpoint.Name, m.vmTemplateID, err)
	}

	err = m.mutationEndpointLabels(endpoint.Name, endpoint.Labels)
	if err != nil {
		return nil, fmt.Errorf("unable update %s labels: %s", endpoint.Name, err)
	}

	return endpoint, m.setupIPAddrPorts(ctx, endpoint)
}

func (m *provider) Update(ctx context.Context, endpoint *model.Endpoint) (*model.Endpoint, error) {
	var old *model.Endpoint
	var err error

	if old, err = m.Get(ctx, endpoint.Name); err != nil {
		return nil, err
	}
	endpoint.Status = old.Status

	if err = m.mutationEndpointLabels(endpoint.Name, endpoint.Labels); err != nil {
		return nil, err
	}

	description, err := m.endpointIntoDescription(endpoint)
	if err != nil {
		return nil, err
	}

	_, err = mutationUpdateVM(m.towerClient, &VMUpdateInput{Description: &description}, &VMWhereUniqueInput{ID: &endpoint.Status.LocalID})
	if err != nil {
		return nil, err
	}

	return endpoint, m.setupIPAddrPorts(ctx, endpoint)
}

func (m *provider) Delete(ctx context.Context, name string) error {
	vmID := m.vmKeyFunc(name)
	_, err := mutationDeleteVM(m.towerClient, &VMWhereUniqueInput{ID: &vmID})
	if err != nil {
		return err
	}
	return m.waitForVMReady(ctx, name)
}

func (m *provider) RenewIP(ctx context.Context, name string) (*model.Endpoint, error) {
	var endpoint *model.Endpoint
	var err error

	if endpoint, err = m.Get(ctx, name); err != nil {
		return nil, err
	}

	// todo: release old ipaddr
	endpoint.Status.IPAddr = ""
	if err = m.completeRandomStatus(endpoint); err != nil {
		return nil, err
	}

	description, err := m.endpointIntoDescription(endpoint)
	if err != nil {
		return nil, err
	}

	_, err = mutationUpdateVM(m.towerClient, &VMUpdateInput{Description: &description}, &VMWhereUniqueInput{ID: &endpoint.Status.LocalID})
	if err != nil {
		return nil, err
	}

	return endpoint, m.setupIPAddrPorts(ctx, endpoint)
}

func (m *provider) Migrate(ctx context.Context, name string) (*model.Endpoint, error) {
	var endpoint *model.Endpoint
	var err error
	var agent *node.Agent

	if endpoint, err = m.Get(ctx, name); err != nil {
		return nil, err
	}

	agent, err = m.nodeManager.GetRandomAgent(endpoint.Status.Host)
	if err != nil {
		return nil, err
	}

	return m.migrateToHost(ctx, endpoint, agent.Name)
}

func (m *provider) RunScript(ctx context.Context, name string, script []byte, arg ...string) (int, []byte, error) {
	err := m.waitForVMReady(ctx, name)
	if err != nil {
		return 0, nil, fmt.Errorf("wait for operation: %s", err)
	}

	client, domain, err := m.getGuestExecPath(ctx, name)
	if err != nil {
		return 0, nil, fmt.Errorf("failed to get client: %s", err)
	}

	// $ bash -s [arg ...] <<< 'script'
	return m.guestExec(ctx, client, domain, "bash", script, append([]string{"-s"}, arg...)...)
}

func (m *provider) RunCommand(ctx context.Context, name string, cmd string, arg ...string) (int, []byte, error) {
	err := m.waitForVMReady(ctx, name)
	if err != nil {
		return 0, nil, fmt.Errorf("wait for operation: %s", err)
	}

	client, domain, err := m.getGuestExecPath(ctx, name)
	if err != nil {
		return 0, nil, fmt.Errorf("failed to get client: %s", err)
	}

	return m.guestExec(ctx, client, domain, cmd, nil, arg...)
}

func (m *provider) newFromTemplate(name string, agent string, describe string) (*VM, error) {
	var err error
	var vmID = m.vmKeyFunc(name)

	if err = m.cacheVMTemplate(); err != nil {
		return nil, err
	}

	vmCreateInput := VMCreateInput{
		ClockOffset:          m.vmTemplateCached.ClockOffset,
		Cluster:              &ConnectInput{Connect: &UniqueInput{ID: &m.vmTemplateCached.Cluster.ID}},
		CPU:                  (*CPUInput)(m.vmTemplateCached.CPU),
		CPUModel:             m.vmTemplateCached.CPUModel,
		Description:          describe,
		Firmware:             m.vmTemplateCached.Firmware,
		Ha:                   m.vmTemplateCached.Ha,
		Host:                 &ConnectInput{Connect: &UniqueInput{ID: &agent}},
		ID:                   &vmID,
		InRecycleBin:         false,
		Internal:             false,
		Ips:                  "",
		LocalID:              "",
		Memory:               m.vmTemplateCached.Memory,
		Name:                 name,
		NestedVirtualization: false,
		NodeIP:               "",
		Protected:            false,
		Status:               VMStatusRunning,
		Vcpu:                 m.vmTemplateCached.Vcpu,
		VMDisks:              &VMDiskCreateManyWithoutVMInput{},
		VMNics:               &VMNicCreateManyWithoutVMInput{},
		VMToolsStatus:        VMToolsStatusRunning,
		WinOpt:               false,
	}

	vmCreateEffect := CreateVMEffect{
		CreatedFromTemplateID: &m.vmTemplateID,
	}

	for index, disk := range m.vmTemplateCached.VMDisks {
		diskCreateInput := VMDiskCreateWithoutVMInput{
			Boot:  index,
			Bus:   disk.Bus,
			Type:  disk.Type,
			Index: &index,
			VMVolume: &VMVolumeCreateOneWithoutVMDisksInput{&VMVolumeCreateWithoutVMDisksInput{
				Cluster:          &ConnectInput{&UniqueInput{ID: &m.vmTemplateCached.Cluster.ID}},
				ElfStoragePolicy: VMVolumeElfStoragePolicyTypeReplica2ThinProvision,
				LocalCreatedAt:   "",
				LocalID:          "",
				Mounting:         true,
				Name:             fmt.Sprintf("%s-%d", name, index),
				Path:             disk.Path,
				Sharing:          false,
				Size:             disk.Size,
			}},
		}
		vmCreateInput.VMDisks.Create = append(vmCreateInput.VMDisks.Create, diskCreateInput)
	}

	for _, vmNic := range m.vmTemplateCached.VMNics {
		var mode = VMNicModelVirtio
		var enable = true
		vmNicCreateInput := VMNicCreateWithoutVMInput{
			Enabled: &enable,
			LocalID: "",
			Model:   &mode,
			Vlan:    &ConnectInput{&UniqueInput{LocalID: &vmNic.Vlan.VlanLocalID}},
		}
		vmCreateInput.VMNics.Create = append(vmCreateInput.VMNics.Create, vmNicCreateInput)
	}

	return mutationCreateVM(m.towerClient, &vmCreateInput, &vmCreateEffect)
}

func (m *provider) mutationEndpointLabels(name string, labels map[string]string) error {
	m.mutationLabelLock.Lock()
	defer m.mutationLabelLock.Unlock()

	var errList []error
	var vmID = m.vmKeyFunc(name)

	allTowerLabels, err := queryLabels(m.towerClient)
	if err != nil {
		return fmt.Errorf("failed to query labels: %s", err)
	}

	for key, value := range labels {
		if label := findLabelByKeyValue(allTowerLabels, key, value); label != nil {
			if vm := findVMByID(label.VMs, vmID); vm != nil {
				// the vm already has this label
				continue
			}
			_, err = mutationUpdateLabel(m.towerClient, &LabelUpdateInput{VMs: ConnectManyInput{Connect: []UniqueInput{{ID: &vmID}}}}, &LabelWhereUniqueInput{ID: &label.ID})
			errList = append(errList, err)
		} else {
			_, err = mutationCreateLabel(m.towerClient, &LabelCreateInput{Key: key, Value: &value, VMs: ConnectManyInput{Connect: []UniqueInput{{ID: &vmID}}}})
			errList = append(errList, err)
		}
	}

	// disconnect vm from label if vm don't have the label
	for _, label := range allTowerLabels {
		if value, ok := labels[label.Key]; !(ok || label.Value == value) {
			if vm := findVMByID(label.VMs, vmID); vm == nil {
				continue
			}
			_, err = mutationUpdateLabel(m.towerClient, &LabelUpdateInput{VMs: ConnectManyInput{Disconnect: []UniqueInput{{ID: &vmID}}}}, &LabelWhereUniqueInput{ID: &label.ID})
			errList = append(errList, err)
		}
	}

	return errors.NewAggregate(errList)
}

func (m *provider) waitForVMReady(ctx context.Context, name string) error {
	var vmID = m.vmKeyFunc(name)
	var interval = 100 * time.Millisecond

	for {
		vm, err := queryVM(m.towerClient, &VMWhereUniqueInput{ID: &vmID})
		if err != nil {
			// if not found, operation deleted has completed
			return ignoreNotFound(err)
		}
		if vm.EntityAsyncStatus == nil {
			return nil
		}

		klog.V(8).Infof("waiting for vm %s entityAsyncStatus %s to be ready", vm.Name, *vm.EntityAsyncStatus)

		select {
		case <-ctx.Done():
			return fmt.Errorf("timeout wait for %s ready", name)
		case <-time.After(interval):
		}
	}
}

func (m *provider) cacheVMTemplate() error {
	m.vmTemplateCachedLock.Lock()
	defer m.vmTemplateCachedLock.Unlock()

	if m.vmTemplateCached != nil {
		return nil
	}

	var err error
	m.vmTemplateCached, err = queryVMTemplate(m.towerClient, &VMTemplateWhereUniqueInput{ID: &m.vmTemplateID})
	return err
}

func (m *provider) getGuestExecPath(ctx context.Context, name string) (*ssh.Client, string, error) {
	var vmID = m.vmKeyFunc(name)

	vm, err := queryVM(m.towerClient, &VMWhereUniqueInput{ID: &vmID})
	if err != nil {
		return nil, "", err
	}

	agent, err := m.nodeManager.GetAgent(vm.Host.ID)
	if err != nil {
		return nil, "", fmt.Errorf("get guest %s client: %s", name, err)
	}

	client, err := agent.GetClient()
	if err != nil {
		return nil, "", fmt.Errorf("get guest %s client: %s", name, err)
	}

	return client, vm.LocalID, nil
}

func (m *provider) guestExec(ctx context.Context, client *ssh.Client, domain string, path string, stdin []byte, arg ...string) (int, []byte, error) {
	var timeout time.Duration
	var output []byte

	deadline, ok := ctx.Deadline()
	if ok {
		timeout = time.Until(deadline)
	}

	// wait for vm-tools ready and virsh command succeeded
	err := waitForGuestAgentReady(client, domain, timeout)
	if err != nil {
		return 0, nil, err
	}

	input := base64.StdEncoding.EncodeToString(stdin)
	request := &guestExec{
		Path:          path,
		Arg:           arg,
		InputData:     &input,
		CaptureOutput: true,
	}
	result, err := guestExecWait(client, domain, timeout, request)
	if err != nil {
		return 0, nil, err
	}

	if result.OutData != nil {
		stdout, err := base64.StdEncoding.DecodeString(*result.OutData)
		if err != nil {
			return 0, nil, err
		}
		output = append(output, stdout...)
	}
	if result.ErrData != nil {
		stderr, err := base64.StdEncoding.DecodeString(*result.ErrData)
		if err != nil {
			return 0, nil, err
		}
		output = append(output, stderr...)
	}

	return *result.Exitcode, output, nil
}

func (m *provider) completeRandomStatus(endpoint *model.Endpoint) error {
	if endpoint.Status == nil {
		endpoint.Status = &model.EndpointStatus{}
	}

	endpoint.Status.LocalID = m.vmKeyFunc(endpoint.Name)

	if endpoint.Status.IPAddr == "" {
		ipAddr, err := m.ipPool.AssignFromSubnet(endpoint.ExpectSubnet)
		if err != nil {
			return fmt.Errorf("failed assign ipaddr for %s: %s", endpoint.Name, err)
		}
		endpoint.Status.IPAddr = ipAddr
	}

	if endpoint.Status.Host == "" {
		agent, err := m.nodeManager.GetRandomAgent()
		if err != nil {
			return err
		}
		endpoint.Status.Host = agent.Name
	}

	return nil
}

// setup VM ip address and tcp/udp ports
func (m *provider) setupIPAddrPorts(ctx context.Context, endpoint *model.Endpoint) error {
	updateIPPort := `
		set -o errexit
		set -o pipefail
		set -o nounset
		set -o xtrace

		ipAddr=${1}
		udpPort=${2}
		tcpPort=${3}
		vethName=eth0

		realIP=$(ip addr show ${vethName} | grep -Eo '([0-9]*\.){3}[0-9]*/[0-9]*')
		if [[ "${realIP}" != "${ipAddr}" ]]; then
			ip addr flush ${vethName}
			ip addr add dev ${vethName} ${ipAddr}
		fi

		realCommand=$(ps -o cmd= -p "$(pidof net-utils)" || true)

		expectCommand="net-utils server -d -s"
		if [[ ${tcpPort} != 0 ]]; then
			expectCommand="${expectCommand} --tcp-ports ${tcpPort}"
		fi
		if [[ ${udpPort} != 0 ]]; then
			expectCommand="${expectCommand} --udp-ports ${udpPort}"
		fi

		if [[ "${realCommand}" != "${expectCommand}" ]]; then
		  kill -9 "$(pidof net-utils)" || true
		  eval ${expectCommand}
		fi
	`

	rc, out, err := m.RunScript(ctx, endpoint.Name, []byte(updateIPPort), endpoint.Status.IPAddr, strconv.Itoa(endpoint.UDPPort), strconv.Itoa(endpoint.TCPPort))
	if rc != 0 || err != nil {
		return fmt.Errorf("unexpect result: %s, err: %s", string(out), err)
	}
	return nil
}

func (m *provider) migrateToHost(ctx context.Context, endpoint *model.Endpoint, agent string) (*model.Endpoint, error) {
	if endpoint.Status.Host == agent {
		return nil, fmt.Errorf("try to migrate to self node")
	}
	endpoint.Status.Host = agent

	description, err := m.endpointIntoDescription(endpoint)
	if err != nil {
		return nil, err
	}

	host, err := queryHost(m.towerClient, &HostWhereUniqueInput{ID: &endpoint.Status.Host})
	if err != nil {
		return nil, err
	}

	_, err = mutationUpdateVM(m.towerClient, &VMUpdateInput{Description: &description, NodeIP: &host.DataIP}, &VMWhereUniqueInput{ID: &endpoint.Status.LocalID})
	if err != nil {
		return nil, err
	}

	return endpoint, m.waitForVMReady(ctx, endpoint.Name)
}

/*
	endpointProvider is designed as a stateless application, so we store endpoint info into vm.description
*/
func (m *provider) endpointFromDescription(describe string) (*model.Endpoint, error) {
	var endpoint *model.Endpoint
	err := json.NewDecoder(bytes.NewBufferString(describe)).Decode(&endpoint)
	if err != nil {
		return nil, err
	}
	if endpoint.Name == "" {
		return nil, fmt.Errorf("unexpected endpoint %+v from %s", endpoint, describe)
	}
	return endpoint, nil
}

func (m *provider) endpointIntoDescription(vm *model.Endpoint) (string, error) {
	var description bytes.Buffer
	err := json.NewEncoder(&description).Encode(vm)
	return description.String(), err
}

func vmKeyFuncDefault(name string) string {
	return fmt.Sprintf("lynx%x", sha1.Sum([]byte(name)))[:25]
}

func findLabelByKeyValue(labels []Label, key, value string) *Label {
	for _, label := range labels {
		if label.Key == key && label.Value == value {
			return &label
		}
	}
	return nil
}

func findVMByID(vms []VM, id string) *VM {
	for _, vm := range vms {
		if vm.ID == id {
			return &vm
		}
	}
	return nil
}

func ignoreNotFound(err error) error {
	if apierrors.IsNotFound(err) {
		return nil
	}
	return err
}
