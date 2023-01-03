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

package tower

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"sync"

	rthttp "github.com/hashicorp/go-retryablehttp"
	"golang.org/x/crypto/ssh"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/everoute/everoute/plugin/tower/pkg/client"
	"github.com/everoute/everoute/plugin/tower/pkg/informer"
	"github.com/everoute/everoute/tests/e2e/framework/ipam"
	"github.com/everoute/everoute/tests/e2e/framework/model"
	"github.com/everoute/everoute/tests/e2e/framework/node"
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
	vmTemplateID         string
	vmTemplateCachedLock sync.Mutex
	vmTemplateCached     *VMTemplate

	// create vm in the specify vds
	vdsID           string
	mutationVdsLock sync.Mutex

	// concurrent mutation labels cause mistakes
	mutationLabelLock sync.Mutex
}

func NewProvider(pool ipam.Pool, nodeManager *node.Manager, towerClient *client.Client, vmTemplateID, vdsID string) model.EndpointProvider {
	retryClient := rthttp.NewClient()
	retryClient.RetryMax = 10
	retryClient.Logger = nil
	towerClient.HTTPClient = retryClient.StandardClient()

	// add default task monitor for client
	towerFactory := informer.NewSharedInformerFactory(towerClient, 0)
	towerClient.TaskMonitor = informer.NewTaskMonitor(towerFactory)
	towerFactory.Start(make(chan struct{}))

	return &provider{
		ipPool:       pool,
		nodeManager:  nodeManager,
		towerClient:  towerClient,
		vmTemplateID: vmTemplateID,
		vdsID:        vdsID,
	}
}

func (m *provider) Name() string {
	return "tower"
}

func (m *provider) Get(ctx context.Context, name string) (*model.Endpoint, error) {
	clusterID, err := m.getClusterID()
	if err != nil {
		return nil, fmt.Errorf("read cluster id: %s", err)
	}

	vms, err := queryVMs(m.towerClient, &VMWhereInput{Cluster: &ClusterWhereInput{ID: &clusterID}, Name: &name})
	if err != nil {
		return nil, fmt.Errorf("query vms: %s", err)
	}

	switch len(vms) {
	case 0:
		return nil, apierrors.NewNotFound(schema.GroupResource{Group: "tower", Resource: "vm"}, name)
	case 1:
		return m.toEndpoint(&vms[0])
	default:
		return nil, fmt.Errorf("multiple vms with name %s in cluster %s: %+v", name, clusterID, vms)
	}
}

func (m *provider) List(ctx context.Context) ([]*model.Endpoint, error) {
	var epList []*model.Endpoint
	var boolFalse = false

	vmList, err := queryVMs(m.towerClient, &VMWhereInput{InRecycleBin: &boolFalse})
	if err != nil {
		return nil, err
	}

	for _, vm := range vmList {
		if endpoint, err := m.toEndpoint(&vm); err == nil {
			epList = append(epList, endpoint)
		}
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

	vm, err := m.newFromTemplate(endpoint.Name, endpoint.Status.Host, endpoint.VID, description)
	if err != nil {
		return nil, fmt.Errorf("create %s from template %s: %s", endpoint.Name, m.vmTemplateID, err)
	}
	endpoint.Status.LocalID = vm.ID

	err = m.mutationVMLabels(vm.ID, endpoint.Labels)
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

	if err = m.mutationVMLabels(endpoint.Status.LocalID, endpoint.Labels); err != nil {
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
	epList, err := m.List(ctx)
	if err != nil {
		return err
	}

	for _, ep := range epList {
		// find endpoint by name
		if ep.Name != name || ep.Status.LocalID == "" {
			continue
		}
		_, err = mutationDeleteVM(m.towerClient, &VMWhereUniqueInput{ID: &ep.Status.LocalID})
		if err != nil {
			return err
		}
	}

	return nil
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
	ep, err := m.Get(ctx, name)
	if err != nil {
		return 0, nil, err
	}

	client, domain, err := m.getGuestExecPath(ctx, ep.Status.LocalID)
	if err != nil {
		return 0, nil, fmt.Errorf("failed to get client: %s", err)
	}

	// $ bash -s [arg ...] <<< 'script'
	return execContext(ctx, client, domain, "bash", script, append([]string{"-s"}, arg...)...)
}

func (m *provider) RunCommand(ctx context.Context, name string, cmd string, arg ...string) (int, []byte, error) {
	ep, err := m.Get(ctx, name)
	if err != nil {
		return 0, nil, err
	}

	client, domain, err := m.getGuestExecPath(ctx, ep.Status.LocalID)
	if err != nil {
		return 0, nil, fmt.Errorf("failed to get client: %s", err)
	}

	return execContext(ctx, client, domain, cmd, nil, arg...)
}

func (m *provider) newFromTemplate(name string, agent string, vlanID int, describe string) (*VM, error) {
	var err error
	var vlanUUID string

	if err = m.cacheVMTemplate(); err != nil {
		return nil, err
	}
	if vlanUUID, err = m.mutationQueryVlan(context.TODO(), vlanID); err != nil {
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

	var mode = VMNicModelVirtio
	var enable = true
	vmCreateInput.VMNics.Create = []VMNicCreateWithoutVMInput{
		{
			Enabled: &enable,
			LocalID: "",
			Model:   &mode,
			Vlan:    &ConnectInput{&UniqueInput{ID: &vlanUUID}},
		},
	}

	return mutationCreateVM(m.towerClient, &vmCreateInput, &vmCreateEffect)
}

func (m *provider) mutationVMLabels(vmID string, labels map[string][]string) error {
	var errList []error

	m.mutationLabelLock.Lock()
	defer m.mutationLabelLock.Unlock()

	allTowerLabels, err := queryLabels(m.towerClient)
	if err != nil {
		return fmt.Errorf("failed to query labels: %s", err)
	}

	for key, valueSet := range labels {
		for _, value := range valueSet {
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
	}

	// disconnect vm from label if vm don't have the label
	for _, label := range allTowerLabels {
		if valueSet, ok := labels[label.Key]; !ok || sets.NewString(valueSet...).Has(label.Value) {
			if vm := findVMByID(label.VMs, vmID); vm == nil {
				continue
			}
			_, err = mutationUpdateLabel(m.towerClient, &LabelUpdateInput{VMs: ConnectManyInput{Disconnect: []UniqueInput{{ID: &vmID}}}}, &LabelWhereUniqueInput{ID: &label.ID})
			errList = append(errList, err)
		}
	}

	return errors.NewAggregate(errList)
}

// mutationQueryVlan find vlan by id. If not found, it will be create.
func (m *provider) mutationQueryVlan(ctx context.Context, vlanID int) (string, error) {
	m.mutationVdsLock.Lock()
	defer m.mutationVdsLock.Unlock()

	if vlanID < 0 || vlanID > 4095 {
		return "", fmt.Errorf("valide vlan id must between 0-4095")
	}

	var vlanUUID string
	if towerVlans, err := queryVlans(m.towerClient); err == nil {
		for _, vlan := range towerVlans {
			if !strings.Contains(vlan.LocalID, "_") || vlan.Type != NetworkTypeVM {
				// filter out invalid vlan
				continue
			}
			if vlan.Vds.ID == m.vdsID && vlan.VlanID == vlanID {
				vlanUUID = vlan.ID
				break
			}
		}
	} else {
		return "", fmt.Errorf("failed to query vlans: %s", err)
	}

	if vlanUUID == "" {
		vlan, err := adaptMutationCreateVlan(m.towerClient, &VlanCreateInput{
			Name:   fmt.Sprintf("vlan%d", vlanID),
			Type:   NetworkTypeVM,
			Vds:    &ConnectInput{Connect: &UniqueInput{ID: &m.vdsID}},
			VlanID: vlanID,
		})
		if err != nil {
			return "", fmt.Errorf("failed to create vlan: %s", err)
		}
		vlanUUID = vlan.ID
	}

	return vlanUUID, nil
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

func (m *provider) getGuestExecPath(ctx context.Context, vmID string) (*ssh.Client, string, error) {
	vm, err := queryVM(m.towerClient, &VMWhereUniqueInput{ID: &vmID})
	if err != nil {
		return nil, "", err
	}

	agent, err := m.nodeManager.GetAgent(vm.Host.ID)
	if err != nil {
		return nil, "", fmt.Errorf("get guest %s client: %s", vmID, err)
	}

	client, err := agent.GetClient()
	if err != nil {
		return nil, "", fmt.Errorf("get guest %s client: %s", vmID, err)
	}

	return client, vm.LocalID, nil
}

func (m *provider) completeRandomStatus(endpoint *model.Endpoint) error {
	if endpoint.Status == nil {
		endpoint.Status = &model.EndpointStatus{}
	}

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

		ip link set lo up
		ip link set ${vethName} up

		realIP=$(ip addr show ${vethName} | grep -Eo '([0-9]*\.){3}[0-9]*/[0-9]*' || true)
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

	return endpoint, nil
}

func (m *provider) getClusterID() (string, error) {
	// read cluster id from vm template
	if err := m.cacheVMTemplate(); err != nil {
		return "", err
	}
	return m.vmTemplateCached.Cluster.ID, nil
}

/*
	endpointProvider is designed as a stateless application, so we store endpoint info into vm.description
*/
func (m *provider) toEndpoint(vm *VM) (*model.Endpoint, error) {
	var endpoint *model.Endpoint
	err := json.NewDecoder(bytes.NewBufferString(vm.Description)).Decode(&endpoint)
	if err != nil {
		return nil, err
	}
	if endpoint.Status.LocalID == "" {
		endpoint.Status.LocalID = vm.ID
	}
	return endpoint, nil
}

func (m *provider) endpointIntoDescription(vm *model.Endpoint) (string, error) {
	var description bytes.Buffer
	err := json.NewEncoder(&description).Encode(vm)
	return description.String(), err
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
