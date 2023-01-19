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

package node

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	errutils "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apimachinery/pkg/util/rand"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/klog"

	"github.com/everoute/everoute/tests/e2e/framework/config"
)

type Node struct {
	// Name is an unique identification of the node
	Name string
	// Roles identifies the type of node
	Roles sets.String
	// User name for connect to this node
	User string
	// Accessible address, such as 192.168.0.1:22
	DialAddr string
	// Methonds for login into. If empty, file ~/.ssh/id_rsa be use.
	AuthMethods []ssh.AuthMethod
	// BridgeName only available when roles contains agent
	BridgeName string

	lock sync.Mutex
	// ssh client connect to this node
	client *ssh.Client
}

const (
	RoleController = "controller"
	RoleAgent      = "agent"
)

// GetClient return client connect to this node, must not close the returned client.
func (n *Node) GetClient() (*ssh.Client, error) {
	n.lock.Lock()
	defer n.lock.Unlock()

	if n.client != nil {
		// return is client alreay create
		return n.client, nil
	}

	var err error
	if n.client, err = n.newClientLocked(); err != nil {
		return nil, err
	}

	return n.client, nil
}

func (n *Node) newClientLocked() (*ssh.Client, error) {
	if n.User == "" {
		n.User = os.Getenv("USER")
	}

	if len(n.AuthMethods) == 0 {
		signer, err := loadLocalSigner()
		if err != nil {
			return nil, err
		}
		n.AuthMethods = append(n.AuthMethods, ssh.PublicKeys(signer))
	}

	return ssh.Dial("tcp", n.DialAddr, &ssh.ClientConfig{
		Config:          ssh.Config{},
		User:            n.User,
		Auth:            n.AuthMethods,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	})
}

func (n *Node) fetchFile(name string) ([]byte, error) {
	rc, out, err := n.runCommand(fmt.Sprintf("cat %s", name))
	if rc != 0 || err != nil {
		return nil, fmt.Errorf("exit code: %d, err: %s", rc, err)
	}
	return out, nil
}

func (n *Node) reRunProcess(name string) error {
	rc, out, err := n.runCommand(fmt.Sprintf("ps -o cmd= -p $(pidof %s)", name))
	if err != nil || rc != 0 {
		return fmt.Errorf("can't found process %s", name)
	}
	processCommand := string(bytes.ReplaceAll(out, []byte{'\n'}, nil))

	rc, out, err = n.runCommand(fmt.Sprintf("kill -9 $(pidof %s)", name))
	if err != nil || rc != 0 {
		return fmt.Errorf("can't kill old process %s", name)
	}

	// check whether the process exists first,
	// will auto restart if it run as service
	time.Sleep(time.Second)
	health, err := n.checkProcess(name)
	if err == nil && health {
		return nil
	}

	session, err := n.newSession()
	if err != nil {
		return err
	}
	defer session.Close()

	// start as daemon, and redirect output to log file
	return session.Start(fmt.Sprintf("%s >> /var/log/%s.log 2>&1", processCommand, name))
}

func (n *Node) checkProcess(name string) (bool, error) {
	rc, out, err := n.runCommand(fmt.Sprintf("pidof %s", name))
	return rc == 0 && len(out) != 0, err
}

func (n *Node) runCommand(cmd string) (int, []byte, error) {
	session, err := n.newSession()
	if err != nil {
		return 0, nil, err
	}
	defer session.Close()

	out, err := session.CombinedOutput(cmd)
	if _, ok := err.(*ssh.ExitError); ok {
		return err.(*ssh.ExitError).ExitStatus(), out, nil
	}
	return 0, out, err
}

func (n *Node) newSession() (*ssh.Session, error) {
	client, err := n.GetClient()
	if err != nil {
		return nil, err
	}
	return client.NewSession()
}

func loadLocalSigner() (ssh.Signer, error) {
	signerFile := filepath.Join(os.Getenv("HOME"), ".ssh", "id_rsa")

	buffer, err := ioutil.ReadFile(signerFile)
	if err != nil {
		return nil, fmt.Errorf("error reading SSH key %s: '%v'", signerFile, err)
	}

	return ssh.ParsePrivateKey(buffer)
}

// Manager manage and cached all nodes
type Manager struct {
	nodeMap                    map[string]*Node
	disableAgentRestarter      bool
	disableControllerRestarter bool
}

func NewManager(disableAgentRestarter, disableControllerRestarter bool, nodes ...*Node) *Manager {
	manager := Manager{
		nodeMap:                    make(map[string]*Node, len(nodes)),
		disableAgentRestarter:      disableAgentRestarter,
		disableControllerRestarter: disableControllerRestarter,
	}

	for _, node := range nodes {
		manager.nodeMap[node.Name] = node
	}

	return &manager
}

func NewManagerFromConfig(nodesConfig *config.NodesConfig) (*Manager, error) {
	var nodes = make([]*Node, 0, len(nodesConfig.Instances))

	for _, nodeConfig := range nodesConfig.Instances {
		node := Node{
			Name:     nodeConfig.Name,
			Roles:    sets.NewString(nodeConfig.Roles...),
			User:     nodeConfig.User,
			DialAddr: nodeConfig.DialAddress,
		}
		if nodeConfig.BridgeName != nil {
			node.BridgeName = *nodeConfig.BridgeName
		}

		if nodeConfig.Password != nil {
			node.AuthMethods = append(node.AuthMethods, ssh.Password(*nodeConfig.Password))
		}

		if nodeConfig.PrivateKeyData != nil {
			keyRaw, err := base64.StdEncoding.DecodeString(*nodeConfig.PrivateKeyData)
			if err != nil {
				return nil, err
			}
			signer, err := ssh.ParsePrivateKey(keyRaw)
			if err != nil {
				return nil, err
			}
			node.AuthMethods = append(node.AuthMethods, ssh.PublicKeys(signer))
		}

		nodes = append(nodes, &node)
	}

	return NewManager(nodesConfig.DisableAgentRestarter, nodesConfig.DisableControllerRestarter, nodes...), nil
}

func (m *Manager) GetAgent(name string) (*Agent, error) {
	node, ok := m.nodeMap[name]
	if ok && node.Roles.Has(RoleAgent) {
		return &Agent{node}, nil
	}
	err := errors.NewNotFound(schema.GroupResource{
		Group:    "externalversion",
		Resource: RoleAgent,
	}, name)
	return nil, err
}

func (m *Manager) GetController(name string) (*Controller, error) {
	node, ok := m.nodeMap[name]
	if ok && node.Roles.Has(RoleController) {
		return &Controller{node}, nil
	}
	err := errors.NewNotFound(schema.GroupResource{
		Group:    "externalversion",
		Resource: RoleController,
	}, name)
	return nil, err
}

func (m *Manager) GetRandomAgent(except ...string) (*Agent, error) {
	var agents []*Agent
	var excepts = sets.NewString(except...)

	for _, node := range m.nodeMap {
		if excepts.Has(node.Name) {
			continue
		}
		agents = append(agents, &Agent{node})
	}

	if len(agents) == 0 {
		return nil, fmt.Errorf("no nodes that match the filter")
	}

	return agents[rand.Intn(len(agents))], nil
}

func (m *Manager) GetRandomController(except ...string) (*Controller, error) {
	var controllers []*Controller
	var excepts = sets.NewString(except...)

	for _, node := range m.nodeMap {
		if excepts.Has(node.Name) {
			continue
		}
		controllers = append(controllers, &Controller{node})
	}

	if len(controllers) == 0 {
		return nil, fmt.Errorf("no nodes that match the filter")
	}

	return controllers[rand.Intn(len(controllers))], nil
}

func (m *Manager) DumpFlowAll() (map[string][]string, error) {
	var errList []error
	var flowMap = make(map[string][]string, len(m.ListAgent()))

	for _, agent := range m.ListAgent() {
		flows, err := agent.DumpFlow()
		flowMap[agent.Name] = flows
		errList = append(errList, err)
	}

	return flowMap, errutils.NewAggregate(errList)
}

func (m *Manager) ListAgent() []*Agent {
	var agents []*Agent
	for _, node := range m.nodeMap {
		if node.Roles.Has(RoleAgent) {
			agents = append(agents, &Agent{node})
		}
	}
	return agents
}

func (m *Manager) ListController() []*Controller {
	var agents []*Controller
	for _, node := range m.nodeMap {
		if node.Roles.Has(RoleController) {
			agents = append(agents, &Controller{node})
		}
	}
	return agents
}

// ServiceRestarter random restart controller and agent when e2e
// Deprecated, we should use external chaos engineering tools to replace restarter
func (m *Manager) ServiceRestarter(minInterval, upwardFloatInterval int) *ServiceRestarter {
	var serviceList []Service

	if !m.disableAgentRestarter {
		for _, agent := range m.ListAgent() {
			serviceList = append(serviceList, agent)
		}
	}

	if !m.disableControllerRestarter {
		for _, controller := range m.ListController() {
			serviceList = append(serviceList, controller)
		}
	}

	return &ServiceRestarter{
		minInterval:         minInterval,
		upwardFloatInterval: upwardFloatInterval,
		serviceList:         serviceList,
		stopSig:             make(chan struct{}),
	}
}

type Service interface {
	GetName() string
	Restart() error
	Healthz() (bool, error)
	FetchLog() ([]byte, error)
}

// ServiceRestarter control automatically restart part of services after every random interval.
type ServiceRestarter struct {
	minInterval         int
	upwardFloatInterval int
	serviceList         []Service
	stopSig             chan struct{}
}

// Run it in another goroutine
func (c *ServiceRestarter) RunAsync() {
	go c.Run()
}

func (c *ServiceRestarter) Run() {
	klog.Info("Service Restarter run!")
	ctx := context.Background()
	firstTime := true
	getMinInterval := func() int {
		if firstTime {
			firstTime = false
			return 0
		}
		return c.minInterval
	}

	for {
		minInterval := getMinInterval()
		select {
		case <-time.After(time.Duration(rand.IntnRange(minInterval, minInterval+c.upwardFloatInterval)) * time.Second):
			for _, service := range c.serviceList {
				if rand.Intn(2) == 0 {
					continue
				}
				klog.Infof("will restart service %s", service.GetName())

				if err := service.Restart(); err != nil {
					log, _ := service.FetchLog()
					klog.Fatalf("failed to restart service %s: %s, log\n: %s", service.GetName(), err, string(log))
				}
			}
		case <-ctx.Done():
			return
		case <-c.stopSig:
			return
		}
	}
}

// stop a living restarter and block here util the restarter is closed
func (c *ServiceRestarter) Stop() {
	klog.Info("Service Restarter Stop!")
	c.stopSig <- struct{}{}
}
