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

package framework

import (
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/rand"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/klog"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"

	agentv1alpha1 "github.com/smartxworks/lynx/pkg/apis/agent/v1alpha1"
	groupv1alpha1 "github.com/smartxworks/lynx/pkg/apis/group/v1alpha1"
	policyv1alpha1 "github.com/smartxworks/lynx/pkg/apis/policyrule/v1alpha1"
	securityv1alpha1 "github.com/smartxworks/lynx/pkg/apis/security/v1alpha1"
)

type Framework struct {
	ctx       context.Context
	k8sClient client.Client

	ipPoolLock sync.RWMutex
	ipPoolCidr string
	ipUsed     map[string]bool // list of ips has been assigned

	agentsLock sync.RWMutex           // agents read/write lock
	agents     []string               // agents name or ip address
	clientMap  map[string]*ssh.Client // agents client map

	timeout  time.Duration
	interval time.Duration
}

func FrameworkFromConfig(configFile string) (*Framework, error) {
	var err error

	var f = &Framework{
		ctx:        context.Background(),
		ipPoolCidr: "10.0.0.0/24",
		ipUsed:     map[string]bool{"10.0.0.0": true, "10.0.0.255": true},
		clientMap:  make(map[string]*ssh.Client),
		timeout:    time.Second * 20,
		interval:   time.Millisecond * 250,
	}

	f.k8sClient, err = client.New(config.GetConfigOrDie(), client.Options{
		Scheme: addLynxToScheme(runtime.NewScheme()),
	})
	if err != nil {
		return nil, err
	}

	if err = f.initAgents(configFile); err != nil {
		return nil, err
	}

	return f, nil
}

type VM struct {
	Name   string
	Labels string

	ExpectCidr string
	TCPPort    int
	UDPPort    int

	status *vmStatus
}

type vmStatus struct {
	ipAddr string
	agent  string
	netns  string
}

func (f *Framework) CheckAgentHealth(port, timeout int) map[string]bool {
	f.agentsLock.RLock()
	defer f.agentsLock.RUnlock()

	var healthMap = make(map[string]bool, len(f.agents))

	if port == 0 {
		port = 30000
	}

	for _, agent := range f.agents {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", agent, port), time.Duration(timeout)*time.Second)
		if err == nil {
			conn.Close()
		}
		healthMap[agent] = err == nil
	}

	return healthMap
}

func (f *Framework) SetupVMs(vms ...*VM) error {
	for _, vm := range vms {
		if vm.status != nil {
			return fmt.Errorf("vm %s has been setup already", vm.Name)
		}

		var vmNetns = rand.String(6)
		var err error

		vm.status = &vmStatus{
			agent: f.randomAgent(),
			netns: vmNetns,
		}

		if vm.ExpectCidr == "" {
			vm.ExpectCidr = f.ipPoolCidr
		}
		vm.status.ipAddr, err = f.randomIPv4(vm.ExpectCidr)
		if err != nil {
			return fmt.Errorf("get random ip for vm %s: %s", vm.Name, err)
		}

		c, err := f.getAgentClient(vm.status.agent)
		if err != nil {
			return err
		}

		stdout, rc, err := runScriptRemote(c, startNewVM, vm.status.netns, vm.status.ipAddr, strconv.Itoa(vm.TCPPort), strconv.Itoa(vm.UDPPort))
		if err != nil {
			return err
		}
		if rc != 0 {
			return fmt.Errorf(string(stdout))
		}

		var vmEp = toEndpoint(vm)
		if err := f.k8sClient.Create(f.ctx, vmEp); err != nil {
			return err
		}

		klog.Infof("setup vm %s on agent %s, ip = %s, netns = %s", vm.Name, vm.status.agent, vm.status.ipAddr, vm.status.netns)
	}
	return nil
}

func (f *Framework) CleanVMs(vms ...*VM) error {
	for _, vm := range vms {
		if vm.status == nil {
			return fmt.Errorf("cant clean vm %s because vm haven't setup yet", vm.Name)
		}

		c, err := f.getAgentClient(vm.status.agent)
		if err != nil {
			return err
		}

		stdout, rc, err := runScriptRemote(c, destroyVM, vm.status.netns)
		if err != nil {
			return err
		}
		if rc != 0 {
			return fmt.Errorf(string(stdout))
		}

		var vmEp = toEndpoint(vm)
		if err := f.k8sClient.Delete(f.ctx, vmEp); err != nil {
			return err
		}

		klog.Infof("clean vm %s on agent %s, netns = %s", vm.Name, vm.status.agent, vm.status.netns)
	}
	return nil
}

func (f *Framework) UpdateVMLabels(vm *VM) error {
	var vmEp = &securityv1alpha1.Endpoint{}
	if vm.status == nil {
		return fmt.Errorf("cant update vm %s labels because vm haven't setup yet", vm.Name)
	}

	err := f.k8sClient.Get(f.ctx, types.NamespacedName{Name: vm.Name}, vmEp)
	if err != nil {
		return err
	}

	vmEp.Labels = toEndpoint(vm).Labels
	return f.k8sClient.Update(f.ctx, vmEp)
}

func (f *Framework) UpdateVMRandIP(vm *VM) error {
	var expectIPv4, err = f.randomIPv4(vm.ExpectCidr)
	if err != nil {
		return fmt.Errorf("get random ip for vm %s: %s", vm.Name, err)
	}

	c, err := f.getAgentClient(vm.status.agent)
	if err != nil {
		return err
	}

	stdout, rc, err := runScriptRemote(c, updateVMIP, vm.status.netns, expectIPv4)
	if err != nil {
		return err
	}
	if rc != 0 {
		return fmt.Errorf(string(stdout))
	}

	vm.status.ipAddr = expectIPv4

	klog.Infof("update vm %s ip to %s on agent %s, netns = %s", vm.Name, vm.status.ipAddr, vm.status.agent, vm.status.netns)
	return nil
}

func (f *Framework) MigrateVM(vm *VM) error {
	if f.CleanVMs(vm) != nil {
		klog.Errorf("Failed to delete oldVM while vm migration: %v", vm.Name)
	}

	for {
		newAgent := f.randomAgent()
		if newAgent != vm.status.agent {
			vm.status.agent = newAgent
			break
		}
	}

	c, err := f.getAgentClient(vm.status.agent)
	if err != nil {
		return err
	}

	stdout, rc, err := runScriptRemote(c, startNewVM, vm.status.netns,
		vm.status.ipAddr, strconv.Itoa(vm.TCPPort), strconv.Itoa(vm.UDPPort))
	if err != nil {
		return err
	}
	if rc != 0 {
		return fmt.Errorf(string(stdout))
	}

	var vmEp = toEndpoint(vm)
	if err := f.k8sClient.Create(f.ctx, vmEp); err != nil {
		return err
	}

	klog.Infof("setup vm %s on agent %s, ip = %s, netns = %s", vm.Name,
		vm.status.agent, vm.status.ipAddr, vm.status.netns)

	return nil
}

func (f *Framework) SetupObjects(objects ...metav1.Object) error {
	for _, object := range objects {
		err := f.k8sClient.Create(f.ctx, object.(runtime.Object).DeepCopyObject())
		if err != nil {
			return fmt.Errorf("unable create object %s: %s", object.GetName(), err)
		}

		err = wait.Poll(f.Interval(), f.Timeout(), func() (done bool, err error) {
			var objKey = types.NamespacedName{Name: object.GetName()}
			var obj = object.(runtime.Object)
			var getErr = f.k8sClient.Get(f.ctx, objKey, obj.DeepCopyObject())
			return getErr == nil, nil
		})
		if err != nil {
			return fmt.Errorf("unable wait for object %s create: %s", object.GetName(), err)
		}
	}

	return nil
}

func (f *Framework) CleanObjects(objects ...metav1.Object) error {
	for _, object := range objects {
		err := f.k8sClient.Delete(f.ctx, object.(runtime.Object).DeepCopyObject())
		if client.IgnoreNotFound(err) != nil {
			return fmt.Errorf("unable remove object %s: %s", object.GetName(), err)
		}

		err = wait.Poll(f.Interval(), f.Timeout(), func() (done bool, err error) {
			var objKey = types.NamespacedName{Name: object.GetName()}
			var obj = object.(runtime.Object)
			var getErr = f.k8sClient.Get(f.ctx, objKey, obj.DeepCopyObject())
			return errors.IsNotFound(getErr), nil
		})
		if err != nil {
			return fmt.Errorf("unable wait for object %s delete: %s", object.GetName(), err)
		}
	}

	return nil
}

func (f *Framework) Reachable(src *VM, dst *VM, protocol string) (bool, error) {
	klog.Infof("protocol %s reach test, src: %s netns=%s ip=%s, dst: %s netns=%s ip=%s", protocol,
		src.Name, src.status.netns, src.status.ipAddr,
		dst.Name, dst.status.netns, dst.status.ipAddr)

	out, rc, err := f.reachable(src, dst, protocol, 0)

	klog.Infof("trace reach test command result: \n%s", string(out))
	return rc, err
}

func (f *Framework) ReachableWithPort(src *VM, dst *VM, protocol string, port int) (bool, error) {
	_, rc, err := f.reachable(src, dst, protocol, port)
	return rc, err
}

func (f *Framework) reachable(src *VM, dst *VM, protocol string, port int) ([]byte, bool, error) {
	var out []byte
	var rc int
	var err error
	var c *ssh.Client

	c, err = f.getAgentClient(src.status.agent)
	if err != nil {
		return nil, false, err
	}

	if port == 0 {
		switch protocol {
		case "TCP":
			port = dst.TCPPort
		case "UDP":
			port = dst.UDPPort
		}
	}

	switch protocol {
	case "TCP":
		out, rc, err = runScriptRemote(c, tcpReachable, src.status.netns, dst.status.ipAddr, strconv.Itoa(port))
	case "UDP":
		out, rc, err = runScriptRemote(c, udpReachable, src.status.netns, dst.status.ipAddr, strconv.Itoa(port))
	case "ICMP":
		out, rc, err = runScriptRemote(c, icmpReachable, src.status.netns, dst.status.ipAddr)
	default:
		err = fmt.Errorf("unknow protocol %s", protocol)
	}

	return out, rc == 0, err
}

func (f *Framework) Timeout() time.Duration {
	return f.timeout
}

func (f *Framework) Interval() time.Duration {
	return f.interval
}

func (f *Framework) ExecCommand(vm *VM, args ...string) (int, error) {
	c, err := f.getAgentClient(vm.status.agent)
	if err != nil {
		return 0, err
	}

	return runCommandVM(c, vm.status.netns, args...)
}

func (f *Framework) GetClient() client.Client {
	return f.k8sClient
}

func (f *Framework) randomAgent() string {
	f.agentsLock.RLock()
	defer f.agentsLock.RUnlock()

	return f.agents[rand.Intn(len(f.agents))]
}

func (f *Framework) randomIPv4(cidr string) (string, error) {
	f.ipPoolLock.Lock()
	defer f.ipPoolLock.Unlock()

	if !containsCidr(f.ipPoolCidr, cidr) {
		return "", fmt.Errorf("cidr %s not in ip pool %s", cidr, f.ipPoolCidr)
	}

	for {
		var randomIPv4 = randomIPv4FromCidr(cidr)

		if _, ok := f.ipUsed[randomIPv4]; !ok {
			f.ipUsed[randomIPv4] = true
			return randomIPv4, nil
		}
	}
}

func (f *Framework) initAgents(configFile string) error {
	f.agentsLock.Lock()
	defer f.agentsLock.Unlock()

	agents, err := ioutil.ReadFile(configFile)
	if err != nil {
		return err
	}
	agents = bytes.ReplaceAll(bytes.ToValidUTF8(agents, nil), []byte{'\n'}, nil)

	f.agents = strings.Split(string(agents), ",")
	if len(f.agents) == 0 {
		return fmt.Errorf("at least one agent should provided")
	}

	user := os.Getenv("USER")
	signer, err := loadLocalSigner()
	if err != nil {
		return fmt.Errorf("unable load local signer: %s", err)
	}

	for _, agent := range f.agents {
		sshClient, err := newSSHClient(user, agent, 22, signer)
		if err != nil {
			return fmt.Errorf("get agent %s client: %s", agent, err)
		}
		f.clientMap[agent] = sshClient
	}

	return err
}

func (f *Framework) getAgentClient(agent string) (*ssh.Client, error) {
	f.agentsLock.RLock()
	defer f.agentsLock.RUnlock()

	c, ok := f.clientMap[agent]
	if !ok {
		return c, fmt.Errorf("agent %s client not found", agent)
	}

	return c, nil
}

func AsMapLables(labels string) map[string]string {
	var labelList = strings.Split(labels, ",")
	var mapLabels = make(map[string]string, len(labelList))

	for _, label := range labelList {
		if len(label) != 0 {
			mapLabels[strings.Split(label, "=")[0]] = strings.Split(label, "=")[1]
		}
	}

	return mapLabels
}

func randomIPv4FromCidr(cidr string) string {
	var _, netCidr, _ = net.ParseCIDR(cidr)
	var maskSize, _ = netCidr.Mask.Size()
	var offset = rand.Intn(1 << (32 - maskSize))

	var ipToI32 = func(ip net.IP) int32 {
		ip = ip.To4()
		return int32(ip[0])<<24 | int32(ip[1])<<16 | int32(ip[2])<<8 | int32(ip[3])
	}

	var i32ToIP = func(a int32) net.IP {
		return net.IPv4(byte(a>>24), byte(a>>16), byte(a>>8), byte(a))
	}

	return i32ToIP(ipToI32(netCidr.IP) + int32(offset)).String()
}

func containsCidr(cidr1, cidr2 string) bool {
	var _, netCidr1, _ = net.ParseCIDR(cidr1)
	var _, netCidr2, _ = net.ParseCIDR(cidr2)

	var maskSize1, _ = netCidr1.Mask.Size()
	var maskSize2, _ = netCidr2.Mask.Size()

	if maskSize1 > maskSize2 {
		return false
	}

	return netCidr1.Contains(netCidr1.IP)
}

func toEndpoint(vm *VM) *securityv1alpha1.Endpoint {
	if vm.status == nil {
		return nil
	}

	return &securityv1alpha1.Endpoint{
		ObjectMeta: metav1.ObjectMeta{
			Name: vm.Name,
			Annotations: map[string]string{
				"TCPPort": fmt.Sprintf("%d", vm.TCPPort),
				"UDPPort": fmt.Sprintf("%d", vm.UDPPort),
				"Agent":   vm.status.agent,
				"Netns":   vm.status.netns,
			},
			Labels: AsMapLables(vm.Labels),
		},
		Spec: securityv1alpha1.EndpointSpec{
			Reference: securityv1alpha1.EndpointReference{
				ExternalIDName:  "external_uuid",
				ExternalIDValue: fmt.Sprintf("uuid-%s", vm.status.netns),
			},
		},
	}
}

func addLynxToScheme(scheme *runtime.Scheme) *runtime.Scheme {
	_ = policyv1alpha1.AddToScheme(scheme)
	_ = securityv1alpha1.AddToScheme(scheme)
	_ = groupv1alpha1.AddToScheme(scheme)
	_ = agentv1alpha1.AddToScheme(scheme)

	return scheme
}

func SetVM(vm *VM, agent, netns, ipAddr string) {
	if vm.status == nil {
		vm.status = &vmStatus{}
	}

	vm.status.agent = agent
	vm.status.netns = netns
	vm.status.ipAddr = ipAddr
}
