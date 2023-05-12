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

package testing

import (
	"fmt"
	"net"

	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/rand"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/validation"

	"github.com/everoute/everoute/pkg/apis/security/v1alpha1"
	"github.com/everoute/everoute/pkg/labels"
	"github.com/everoute/everoute/plugin/tower/pkg/schema"
)

func NewRandomVM() *schema.VM {
	return &schema.VM{
		ObjectMeta: schema.ObjectMeta{ID: rand.String(10)},
		Name:       rand.String(10),
		Status:     schema.VMStatusRunning,
	}
}

func NewRandomVMNicAttachedTo(vm *schema.VM) *schema.VMNic {
	vlanInfo := schema.Vlan{
		ObjectMeta: schema.ObjectMeta{ID: rand.String(10)},
		Name:       rand.String(10),
		VlanID:     0,
		Type:       schema.NetworkVM,
	}

	vmnic := schema.VMNic{
		ObjectMeta:  schema.ObjectMeta{ID: rand.String(10)},
		Vlan:        vlanInfo,
		Enabled:     true,
		InterfaceID: rand.String(10),
	}

	vm.VMNics = append(vm.VMNics, vmnic)
	return &vmnic
}

func NewRandomLabel() *schema.Label {
	return NewLabel(rand.String(10), rand.String(10))
}

func NewLabel(key string, value string) *schema.Label {
	return &schema.Label{
		ObjectMeta: schema.ObjectMeta{ID: rand.String(10)},
		Key:        key,
		Value:      value,
	}
}

func AggregateLabels(labels ...*schema.Label) map[string]string {
	labelMap := make(map[string]string)
	for _, label := range labels {
		labelMap[label.Key] = label.Value
	}
	return labelMap
}

func NewService(rulePorts ...schema.NetworkPolicyRulePort) *schema.NetworkPolicyRuleService {
	return &schema.NetworkPolicyRuleService{
		ObjectMeta: schema.ObjectMeta{ID: rand.String(10)},
		Members:    rulePorts,
	}
}

func NewSecurityPolicy(everouteCluster string, communicable bool, group *schema.SecurityGroup, selectors ...*schema.Label) *schema.SecurityPolicy {
	policy := &schema.SecurityPolicy{
		ObjectMeta:      schema.ObjectMeta{ID: rand.String(10)},
		EverouteCluster: schema.ObjectReference{ID: everouteCluster},
	}

	if group != nil {
		policy.ApplyTo = append(policy.ApplyTo, schema.SecurityPolicyApply{
			Type:          schema.SecurityPolicyTypeSecurityGroup,
			Communicable:  communicable,
			SecurityGroup: &schema.ObjectReference{ID: group.GetID()},
		})
	}

	if len(selectors) != 0 {
		policy.ApplyTo = append(policy.ApplyTo, schema.SecurityPolicyApply{
			Type:         schema.SecurityPolicyTypeSelector,
			Communicable: communicable,
			Selector:     LabelAsReference(selectors...),
		})
	}

	return policy
}

func NewIsolationPolicy(everouteCluster string, vm *schema.VM, isolationMode schema.IsolationMode) *schema.IsolationPolicy {
	return &schema.IsolationPolicy{
		ObjectMeta:      schema.ObjectMeta{ID: rand.String(10)},
		EverouteCluster: schema.ObjectReference{ID: everouteCluster},
		VM:              schema.ObjectReference{ID: vm.GetID()},
		Mode:            isolationMode,
	}
}

func NewNetworkPolicyRule(protocol, port string, ipBlock *networkingv1.IPBlock, selectors ...*schema.Label) *schema.NetworkPolicyRule {
	var rule schema.NetworkPolicyRule

	if protocol != "" {
		rule.Ports = append(rule.Ports, schema.NetworkPolicyRulePort{
			Port:     &port,
			Protocol: schema.NetworkPolicyRulePortProtocol(protocol),
		})
	}

	if ipBlock != nil {
		rule.Type = schema.NetworkPolicyRuleTypeIPBlock
		rule.IPBlock = &ipBlock.CIDR
		rule.ExceptIPBlock = ipBlock.Except
	}

	if len(selectors) != 0 {
		rule.Type = schema.NetworkPolicyRuleTypeSelector
		rule.Selector = LabelAsReference(selectors...)
	}

	return &rule
}

func NewNetworkPolicyRulePort(protocol, algProtocol, port string) *schema.NetworkPolicyRulePort {
	return &schema.NetworkPolicyRulePort{
		Port:        &port,
		Protocol:    schema.NetworkPolicyRulePortProtocol(protocol),
		AlgProtocol: schema.NetworkPolicyRulePortAlgProtocol(algProtocol),
	}
}

func NetworkPolicyRuleAddPorts(rule *schema.NetworkPolicyRule, ports ...schema.NetworkPolicyRulePort) {
	rule.Ports = append(rule.Ports, ports...)
}

func NetworkPolicyRuleAddServices(rule *schema.NetworkPolicyRule, svcIDs ...string) {
	for i := range svcIDs {
		rule.Services = append(rule.Services, schema.ObjectReference{
			ID: svcIDs[i],
		})
	}
}

func NetworkPolicyRuleDelServices(rule *schema.NetworkPolicyRule, svcIDs ...string) {
	if len(svcIDs) == 0 || len(rule.Services) == 0 {
		return
	}

	var curSvcIDs []string
	for i := range rule.Services {
		curSvcIDs = append(curSvcIDs, rule.Services[i].ID)
	}
	newSvcIDs := sets.NewString(curSvcIDs...).Delete(svcIDs...)

	rule.Services = nil
	NetworkPolicyRuleAddServices(rule, newSvcIDs.List()...)
}

func NewSecurityPolicyRuleIngress(protocol, port string, ipBlock *networkingv1.IPBlock, selectors ...*schema.Label) *v1alpha1.Rule {
	var rule v1alpha1.Rule

	if protocol != "" {
		rule.Ports = append(rule.Ports, v1alpha1.SecurityPolicyPort{
			Protocol:  v1alpha1.Protocol(protocol),
			PortRange: port,
		})
	}

	if ipBlock != nil {
		rule.From = append(rule.From, v1alpha1.SecurityPolicyPeer{IPBlock: ipBlock})
	}

	if len(selectors) != 0 {
		rule.From = append(rule.From, v1alpha1.SecurityPolicyPeer{
			EndpointSelector: LabelsAsSelector(selectors...),
		})
	}

	return &rule
}

func NewSecurityPolicyRuleEgress(protocol, port string, ipBlock *networkingv1.IPBlock, selectors ...*schema.Label) *v1alpha1.Rule {
	var rule v1alpha1.Rule

	if protocol != "" {
		rule.Ports = append(rule.Ports, v1alpha1.SecurityPolicyPort{
			Protocol:  v1alpha1.Protocol(protocol),
			PortRange: port,
		})
	}

	if ipBlock != nil {
		rule.To = append(rule.To, v1alpha1.SecurityPolicyPeer{IPBlock: ipBlock})
	}

	if len(selectors) != 0 {
		rule.To = append(rule.To, v1alpha1.SecurityPolicyPeer{
			EndpointSelector: LabelsAsSelector(selectors...),
		})
	}

	return &rule
}

func RuleAddPorts(rule *v1alpha1.Rule, portInfo ...string) {
	portsLen := len(portInfo) / 2
	for i := 0; i < portsLen; i++ {
		rule.Ports = append(rule.Ports, v1alpha1.SecurityPolicyPort{
			Protocol:  v1alpha1.Protocol(portInfo[2*i]),
			PortRange: portInfo[2*i+1],
		})
	}
}

func RuleSetDisableSymmetric(rule *v1alpha1.Rule, disableSymmetric bool) {
	if rule == nil {
		return
	}
	if len(rule.From) > 0 {
		rule.From[0].DisableSymmetric = disableSymmetric
	}

	if len(rule.To) > 0 {
		rule.To[0].DisableSymmetric = disableSymmetric
	}
}

func NewSecurityPolicyApplyPeer(endpoint string, selectors ...*schema.Label) v1alpha1.ApplyToPeer {
	var peer v1alpha1.ApplyToPeer
	if endpoint != "" {
		peer.Endpoint = &endpoint
	}
	if len(selectors) != 0 {
		peer.EndpointSelector = LabelsAsSelector(selectors...)
	}
	return peer
}

func LabelsAsSelector(selectors ...*schema.Label) *labels.Selector {
	var matchLabels = make(map[string]string)
	var extendMatchLabels = make(map[string][]string)

	for _, label := range selectors {
		extendMatchLabels[label.Key] = append(extendMatchLabels[label.Key], label.Value)
	}

	for key, valueSet := range extendMatchLabels {
		if len(valueSet) != 1 {
			continue
		}
		if len(validation.IsQualifiedName(key)) == 0 &&
			len(validation.IsValidLabelValue(valueSet[0])) == 0 {
			matchLabels[key] = valueSet[0]
			delete(extendMatchLabels, key)
		}
	}

	return &labels.Selector{
		LabelSelector:     metav1.LabelSelector{MatchLabels: matchLabels},
		ExtendMatchLabels: extendMatchLabels,
	}
}

func LabelAsReference(labels ...*schema.Label) []schema.ObjectReference {
	var labelRefs []schema.ObjectReference
	for _, label := range labels {
		labelRefs = append(labelRefs, schema.ObjectReference{
			ID: label.GetID(),
		})
	}
	return labelRefs
}

func NewEverouteCluster(erClusterID string, defaultAction schema.GlobalPolicyAction) *schema.EverouteCluster {
	return &schema.EverouteCluster{
		ObjectMeta:          schema.ObjectMeta{ID: erClusterID},
		GlobalDefaultAction: defaultAction,
		ControllerInstances: []schema.EverouteControllerInstance{
			{IPAddr: NewRandomIP().String()},
			{IPAddr: NewRandomIP().String()},
			{IPAddr: NewRandomIP().String()},
		},
	}
}

func NewGlobalWhitelist() *schema.EverouteClusterWhitelist {
	return &schema.EverouteClusterWhitelist{
		Enable: true,
		Egress: []schema.NetworkPolicyRule{
			*NewNetworkPolicyRule("", "", &networkingv1.IPBlock{CIDR: NewRandomIP().String()}),
		},
		Ingress: []schema.NetworkPolicyRule{
			*NewNetworkPolicyRule("", "", &networkingv1.IPBlock{CIDR: NewRandomIP().String()}),
		},
	}
}

func NewSystemEndpoints(endpointNum int) *schema.SystemEndpoints {
	systemEndpoints := &schema.SystemEndpoints{IPPortEndpoints: make([]schema.IPPortSystemEndpoint, 0, endpointNum)}
	for i := 0; i < endpointNum; i++ {
		systemEndpoints.IPPortEndpoints = append(
			systemEndpoints.IPPortEndpoints,
			schema.IPPortSystemEndpoint{
				Key: rand.String(24),
				IP:  NewRandomIP().String(),
			},
		)
	}
	return systemEndpoints
}

func NewRandomIP() net.IP {
	return net.ParseIP(
		fmt.Sprintf("%d.%d.%d.%d",
			rand.Intn(256),
			rand.Intn(256),
			rand.Intn(256),
			rand.Intn(256),
		),
	)
}

func NewRandomIPBlock() *networkingv1.IPBlock {
	ipStr := NewRandomIP().String()
	prefixLen := fmt.Sprintf("%d", rand.Intn(33))
	ipBlock := &networkingv1.IPBlock{
		CIDR: ipStr + "/" + prefixLen,
	}
	exceptLen := rand.Intn(3)
	var exceptIPs []string
	for i := 0; i <= exceptLen; i++ {
		exceptIPs = append(exceptIPs, NewRandomIP().String()+"/32")
	}
	ipBlock.Except = exceptIPs
	return ipBlock
}

func NewTask(status schema.TaskStatus) *schema.Task {
	return &schema.Task{
		ObjectMeta: schema.ObjectMeta{ID: rand.String(10)},
		Status:     status,
	}
}

func NewSecurityGroup(clusterID string) *schema.SecurityGroup {
	return &schema.SecurityGroup{
		ObjectMeta:      schema.ObjectMeta{ID: rand.String(10)},
		EverouteCluster: schema.ObjectReference{ID: clusterID},
	}
}

// NewRandomHost creates a random Host
func NewRandomHost() *schema.Host {
	return &schema.Host{
		ObjectMeta: schema.ObjectMeta{ID: rand.String(10)},
		Name:       rand.String(10),
	}
}

// NewRandomNicAttachedTo creates a random NIC attached to the given Host
func NewRandomNicAttachedTo(host *schema.Host, name string) *schema.Nic {
	if name == "" {
		name = rand.String(10)
	}

	nic := schema.Nic{
		ObjectMeta: schema.ObjectMeta{ID: rand.String(10)},
		Name:       name,
		IPAddress:  NewRandomIP().String(),
	}

	host.Nics = append(host.Nics, nic)
	return &nic
}
