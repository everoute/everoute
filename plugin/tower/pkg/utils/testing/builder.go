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

	"github.com/everoute/everoute/pkg/apis/security/v1alpha1"
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
	return &schema.Label{
		ObjectMeta: schema.ObjectMeta{ID: rand.String(10)},
		Key:        rand.String(10),
		Value:      rand.String(10),
	}
}

func AggregateLabels(labels ...*schema.Label) map[string]string {
	labelMap := make(map[string]string)
	for _, label := range labels {
		labelMap[label.Key] = label.Value
	}
	return labelMap
}

func NewSecurityPolicy(everouteCluster string, communicable bool, selectors ...*schema.Label) *schema.SecurityPolicy {
	return &schema.SecurityPolicy{
		ObjectMeta:      schema.ObjectMeta{ID: rand.String(10)},
		EverouteCluster: schema.ObjectReference{ID: everouteCluster},
		ApplyTo: []schema.SecurityPolicyApply{{
			Communicable: communicable,
			Selector:     LabelAsReference(selectors...),
		}},
	}
}

func NewIsolationPolicy(everouteCluster string, vm *schema.VM, isolationMode schema.IsolationMode) *schema.IsolationPolicy {
	return &schema.IsolationPolicy{
		ObjectMeta:      schema.ObjectMeta{ID: rand.String(10)},
		EverouteCluster: schema.ObjectReference{ID: everouteCluster},
		VM:              schema.ObjectReference{ID: vm.GetID()},
		Mode:            isolationMode,
	}
}

func NewNetworkPolicyRule(protocol, port string, ipBlock string, selectors ...*schema.Label) *schema.NetworkPolicyRule {
	var rule schema.NetworkPolicyRule

	if protocol != "" {
		rule.Ports = append(rule.Ports, schema.NetworkPolicyRulePort{
			Port:     &port,
			Protocol: schema.NetworkPolicyRulePortProtocol(protocol),
		})
	}

	if ipBlock != "" {
		rule.Type = schema.NetworkPolicyRuleTypeIPBlock
		rule.IPBlock = &ipBlock
	}

	if len(selectors) != 0 {
		rule.Type = schema.NetworkPolicyRuleTypeSelector
		rule.Selector = LabelAsReference(selectors...)
	}

	return &rule
}

func NewSecurityPolicyRuleIngress(protocol, port string, ipBlock string, selectors ...*schema.Label) *v1alpha1.Rule {
	var rule v1alpha1.Rule

	if protocol != "" {
		rule.Ports = append(rule.Ports, v1alpha1.SecurityPolicyPort{
			Protocol:  v1alpha1.Protocol(protocol),
			PortRange: port,
		})
	}

	if ipBlock != "" {
		rule.From = append(rule.From, v1alpha1.SecurityPolicyPeer{
			IPBlock: &networkingv1.IPBlock{
				CIDR: ipBlock,
			},
		})
	}

	if len(selectors) != 0 {
		rule.From = append(rule.From, v1alpha1.SecurityPolicyPeer{
			EndpointSelector: &metav1.LabelSelector{
				MatchLabels: AggregateLabels(selectors...),
			},
		})
	}

	return &rule
}

func NewSecurityPolicyRuleEgress(protocol, port string, ipBlock string, selectors ...*schema.Label) *v1alpha1.Rule {
	var rule v1alpha1.Rule

	if protocol != "" {
		rule.Ports = append(rule.Ports, v1alpha1.SecurityPolicyPort{
			Protocol:  v1alpha1.Protocol(protocol),
			PortRange: port,
		})
	}

	if ipBlock != "" {
		rule.To = append(rule.To, v1alpha1.SecurityPolicyPeer{
			IPBlock: &networkingv1.IPBlock{
				CIDR: ipBlock,
			},
		})
	}

	if len(selectors) != 0 {
		rule.To = append(rule.To, v1alpha1.SecurityPolicyPeer{
			EndpointSelector: &metav1.LabelSelector{
				MatchLabels: AggregateLabels(selectors...),
			},
		})
	}

	return &rule
}

func NewSecurityPolicyApplyPeer(endpoint string, selectors ...*schema.Label) v1alpha1.ApplyToPeer {
	var peer v1alpha1.ApplyToPeer
	if endpoint != "" {
		peer.Endpoint = &endpoint
	}
	if len(selectors) != 0 {
		peer.EndpointSelector = &metav1.LabelSelector{
			MatchLabels: AggregateLabels(selectors...),
		}
	}
	return peer
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
			*NewNetworkPolicyRule("", "", NewRandomIP().String()),
		},
		Ingress: []schema.NetworkPolicyRule{
			*NewNetworkPolicyRule("", "", NewRandomIP().String()),
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
