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

package command

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8stypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/klog"
	kubeclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/smartxworks/lynx/pkg/apis/security/v1alpha1"
	"github.com/smartxworks/lynx/tests/e2e/framework"
)

const (
	Ingress = "Ingress"
	Egress  = "Egress"
)

func NewPolicyCommand(f *framework.Framework) *cobra.Command {
	ac := &cobra.Command{
		Use:   "policy <subcommand>",
		Short: "Policy related commands",
	}

	ac.AddCommand(newPolicyAddCommand(f))
	ac.AddCommand(newPolicySetCommand(f))
	ac.AddCommand(newPolicyDelCommand(f))
	ac.AddCommand(newPolicyListCommand(f))

	ac.AddCommand(newPolicyShowCommand(f))
	ac.AddCommand(newPolicyAddEgressCommand(f))
	ac.AddCommand(newPolicyAddIngressCommand(f))
	ac.AddCommand(newPolicySetRuleCommand(f))
	ac.AddCommand(newPolicyDelRuleCommand(f))

	return ac
}

func newPolicyAddCommand(f *framework.Framework) *cobra.Command {
	var tier, groups string
	var priority int32

	cmd := &cobra.Command{
		Use:   "add <policy name> [options]",
		Short: "Add a new security policy",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return fmt.Errorf("policy add command requires policy name as its argument")
			}
			return addPolicy(f, args[0], tier, priority, groups)
		},
	}

	cmd.PersistentFlags().StringVarP(&tier, "tier", "t", tier1, "policy tier, tier must create first")
	cmd.PersistentFlags().StringVarP(&groups, "applied-groups", "g", "", "policy applied groups, example: group01,group02,group03")
	cmd.PersistentFlags().Int32VarP(&priority, "priority", "p", 10, "policy priority")

	return cmd
}

// todo: allow set policy tier, priority and applied groups
func newPolicySetCommand(f *framework.Framework) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "set <policy name> [options]",
		Short: "Set or update policy attributes",
		RunE: func(cmd *cobra.Command, args []string) error {
			_ = f
			panic("todo")
		},
	}

	return cmd
}

func newPolicyDelCommand(f *framework.Framework) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "del <policy name>",
		Aliases: []string{"delete"},
		Short:   "Delete an old security policy",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return fmt.Errorf("policy delete command requires policy name as its argument")
			}
			return delPolicy(f, args[0])
		},
	}

	return cmd
}

func newPolicyListCommand(f *framework.Framework) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "ls",
		Aliases: []string{"list"},
		Short:   "List and show all policies",
		RunE: func(cmd *cobra.Command, args []string) error {
			return listPolicy(f, cmd.OutOrStdout())
		},
	}

	return cmd
}

func newPolicyShowCommand(f *framework.Framework) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "show <policy name>",
		Short: "Show security policy and its rules",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return fmt.Errorf("policy show command requires policy name as its argument")
			}
			return showPolicy(f, cmd.OutOrStdout(), args[0])
		},
	}

	return cmd
}

func newPolicyAddIngressCommand(f *framework.Framework) *cobra.Command {
	var peers, protocol, ports string

	cmd := &cobra.Command{
		Use:   "add-ingress <policy name> <rule name> [options]",
		Short: "Add an ingress rule to policy",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 2 {
				return fmt.Errorf("policy add-ingress command requires policy name and rule name as its argument")
			}
			return addPolicyRule(f, args[0], args[1], Ingress, peers, protocol, ports)
		},
	}

	cmd.PersistentFlags().StringVar(&peers, "peers", "", "ingress from peers, should be groups or cidrs")
	cmd.PersistentFlags().StringVar(&protocol, "protocol", "TCP", "packets protocol, should be TCP, UDP or ICMP")
	cmd.PersistentFlags().StringVar(&ports, "ports", "", "source ports range, example: 80-82, or 80")

	return cmd
}

func newPolicySetRuleCommand(f *framework.Framework) *cobra.Command {
	var protocol, ports string

	cmd := &cobra.Command{
		Use:   "set-rule <policy name> <rule name> [options]",
		Short: "Set or update policy rule attributes",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 2 {
				return fmt.Errorf("policy set-rule command requires policy name and rule name as its argument")
			}
			return setPolicyRule(f, args[0], args[1], protocol, ports)
		},
	}

	cmd.PersistentFlags().StringVar(&protocol, "protocol", "TCP", "packets protocol, should be TCP, UDP or ICMP")
	cmd.PersistentFlags().StringVar(&ports, "ports", "", "destination ports range, example: 80-82, or 80")

	return cmd
}

func newPolicyDelRuleCommand(f *framework.Framework) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "del-rule <policy name> <rule name>",
		Short: "Delete a rule from policy",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 2 {
				return fmt.Errorf("policy del-rule command requires policy name and rule name as its argument")
			}
			return delPolicyRule(f, args[0], args[1])
		},
	}

	return cmd
}

func newPolicyAddEgressCommand(f *framework.Framework) *cobra.Command {
	var peers, protocol, ports string

	cmd := &cobra.Command{
		Use:   "add-egress <policy name> <rule name> [options]",
		Short: "Add an egress rule to policy",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 2 {
				return fmt.Errorf("policy add-egress command requires policy name and rule name as its argument")
			}
			return addPolicyRule(f, args[0], args[1], Egress, peers, protocol, ports)
		},
	}

	cmd.PersistentFlags().StringVar(&peers, "peers", "", "egress to peers, should be groups or cidrs")
	cmd.PersistentFlags().StringVar(&protocol, "protocol", "TCP", "packets protocol, should be TCP, UDP or ICMP")
	cmd.PersistentFlags().StringVar(&ports, "ports", "", "destination ports range, example: 80-82, or 80")

	return cmd
}

func addPolicy(f *framework.Framework, name string, tier string, priority int32, appliedGroups string) error {
	var policy = &v1alpha1.SecurityPolicy{}
	policy.Name = name
	policy.Namespace = metav1.NamespaceDefault

	policy.Spec = v1alpha1.SecurityPolicySpec{
		Tier:     tier,
		Priority: priority,
		AppliedTo: v1alpha1.AppliedTo{
			EndpointGroups: strings.Split(appliedGroups, ","),
		},
	}

	return f.SetupObjects(context.TODO(), policy)
}

func delPolicy(f *framework.Framework, name string) error {
	var client = f.KubeClient()
	var policy = &v1alpha1.SecurityPolicy{}

	err := client.Get(context.TODO(), k8stypes.NamespacedName{Name: name, Namespace: metav1.NamespaceDefault}, policy)
	if err != nil {
		return err
	}

	return client.Delete(context.TODO(), policy)
}

func listPolicy(f *framework.Framework, output io.Writer) error {
	var client = f.KubeClient()
	var policyList = &v1alpha1.SecurityPolicyList{}

	err := client.List(context.TODO(), policyList, kubeclient.InNamespace(metav1.NamespaceDefault))
	if err != nil {
		return err
	}

	return printPolicy(output, policyList.Items)
}

func showPolicy(f *framework.Framework, output io.Writer, name string) error {
	var client = f.KubeClient()
	var policy = &v1alpha1.SecurityPolicy{}

	err := client.Get(context.TODO(), k8stypes.NamespacedName{Name: name, Namespace: metav1.NamespaceDefault}, policy)
	if err != nil {
		return err
	}

	err = printPolicy(output, []v1alpha1.SecurityPolicy{*policy})
	if err != nil {
		return err
	}

	if len(policy.Spec.IngressRules) == 0 && len(policy.Spec.EgressRules) == 0 {
		return nil
	}

	if _, err = fmt.Fprintln(output); err != nil {
		return err
	}

	return printPolicyRule(output, policy)
}

func addPolicyRule(f *framework.Framework, policyName, ruleName, ruleDirection, peers, protocol, ports string) error {
	var client = f.KubeClient()
	var policy = &v1alpha1.SecurityPolicy{}

	err := client.Get(context.TODO(), k8stypes.NamespacedName{Name: policyName, Namespace: metav1.NamespaceDefault}, policy)
	if err != nil {
		return err
	}

	var peer = getPeer(strings.Split(peers, ",")...)
	var rule = &v1alpha1.Rule{
		Name:  ruleName,
		Ports: getPort(protocol, ports),
	}

	if ruleDirection == Ingress {
		rule.From = peer
		policy.Spec.IngressRules = append(policy.Spec.IngressRules, *rule)
	}

	if ruleDirection == Egress {
		rule.To = peer
		policy.Spec.EgressRules = append(policy.Spec.EgressRules, *rule)
	}

	return client.Update(context.TODO(), policy)
}

func setPolicyRule(f *framework.Framework, policyName, ruleName, protocol, ports string) error {
	var client = f.KubeClient()
	var policy = &v1alpha1.SecurityPolicy{}
	var rule *v1alpha1.Rule

	err := client.Get(context.TODO(), k8stypes.NamespacedName{Name: policyName, Namespace: metav1.NamespaceDefault}, policy)
	if err != nil {
		return err
	}

	for index, policyRule := range policy.Spec.IngressRules {
		if policyRule.Name == ruleName {
			rule = &policy.Spec.IngressRules[index]
		}
	}

	for index, policyRule := range policy.Spec.EgressRules {
		if policyRule.Name == ruleName {
			rule = &policy.Spec.EgressRules[index]
		}
	}

	if rule == nil {
		return fmt.Errorf("policy %s rule %s not found", policyName, ruleName)
	}

	rule.Ports = getPort(protocol, ports)
	return client.Update(context.TODO(), policy)
}

func delPolicyRule(f *framework.Framework, policyName, ruleName string) error {
	var client = f.KubeClient()
	var policy = &v1alpha1.SecurityPolicy{}

	err := client.Get(context.TODO(), k8stypes.NamespacedName{Name: policyName, Namespace: metav1.NamespaceDefault}, policy)
	if err != nil {
		return err
	}

	for index, rule := range policy.Spec.IngressRules {
		if rule.Name == ruleName {
			policy.Spec.IngressRules = append(policy.Spec.IngressRules[:index], policy.Spec.IngressRules[index+1:]...)
			klog.Infof("found ingress rule %s to remove: %+v", ruleName, rule)
			break
		}
	}

	for index, rule := range policy.Spec.EgressRules {
		if rule.Name == ruleName {
			policy.Spec.EgressRules = append(policy.Spec.EgressRules[:index], policy.Spec.EgressRules[index+1:]...)
			klog.Infof("found egress rule %s to remove: %+v", ruleName, rule)
			break
		}
	}

	return client.Update(context.TODO(), policy)
}

// peer is group peer or cidr peer, format like: group01 or 10.0.0.0/24.
func getPeer(peers ...string) v1alpha1.SecurityPolicyPeer {
	var policyPeer v1alpha1.SecurityPolicyPeer

	for _, peer := range peers {
		if strings.Count(peer, "/") == 1 {
			policyPeer.IPBlocks = append(policyPeer.IPBlocks, networkingv1.IPBlock{
				CIDR: peer,
			})
		} else if peer != "" {
			policyPeer.EndpointGroups = append(policyPeer.EndpointGroups, peer)
		}
	}

	return policyPeer
}

func getPort(protocol, ports string) []v1alpha1.SecurityPolicyPort {
	if protocol == "" {
		return nil
	}
	return []v1alpha1.SecurityPolicyPort{
		{
			Protocol:  v1alpha1.Protocol(strings.ToUpper(protocol)),
			PortRange: ports,
		},
	}
}
