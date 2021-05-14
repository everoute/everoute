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
	"fmt"
	"io"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/cli-runtime/pkg/printers"

	groupv1alpha1 "github.com/smartxworks/lynx/pkg/apis/group/v1alpha1"
	securityv1alpha1 "github.com/smartxworks/lynx/pkg/apis/security/v1alpha1"
	"github.com/smartxworks/lynx/pkg/types"
)

func printTier(output io.Writer, tiers []securityv1alpha1.Tier) error {
	var table = newTable("name", "priority", "tiermode")

	for _, tier := range tiers {
		var row = []interface{}{}

		row = append(row, tier.Name)
		row = append(row, tier.Spec.Priority)
		row = append(row, tier.Spec.TierMode)

		addRow(table, row)
	}

	return printTable(output, table)
}

func printVM(output io.Writer, eps []securityv1alpha1.Endpoint) error {
	var table = newTable("name", "agent", "netns", "labels", "tcp-port", "udp-port", "ipaddr")

	var ipsToString = func(ips []types.IPAddress) string {
		var list string
		if len(ips) == 0 {
			return ""
		}

		for _, ip := range ips {
			list = fmt.Sprintf("%s,%s", list, ip.String())
		}

		return list[1:]
	}

	for _, ep := range eps {
		var row = []interface{}{}

		row = append(row, ep.Name)
		row = append(row, ep.Annotations["Agent"])
		row = append(row, ep.Annotations["Netns"])
		row = append(row, mapJoin(ep.Labels, "=", ","))
		row = append(row, ep.Annotations["TCPPort"])
		row = append(row, ep.Annotations["UDPPort"])
		row = append(row, ipsToString(ep.Status.IPs))

		addRow(table, row)
	}

	return printTable(output, table)
}

func printGroup(output io.Writer, groups []groupv1alpha1.EndpointGroup, eps []securityv1alpha1.Endpoint) error {
	var table = newTable("name", "selector", "members")

	var selectorToString = func(selector *metav1.LabelSelector) string {
		if selector == nil {
			return "<empty>"
		}
		return mapJoin(selector.MatchLabels, "=", ",")
	}

	var selectEndpoint = func(ls *metav1.LabelSelector, eps []securityv1alpha1.Endpoint) string {
		var epList []string

		for _, ep := range selectEndpoint(ls, &securityv1alpha1.EndpointList{Items: eps}).Items {
			epList = append(epList, ep.Name)
		}

		return strings.Join(epList, ",")
	}

	for _, group := range groups {
		var row = []interface{}{}

		row = append(row, group.Name)
		row = append(row, selectorToString(group.Spec.Selector))
		row = append(row, selectEndpoint(group.Spec.Selector, eps))

		addRow(table, row)
	}

	return printTable(output, table)
}

func printPolicy(output io.Writer, policies []securityv1alpha1.SecurityPolicy) error {
	var table = newTable("name", "tier", "priority", "applied-groups")

	for _, policy := range policies {
		var row = []interface{}{}

		row = append(row, policy.Name)
		row = append(row, policy.Spec.Tier)
		row = append(row, policy.Spec.Priority)
		row = append(row, strings.Join(policy.Spec.AppliedTo.EndpointGroups, ","))

		addRow(table, row)
	}

	return printTable(output, table)
}

func printPolicyRule(output io.Writer, policy *securityv1alpha1.SecurityPolicy) error {
	var table = newTable("name", "peers", "direction", "protocol", "ports")

	var peerToString = func(peer *securityv1alpha1.SecurityPolicyPeer) string {
		var str = strings.Join(peer.EndpointGroups, ",")

		for _, ipblock := range peer.IPBlocks {
			if str != "" {
				str = fmt.Sprintf("%s,", str)
			}
			str += fmt.Sprintf("%s/%d", ipblock.IP, ipblock.PrefixLength)
		}

		return str
	}

	for _, rule := range policy.Spec.IngressRules {
		var row = []interface{}{}

		row = append(row, rule.Name)
		row = append(row, peerToString(&rule.From))
		row = append(row, Ingress)

		// todo: support multiple ports in e2e
		if len(rule.Ports) != 0 {
			row = append(row, rule.Ports[0].Protocol)
			row = append(row, rule.Ports[0].PortRange)
		}

		addRow(table, row)
	}

	for _, rule := range policy.Spec.EgressRules {
		var row = []interface{}{}

		row = append(row, rule.Name)
		row = append(row, peerToString(&rule.To))
		row = append(row, Egress)

		if len(rule.Ports) != 0 {
			row = append(row, rule.Ports[0].Protocol)
			row = append(row, rule.Ports[0].PortRange)
		}

		addRow(table, row)
	}

	return printTable(output, table)
}

func printTable(output io.Writer, table *metav1.Table) error {
	printer := printers.NewTablePrinter(printers.PrintOptions{})
	return printer.PrintObj(table, output)
}

func newTable(columns ...string) *metav1.Table {
	var table = &metav1.Table{}

	for _, column := range columns {
		table.ColumnDefinitions = append(table.ColumnDefinitions, metav1.TableColumnDefinition{
			Name: column,
			Type: "string",
		})
	}

	return table
}

func addRow(table *metav1.Table, row []interface{}) {
	table.Rows = append(table.Rows, metav1.TableRow{
		Cells: row,
	})
}
