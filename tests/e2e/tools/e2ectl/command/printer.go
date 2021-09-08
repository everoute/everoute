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
	"io"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/cli-runtime/pkg/printers"

	"github.com/smartxworks/lynx/tests/e2e/framework/model"
)

func printEndpoint(output io.Writer, eps []*model.Endpoint) error {
	var table = newTable("name", "host", "local-id", "labels", "tcp-port", "udp-port", "ip-addr")

	for _, ep := range eps {
		var row = []interface{}{}

		row = append(row, ep.Name)
		row = append(row, ep.Status.Host)
		row = append(row, ep.Status.LocalID)
		row = append(row, mapJoin(ep.Labels, "=", ","))
		row = append(row, ep.TCPPort)
		row = append(row, ep.UDPPort)
		row = append(row, ep.Status.IPAddr)

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
