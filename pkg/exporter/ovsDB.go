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

package exporter

import (
	"fmt"
	"reflect"
	"strings"

	ovsdb "github.com/contiv/libovsdb"
	"k8s.io/klog"

	"github.com/everoute/everoute/pkg/agent/datapath"
)

const (
	SFlowSampling = 64
	SFlowPooling  = 10
	SFlowHeader   = 128

	SFlowPort = 6666

	emptyUUID = "00000000-0000-0000-0000-000000000000"
)

type OvsMonitor struct {
	ovsClient *ovsdb.OvsdbClient

	collectorCache *CollectorCache
}

func NewMonior(cache *CollectorCache) *OvsMonitor {
	ovsClient, err := ovsdb.ConnectUnix(ovsdb.DEFAULT_SOCK)
	if err != nil {
		klog.Errorf("failed to connection to ovsdb: %s", err.Error())
	}

	return &OvsMonitor{
		ovsClient:      ovsClient,
		collectorCache: cache,
	}
}

func (m *OvsMonitor) Run(stopChan <-chan struct{}) {
	defer m.ovsClient.Disconnect()
	defer cleanSFlowOVSConfig()

	m.ovsClient.Register(ovsUpdateHandlerFunc(m.handleOvsUpdates))
	selectAll := ovsdb.MonitorSelect{
		Initial: true,
		Insert:  true,
		Delete:  true,
		Modify:  true,
	}
	requests := map[string]ovsdb.MonitorRequest{
		"Interface": {Select: selectAll, Columns: []string{"ifindex", "external_ids", "name"}},
		"Bridge":    {Select: selectAll, Columns: []string{"name"}},
	}

	initial, err := m.ovsClient.Monitor("Open_vSwitch", nil, requests)
	if err != nil {
		fmt.Errorf("monitor ovsdb %s: %s", "Open_vSwitch", err)
	}
	m.handleOvsUpdates(*initial)

	<-stopChan
}

func FilterBridge(brName interface{}) bool {
	switch brName.(type) {
	case string:
		name := brName.(string)
		if strings.HasSuffix(name, datapath.POLICY_BRIDGE_KEYWORD) ||
			strings.HasSuffix(name, datapath.CLS_BRIDGE_KEYWORD) {
			return true
		}
	default:
		return true
	}

	return false
}

func generateInterface(row ovsdb.Row) *Interface {
	iface := &Interface{}
	switch row.Fields["ifindex"].(type) {
	case float64:
		iface.ifindex = uint32(row.Fields["ifindex"].(float64))
	}

	switch row.Fields["name"].(type) {
	case string:
		iface.name = row.Fields["name"].(string)
	}

	switch row.Fields["external_ids"].(type) {
	case ovsdb.OvsMap:
		iface.externalID = make(map[string]string)
		for k, v := range row.Fields["external_ids"].(ovsdb.OvsMap).GoMap {
			var kStr, vStr string
			switch k.(type) {
			case string:
				kStr = k.(string)
			}
			switch v.(type) {
			case string:
				vStr = v.(string)
			}
			if kStr != "" && vStr != "" {
				iface.externalID[kStr] = vStr
			}
		}
	}
	return iface
}

func (m *OvsMonitor) handleOvsUpdates(updates ovsdb.TableUpdates) {
	for table, tableUpdate := range updates.Updates {
		for _, row := range tableUpdate.Rows {
			empty := ovsdb.Row{}
			if !reflect.DeepEqual(row.New, empty) {
				// add & update
				if table == "Interface" {
					m.collectorCache.AddIface(generateInterface(row.New))
				}
				if table == "Bridge" {
					if FilterBridge(row.New.Fields["name"]) {
						continue
					}
					if err := addSFlowForBridge(row.New.Fields["name"].(string)); err != nil {
						klog.Errorf("add sflow for %s error, err:%s", row.New.Fields["name"].(string), err)
					}
				}
			} else {
				// delete
				if table == "Interface" {
					switch row.New.Fields["ifindex"].(type) {
					case float64:
						m.collectorCache.DelIface(uint32(row.Old.Fields["ifindex"].(float64)))
					}
				}
			}
		}
	}
}

func ovsdbTransact(client *ovsdb.OvsdbClient, database string, operation ...ovsdb.Operation) ([]ovsdb.OperationResult, error) {
	results, err := client.Transact(database, operation...)
	for item, result := range results {
		if result.Error != "" {
			return results, fmt.Errorf("operator %v: %s, details: %s", operation[item], result.Error, result.Details)
		}
	}

	return results, err
}

func addSFlowForBridge(brName string) error {
	client, err := ovsdb.ConnectUnix(ovsdb.DEFAULT_SOCK)
	if err != nil {
		return fmt.Errorf("connect to ovsdb: %s", err)
	}

	createSflowOperation := ovsdb.Operation{
		UUIDName: "dummy",
		Op:       "insert",
		Table:    "sFlow",
		Row: map[string]interface{}{
			"header":   SFlowHeader,
			"polling":  SFlowPooling,
			"targets":  fmt.Sprintf("127.0.0.1:%d", SFlowPort),
			"sampling": SFlowSampling,
		},
	}

	configBridgeOperation := ovsdb.Operation{
		Op:    "update",
		Table: "Bridge",
		Row:   map[string]interface{}{"sflow": ovsdb.UUID{GoUuid: "dummy"}},
		Where: []interface{}{[]interface{}{"name", "==", brName}},
	}

	_, err = ovsdbTransact(client, "Open_vSwitch", createSflowOperation, configBridgeOperation)
	if err != nil {
		return fmt.Errorf("set bridges sflow: %s", err)
	}

	return nil
}

func cleanSFlowOVSConfig() {
	klog.Infof("Cleaning OVS configuration")
	client, err := ovsdb.ConnectUnix(ovsdb.DEFAULT_SOCK)
	if err != nil {
		klog.Fatal("connect to ovsdb: %s", err)
	}

	configBridgeOperation := ovsdb.Operation{
		Op:    "update",
		Table: "Bridge",
		Row:   map[string]interface{}{"sflow": ovsdb.OvsSet{GoSet: []interface{}{}}},
		Where: []interface{}{[]interface{}{"_uuid", "excludes", ovsdb.UUID{GoUuid: emptyUUID}}},
	}

	_, err = ovsdbTransact(client, "Open_vSwitch", configBridgeOperation)
	if err != nil {
		klog.Fatal("clean bridges sflow error: %s", err)
	}
}

// ovsUpdateHandlerFunc implements ovsdb.NotificationHandler
type ovsUpdateHandlerFunc func(tableUpdates ovsdb.TableUpdates)

func (fn ovsUpdateHandlerFunc) Update(context interface{}, tableUpdates ovsdb.TableUpdates) {
	fn(tableUpdates)
}

func (fn ovsUpdateHandlerFunc) Locked([]interface{}) {
}

func (fn ovsUpdateHandlerFunc) Stolen([]interface{}) {
}

func (fn ovsUpdateHandlerFunc) Echo([]interface{}) {
}
