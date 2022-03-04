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
	"bytes"
	"fmt"
	"github.com/everoute/everoute/pkg/apis/exporter/v1alpha1"
	"io/ioutil"
	"net"
	"os/exec"
	"reflect"
	"strconv"
	"strings"
	"time"

	ovsdb "github.com/contiv/libovsdb"
	"k8s.io/klog"

	"github.com/everoute/everoute/pkg/agent/datapath"
)

const (
	SFlowSampling = 64
	SFlowPooling  = 10
	SFlowHeader   = 128

	SFlowPort = 6666

	emptyUUID    = "00000000-0000-0000-0000-000000000000"
	vSwitchdPath = "/var/run/openvswitch/ovs-vswitchd"
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
		"Interface": {Select: selectAll, Columns: []string{"_uuid", "ifindex", "external_ids", "name"}},
		"Bridge":    {Select: selectAll, Columns: []string{"name"}},
		"Port":      {Select: selectAll, Columns: []string{"interfaces"}},
	}

	initial, err := m.ovsClient.Monitor("Open_vSwitch", nil, requests)
	if err != nil {
		klog.Errorf("monitor ovsdb error: %s", "Open_vSwitch", err)
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
	switch row.Fields["_uuid"].(type) {
	case ovsdb.UUID:
		iface.uuid = row.Fields["_uuid"].(ovsdb.UUID).GoUuid
	}

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
						klog.Errorf("add sFlow for %s error, err:%s", row.New.Fields["name"].(string), err)
					}
				}
				if table == "Port" {
					switch row.New.Fields["interfaces"].(type) {
					case ovsdb.OvsSet:
						if len(row.New.Fields["interfaces"].(ovsdb.OvsSet).GoSet) > 1 {
							for _, ifaceUUID := range row.New.Fields["interfaces"].(ovsdb.OvsSet).GoSet {
								switch ifaceUUID.(type) {
								case ovsdb.UUID:
									m.collectorCache.AddBondIf(ifaceUUID.(ovsdb.UUID).GoUuid)
								}
							}
						}
					}
				}
			} else {
				// delete
				if table == "Interface" {
					switch row.Old.Fields["ifindex"].(type) {
					case float64:
						m.collectorCache.DelIface(uint32(row.Old.Fields["ifindex"].(float64)))
					}
					switch row.Old.Fields["_uuid"].(type) {
					case ovsdb.UUID:
						m.collectorCache.DelBondIf(row.Old.Fields["_uuid"].(ovsdb.UUID).GoUuid)
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

func getOvsPid() string {
	data, err := ioutil.ReadFile(vSwitchdPath + ".pid")
	if err != nil {
		return "*"
	}
	return strings.Trim(string(data), " \n")
}

func OvsAppCtl(args ...string) []string {
	cmd := fmt.Sprintf("ovs-appctl -t %s.%s.ctl ", vSwitchdPath, getOvsPid())
	for _, item := range args {
		cmd += item + " "
	}

	b, err := exec.Command("/bin/sh", "-c", cmd).CombinedOutput()
	if err != nil {
		klog.Errorf("exec ovs-appctl error, cmd:%s, err:%s", cmd, err)
		return nil
	}
	out := bytes.NewBuffer(b).String()

	return strings.Split(strings.TrimSpace(out), "\n")
}

func parseTimeDuration(duration string) uint64 {
	d, err := time.ParseDuration(strings.ReplaceAll(duration, " ", ""))
	if err != nil {
		klog.Infof("parse time duration error,err:%s", err)
		return 0
	}
	return uint64(d.Milliseconds())
}

func strToUint64(str string) uint64 {
	num, _ := strconv.Atoi(str)
	return uint64(num)
}

func ovsBondShow(bondInfo []string, msg *v1alpha1.BondMsg) {
	var portName string
	var ifaceName string
	var isBasicInfo bool
	for _, line := range bondInfo {
		// new port
		if strings.HasPrefix(line, "----") {
			portName = strings.Trim(line, "- ")
			msg.Ports[portName] = &v1alpha1.BondPort{
				BondName: portName,
				Ifs:      make(map[string]*v1alpha1.BondInterface),
			}
			isBasicInfo = true
			continue
		}
		// end bond port info, next content will be interface info
		if strings.TrimSpace(line) == "" {
			isBasicInfo = false
			continue
		}
		if isBasicInfo {
			key := strings.TrimSpace(strings.Split(line, ":")[0])
			value := strings.TrimSpace(strings.Join(strings.Split(line, ":")[1:], ":"))
			switch key {
			case "bond_mode":
				msg.Ports[portName].BondMode = value
			case "updelay":
				msg.Ports[portName].UpDelay = parseTimeDuration(value)
			case "downdelay":
				msg.Ports[portName].DownDelay = parseTimeDuration(value)
			case "next rebalance":
				msg.Ports[portName].NextRebalance = parseTimeDuration(value)
			case "lacp_status":
				msg.Ports[portName].LacpStatus = value
			case "lacp_fallback_ab":
				msg.Ports[portName].LacpFallbackAb = value
			case "active slave mac":
				mac, _ := net.ParseMAC(strings.Split(value, "(")[0])
				msg.Ports[portName].ActiveSlaveMac = mac
				msg.Ports[portName].ActiveSlaveInterfaceName = strings.Trim(strings.Split(value, "(")[1], ")")
			}
		} else {
			// new interface
			if strings.HasPrefix(line, "slave") {
				ifaceName = strings.TrimSpace(strings.TrimPrefix(strings.Split(line, ":")[0], "slave"))
				if msg.Ports[portName].Ifs[ifaceName] == nil {
					msg.Ports[portName].Ifs[ifaceName] = &v1alpha1.BondInterface{}
				}
				msg.Ports[portName].Ifs[ifaceName].Name = ifaceName
				msg.Ports[portName].Ifs[ifaceName].Status = strings.TrimSpace(strings.Split(line, ":")[1])
			}
			if strings.TrimSpace(line) == "active slave" {
				msg.Ports[portName].Ifs[ifaceName].IsActiveSlave = true
			}
			if strings.HasPrefix(strings.TrimSpace(line), "may_enable") {
				mayEnable, _ := strconv.ParseBool(strings.TrimSpace(strings.Split(line, ":")[1]))
				msg.Ports[portName].Ifs[ifaceName].MayEnable = mayEnable
			}
		}
	}
}

func ovsLacpStat(lacpInfo []string, msg *v1alpha1.BondMsg) {
	var portName string
	var ifaceName string
	for _, line := range lacpInfo {
		// new port
		if strings.HasPrefix(line, "----") {
			portName = strings.TrimSpace(strings.ReplaceAll(strings.Trim(line, "- "), "statistics", ""))
			continue
		}
		if msg.Ports[portName] == nil {
			continue
		}
		if strings.TrimSpace(line) == "" {
			continue
		}
		// new interface
		if strings.HasPrefix(line, "slave") {
			ifaceName = strings.TrimSpace(strings.Split(line, ":")[1])
			continue
		}
		if msg.Ports[portName].Ifs[ifaceName] == nil {
			continue
		}
		key := strings.TrimSpace(strings.Split(line, ":")[0])
		value := strings.TrimSpace(strings.Join(strings.Split(line, ":")[1:], ":"))
		switch key {
		case "TX PDUs":
			msg.Ports[portName].Ifs[ifaceName].TxPdu = strToUint64(value)
		case "RX PDUs":
			msg.Ports[portName].Ifs[ifaceName].RxPdu = strToUint64(value)
		case "RX Bad PDUs":
			msg.Ports[portName].Ifs[ifaceName].RxBadPdu = strToUint64(value)
		case "RX Marker Request PDUs":
			msg.Ports[portName].Ifs[ifaceName].RxMarkerRequestPdu = strToUint64(value)
		case "Link Expired":
			msg.Ports[portName].Ifs[ifaceName].LinkExpired = strToUint64(value)
		case "Link Defaulted":
			msg.Ports[portName].Ifs[ifaceName].LinkDefaulted = strToUint64(value)
		case "Carrier Status Changed":
			msg.Ports[portName].Ifs[ifaceName].CarrierStatusChange = strToUint64(value)
		}
	}
}

func ovsLacpShow(lacpInfo []string, msg *v1alpha1.BondMsg) {
	var portName string
	var ifaceName string
	var isBasicInfo bool
	for _, line := range lacpInfo {
		// new port
		if strings.HasPrefix(line, "----") {
			portName = strings.TrimSpace(strings.Trim(line, "- "))
			isBasicInfo = true
			continue
		}
		if msg.Ports[portName] == nil {
			continue
		}
		// end bond port info, next content will be interface info
		if strings.TrimSpace(line) == "" {
			isBasicInfo = false
			continue
		}
		if isBasicInfo {
			key := strings.TrimSpace(strings.Split(line, ":")[0])
			value := strings.TrimSpace(strings.Join(strings.Split(line, ":")[1:], ":"))
			switch key {
			case "lacp_time":
				msg.Ports[portName].LacpTime = value
			}
		} else {
			if strings.HasPrefix(line, "slave") {
				ifaceName = strings.TrimSpace(strings.Split(line, ":")[1])
				continue
			}
			if msg.Ports[portName].Ifs[ifaceName] == nil {
				continue
			}
			key := strings.TrimSpace(strings.Split(line, ":")[0])
			value := strings.TrimSpace(strings.Join(strings.Split(line, ":")[1:], ":"))
			switch key {
			case "actor state":
				msg.Ports[portName].Ifs[ifaceName].ActorState = value
			case "partner state":
				msg.Ports[portName].Ifs[ifaceName].PartnerState = value
			}
		}
	}
}

func OvsBondInfo() *v1alpha1.BondMsg {
	msg := &v1alpha1.BondMsg{
		Ports: make(map[string]*v1alpha1.BondPort),
	}
	// bond/show process
	bondInfo := OvsAppCtl("bond/show")
	ovsBondShow(bondInfo, msg)

	// lacp/show-stats process
	lacpInfo := OvsAppCtl("lacp/show-stats")
	ovsLacpStat(lacpInfo, msg)

	// lacp/show process
	lacpInfo = OvsAppCtl("lacp/show")
	ovsLacpShow(lacpInfo, msg)

	return msg
}
