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

package monitor

import (
	"fmt"
	"net"

	ovsdb "github.com/contiv/libovsdb"

	agentv1alpha1 "github.com/everoute/everoute/pkg/apis/agent/v1alpha1"
)

var (
	// vlanModeMap mapping vlan_mode from ovsdb to everoute api
	vlanModeMap = map[string]agentv1alpha1.VlanMode{
		"access":          agentv1alpha1.VlanModeAccess,
		"dot1q-tunnel":    agentv1alpha1.VlanModeDot1qTunnel,
		"native-tagged":   agentv1alpha1.VlanModeNativeTagged,
		"native-untagged": agentv1alpha1.VlanModeNativeUntagged,
		"trunk":           agentv1alpha1.VlanModeTrunk,
	}
	// bondModeMap mapping bond_mode from ovsdb to everoute api
	bondModeMap = map[string]agentv1alpha1.BondMode{
		"active-backup": agentv1alpha1.BondModeActiveBackup,
		"balance-slb":   agentv1alpha1.BondModeBalanceSLB,
		"balance-tcp":   agentv1alpha1.BondModeBalanceTCP,
	}
)

// ovsUpdateHandlerFunc implements ovsdb.NotificationHandler
type ovsUpdateHandlerFunc func(tableUpdates ovsdb.TableUpdates)

func (fn ovsUpdateHandlerFunc) Update(_ interface{}, tableUpdates ovsdb.TableUpdates) {
	fn(tableUpdates)
}

func (fn ovsUpdateHandlerFunc) Locked([]interface{}) {
}

func (fn ovsUpdateHandlerFunc) Stolen([]interface{}) {
}

func (fn ovsUpdateHandlerFunc) Echo([]interface{}) {
}

func listVlanTrunks(trunk interface{}) []float64 {
	var trunkList []float64
	switch t := trunk.(type) {
	case float64:
		return []float64{t}
	case ovsdb.OvsSet:
		trunkSet := trunk.(ovsdb.OvsSet).GoSet
		for item := range trunkSet {
			trunkList = append(trunkList, listVlanTrunks(trunkSet[item])...)
		}
	}

	return trunkList
}

func getIPv4Addr(externalIDs map[interface{}]interface{}) net.IP {
	if ip, ok := externalIDs[LocalEndpointIPv4]; ok {
		return net.ParseIP(ip.(string)).To4()
	}

	return nil
}

func getDriverNameFromInterface(row ovsdb.Row) string {
	if status, ok := row.Fields[InterfaceStatus].(ovsdb.OvsMap); ok {
		if driver, ok := status.GoMap[InterfaceDriver]; ok {
			return driver.(string)
		}
	}

	return ""
}

func getMacStrFromInterface(row ovsdb.Row) (string, error) {
	var macStr string
	driver := getDriverNameFromInterface(row)
	if driver == "" {
		return "", fmt.Errorf("get interface driver failed, interface row: %+v", row)
	}

	isErEp, mac := isErEndpointIntface(row, driver)
	if isErEp {
		macStr = mac
	} else {
		macStr = row.Fields["mac_in_use"].(string)
	}

	if _, err := net.ParseMAC(macStr); err != nil {
		return "", err
	}

	return macStr, nil
}

func isErEndpointIntface(row ovsdb.Row, driver string) (bool, string) {
	if driver == VMNicDriver || driver == PodNicDriver {
		if externalIDs, ok := row.Fields["external_ids"].(ovsdb.OvsMap); ok {
			if mac, ok := externalIDs.GoMap[LocalEndpointIdentity]; ok {
				return true, mac.(string)
			}
		}
	}

	return false, ""
}
