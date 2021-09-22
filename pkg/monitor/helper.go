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

func (fn ovsUpdateHandlerFunc) Update(context interface{}, tableUpdates ovsdb.TableUpdates) {
	fn(tableUpdates)
}

func (fn ovsUpdateHandlerFunc) Locked([]interface{}) {
}

func (fn ovsUpdateHandlerFunc) Stolen([]interface{}) {
}

func (fn ovsUpdateHandlerFunc) Echo([]interface{}) {
}
