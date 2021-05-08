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

package types

import (
	agentv1alpha1 "github.com/smartxworks/lynx/pkg/apis/agent/v1alpha1"
)

// ExternalID describe the externalID of an endpoint.
type ExternalID struct {
	Name  string `json:"Name"`
	Value string `json:"Value"`
}

// ExternalID Name and Value should not containers separator '/', this is
// validated by lynx validate webhook.
const (
	Separator = '/'
)

// MatchIface return the matches ovs interface index, if unmatch, index will be -1.
func (n ExternalID) MatchIface(ifaces []agentv1alpha1.OVSInterface) (index int, matches bool) {
	const unMatchIndex = -1

	for item := range ifaces {
		if ifaces[item].ExternalIDs[n.Name] == n.Value {
			return item, true
		}
	}
	return unMatchIndex, false
}

// String returns the general purpose string representation
// Eg. endpoint.lynx.smartx.com/ep01
func (n ExternalID) String() string {
	return n.Name + string(Separator) + n.Value
}
