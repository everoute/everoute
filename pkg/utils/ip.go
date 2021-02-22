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

package utils

import (
	"github.com/smartxworks/lynx/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
)

// EqualIPs return true when two IP set have same IPaddresses.
func EqualIPs(ips1, ips2 []types.IPAddress) bool {
	toset := func(ips []types.IPAddress) sets.String {
		set := sets.NewString()
		for _, ip := range ips {
			set.Insert(ip.String())
		}
		return set
	}

	return len(ips1) == len(ips2) && toset(ips1).Equal(toset(ips2))
}
