/*
Copyright 2022 The Everoute Authors.

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

package labels

import (
	"fmt"
	"math"

	"k8s.io/apimachinery/pkg/util/sets"
)

// Set contains a set of labels
type Set map[string]sets.String

const maxLabelsSize = math.MaxInt16

// AsSet converts a map of labels and extend labels to a label set
func AsSet(labels map[string]string, extendLabels map[string][]string) (Set, error) {
	// fix: Size computation for allocation may overflow
	if len(labels) > maxLabelsSize {
		return nil, fmt.Errorf("too many labels: %d", len(labels))
	}
	if len(extendLabels) > maxLabelsSize {
		return nil, fmt.Errorf("too many extend labels: %d", len(extendLabels))
	}

	var labelSet = make(Set, len(labels)+len(extendLabels))

	for key, value := range labels {
		labelSet[key] = sets.NewString(value)
	}

	for key, valueSet := range extendLabels {
		if len(valueSet) == 0 {
			return nil, fmt.Errorf("extend label values with key %s is empty", key)
		}
		if _, ok := labelSet[key]; ok {
			return nil, fmt.Errorf("extend label with key %s already exists", key)
		}
		labelSet[key] = sets.NewString(valueSet...)
	}

	return labelSet, nil
}

// Equals returns true if two extend labels are same
func Equals(extendLabels1, extendLabels2 map[string][]string) bool {
	if len(extendLabels1) != len(extendLabels2) {
		return false
	}

	for key, valueSet1 := range extendLabels1 {
		valueSet2, ok := extendLabels2[key]
		if !ok {
			return false
		}
		if len(valueSet1) != len(valueSet2) {
			return false
		}
		if !sets.NewString(valueSet1...).Equal(sets.NewString(valueSet2...)) {
			return false
		}
	}

	return true
}
