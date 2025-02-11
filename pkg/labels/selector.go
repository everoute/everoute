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

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
)

// Selector extends metav1.LabelSelector, it allows select multiple labels with same key but
// different value. The result of matchLabels and matchExpressions and extendMatchLabels are
// ANDed. An empty selector matches all objects. A null selector matches no objects.
// The matched labels MUST be the superset of the MatchLabels and ExtendMatchLabels.
// +k8s:deepcopy-gen=true
type Selector struct {
	metav1.LabelSelector `json:",inline"`

	// ExtendMatchLabels allows match labels with the same key but different value.
	// e.g. {key: [v1, v2]} matches labels: {key: v1, key: v2} and {key: v1, key: v2, key: v3}
	// +optional
	ExtendMatchLabels map[string][]string `json:"extendMatchLabels,omitempty"`

	// MatchNothing does not match any labels when set to true
	MatchNothing bool `json:"matchNothing,omitempty"`
}

// FromLabelSelector covert metav1.LabelSelector to Selector
func FromLabelSelector(labelSelector *metav1.LabelSelector) *Selector {
	if labelSelector == nil {
		return nil
	}
	return &Selector{LabelSelector: *labelSelector}
}

// IsValid checks if the selector is valid, and give a detailed error message if not.
func (in *Selector) IsValid() (bool, string) {
	if in == nil {
		return true, ""
	}

	for key, value := range in.ExtendMatchLabels {
		if len(value) == 0 {
			return false, fmt.Sprintf("values with key %s must be non-empty on ExtendMatchLabels", key)
		}
	}

	for _, expr := range in.LabelSelector.MatchExpressions {
		switch expr.Operator {
		case metav1.LabelSelectorOpIn, metav1.LabelSelectorOpNotIn:
			if len(expr.Values) == 0 {
				return false, fmt.Sprintf("values with key %s of operator %s must be non-empty on MatchExpressions", expr.Key, expr.Operator)
			}
		case metav1.LabelSelectorOpExists, metav1.LabelSelectorOpDoesNotExist:
			if len(expr.Values) != 0 {
				return false, fmt.Sprintf("values with key %s of operator %s must be empty on MatchExpressions", expr.Key, expr.Operator)
			}
		default:
			return false, fmt.Sprintf("operator %s is not supported on MatchExpressions", expr.Operator)
		}
	}

	return true, ""
}

// Matches returns true if the labelSet match the selector.
// We suppose the selector and labelSet are valid, otherwise the result is undefined.
func (in *Selector) Matches(labelSet Set) bool {
	if in == nil || in.MatchNothing {
		return false
	}

	// labels should be the superset of match labels
	for key, value := range in.LabelSelector.MatchLabels {
		if !labelSet[key].IsSuperset(sets.New(value)) {
			return false
		}
	}

	// labesl should be the superset of extend match labels
	for key, valueSet := range in.ExtendMatchLabels {
		if !labelSet[key].IsSuperset(sets.New(valueSet...)) {
			return false
		}
	}

	for _, expr := range in.LabelSelector.MatchExpressions {
		labelValueSet, ok := labelSet[expr.Key]
		switch expr.Operator {
		case metav1.LabelSelectorOpIn:
			if !ok || len(labelValueSet) == 0 {
				return false
			}
			if !sets.New(expr.Values...).IsSuperset(labelValueSet) {
				return false
			}
		case metav1.LabelSelectorOpNotIn:
			if labelValueSet.HasAny(expr.Values...) {
				return false
			}
		case metav1.LabelSelectorOpExists:
			if !ok || len(labelValueSet) == 0 {
				return false
			}
		case metav1.LabelSelectorOpDoesNotExist:
			if ok {
				return false
			}
		}
	}

	return true
}
