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

package labels_test

import (
	"fmt"
	"testing"

	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/everoute/everoute/pkg/labels"
)

func TestSelectorIsValid(t *testing.T) {
	tests := []struct {
		selector        *labels.Selector
		expectedValid   bool
		expectedMessage string
	}{
		{
			selector:      nil,
			expectedValid: true,
		},
		{
			selector: &labels.Selector{
				LabelSelector: metav1.LabelSelector{
					MatchLabels: map[string]string{"foo": "bar"},
				},
				ExtendMatchLabels: map[string][]string{"foz": {"bar", "baz"}},
			},
			expectedValid: true,
		},

		// the following contains invalid cause
		{
			selector: &labels.Selector{
				ExtendMatchLabels: map[string][]string{"foz": {}},
			},
			expectedValid:   false,
			expectedMessage: "values with key foz must be non-empty on ExtendMatchLabels",
		},
		{
			selector: &labels.Selector{
				LabelSelector: metav1.LabelSelector{
					MatchExpressions: []metav1.LabelSelectorRequirement{{
						Key:      "foo",
						Operator: metav1.LabelSelectorOpIn,
					}},
				},
			},
			expectedValid:   false,
			expectedMessage: "values with key foo of operator In must be non-empty on MatchExpressions",
		},
		{
			selector: &labels.Selector{
				LabelSelector: metav1.LabelSelector{
					MatchExpressions: []metav1.LabelSelectorRequirement{{
						Key:      "foo",
						Operator: metav1.LabelSelectorOpNotIn,
					}},
				},
			},
			expectedValid:   false,
			expectedMessage: "values with key foo of operator NotIn must be non-empty on MatchExpressions",
		},
		{
			selector: &labels.Selector{
				LabelSelector: metav1.LabelSelector{
					MatchExpressions: []metav1.LabelSelectorRequirement{{
						Key:      "foo",
						Operator: metav1.LabelSelectorOpExists,
						Values:   []string{"foo", "bar"},
					}},
				},
			},
			expectedValid:   false,
			expectedMessage: "values with key foo of operator Exists must be empty on MatchExpressions",
		},
		{
			selector: &labels.Selector{
				LabelSelector: metav1.LabelSelector{
					MatchExpressions: []metav1.LabelSelectorRequirement{{
						Key:      "foo",
						Operator: metav1.LabelSelectorOpDoesNotExist,
						Values:   []string{"foo", "bar"},
					}},
				},
			},
			expectedValid:   false,
			expectedMessage: "values with key foo of operator DoesNotExist must be empty on MatchExpressions",
		},
		{
			selector: &labels.Selector{
				LabelSelector: metav1.LabelSelector{
					MatchExpressions: []metav1.LabelSelectorRequirement{{
						Key:      "foo",
						Operator: "bar",
					}},
				},
			},
			expectedValid:   false,
			expectedMessage: "operator bar is not supported on MatchExpressions",
		},
	}

	for index, tt := range tests {
		t.Run(fmt.Sprintf("test%d", index), func(t *testing.T) {
			RegisterTestingT(t)
			valid, message := tt.selector.IsValid()
			Expect(valid).To(Equal(tt.expectedValid))
			Expect(message).To(Equal(tt.expectedMessage))
		})
	}
}

func TestSelectorMatch(t *testing.T) {
	tests := []struct {
		selector      *labels.Selector
		labelSet      labels.Set
		expectedMatch bool
	}{
		// nil selector matches nothing
		{
			selector:      nil,
			labelSet:      nil,
			expectedMatch: false,
		},
		{
			selector:      nil,
			labelSet:      map[string]sets.String{"foo": sets.NewString("bar")},
			expectedMatch: false,
		},
		// empty selector matches everything
		{
			selector:      &labels.Selector{},
			labelSet:      nil,
			expectedMatch: true,
		},
		{
			selector:      &labels.Selector{},
			labelSet:      map[string]sets.String{"foo": sets.NewString("bar")},
			expectedMatch: true,
		},
		// match selector.MatchLabels
		{
			selector: &labels.Selector{
				LabelSelector: metav1.LabelSelector{
					MatchLabels: map[string]string{"foo": "bar"},
				},
			},
			labelSet:      nil,
			expectedMatch: false,
		},
		{
			selector: &labels.Selector{
				LabelSelector: metav1.LabelSelector{
					MatchLabels: map[string]string{"foo": "bar"},
				},
			},
			labelSet:      map[string]sets.String{"foz": sets.NewString("baz")},
			expectedMatch: false,
		},
		{
			selector: &labels.Selector{
				LabelSelector: metav1.LabelSelector{
					MatchLabels: map[string]string{"foo": "bar"},
				},
			},
			labelSet:      map[string]sets.String{"foo": sets.NewString("baz")},
			expectedMatch: false,
		},
		{
			selector: &labels.Selector{
				LabelSelector: metav1.LabelSelector{
					MatchLabels: map[string]string{"foo": "bar"},
				},
			},
			labelSet:      map[string]sets.String{"foo": sets.NewString("bar", "baz")},
			expectedMatch: true,
		},
		{
			selector: &labels.Selector{
				LabelSelector: metav1.LabelSelector{
					MatchLabels: map[string]string{"foo": "bar"},
				},
			},
			labelSet:      map[string]sets.String{"foo": sets.NewString("bar")},
			expectedMatch: true,
		},
		{
			selector: &labels.Selector{
				LabelSelector: metav1.LabelSelector{
					MatchLabels: map[string]string{"foo": "bar"},
				},
			},
			labelSet:      map[string]sets.String{"foo": sets.NewString("bar"), "foz": sets.NewString("baz")},
			expectedMatch: true,
		},
		// match selector.ExtendMatchLabels
		{
			selector: &labels.Selector{
				ExtendMatchLabels: map[string][]string{"foo": {"bar", "baz"}},
			},
			labelSet:      nil,
			expectedMatch: false,
		},
		{
			selector: &labels.Selector{
				ExtendMatchLabels: map[string][]string{"foo": {"bar", "baz"}},
			},
			labelSet:      map[string]sets.String{"foz": sets.NewString("baz")},
			expectedMatch: false,
		},
		{
			selector: &labels.Selector{
				ExtendMatchLabels: map[string][]string{"foo": {"bar", "baz"}},
			},
			labelSet:      map[string]sets.String{"foo": sets.NewString("baz")},
			expectedMatch: false,
		},
		{
			selector: &labels.Selector{
				ExtendMatchLabels: map[string][]string{"foo": {"bar", "baz"}},
			},
			labelSet:      map[string]sets.String{"foo": sets.NewString("bar", "baz", "qux")},
			expectedMatch: true,
		},
		{
			selector: &labels.Selector{
				ExtendMatchLabels: map[string][]string{"foo": {"bar", "baz"}},
			},
			labelSet:      map[string]sets.String{"foo": sets.NewString("bar", "baz")},
			expectedMatch: true,
		},
		// match selector.MatchExpressions
		// OpIN
		{
			selector: &labels.Selector{
				LabelSelector: metav1.LabelSelector{
					MatchExpressions: []metav1.LabelSelectorRequirement{{
						Key:      "foo",
						Operator: metav1.LabelSelectorOpIn,
						Values:   []string{"bar", "baz", "qux"},
					}},
				},
			},
			labelSet:      nil,
			expectedMatch: false,
		},
		{
			selector: &labels.Selector{
				LabelSelector: metav1.LabelSelector{
					MatchExpressions: []metav1.LabelSelectorRequirement{{
						Key:      "foo",
						Operator: metav1.LabelSelectorOpIn,
						Values:   []string{"bar", "baz", "qux"},
					}},
				},
			},
			labelSet:      map[string]sets.String{"foo": sets.NewString("bar", "foz")},
			expectedMatch: false,
		},
		{
			selector: &labels.Selector{
				LabelSelector: metav1.LabelSelector{
					MatchExpressions: []metav1.LabelSelectorRequirement{{
						Key:      "foo",
						Operator: metav1.LabelSelectorOpIn,
						Values:   []string{"bar", "baz", "qux"},
					}},
				},
			},
			labelSet:      map[string]sets.String{"foo": sets.NewString("bar", "qux")},
			expectedMatch: true,
		},
		// OpNotIN
		{
			selector: &labels.Selector{
				LabelSelector: metav1.LabelSelector{
					MatchExpressions: []metav1.LabelSelectorRequirement{{
						Key:      "foo",
						Operator: metav1.LabelSelectorOpNotIn,
						Values:   []string{"bar", "baz", "qux"},
					}},
				},
			},
			labelSet:      nil,
			expectedMatch: true,
		},
		{
			selector: &labels.Selector{
				LabelSelector: metav1.LabelSelector{
					MatchExpressions: []metav1.LabelSelectorRequirement{{
						Key:      "foo",
						Operator: metav1.LabelSelectorOpNotIn,
						Values:   []string{"bar", "baz", "qux"},
					}},
				},
			},
			labelSet:      map[string]sets.String{"foz": sets.NewString("bar")},
			expectedMatch: true,
		},
		{
			selector: &labels.Selector{
				LabelSelector: metav1.LabelSelector{
					MatchExpressions: []metav1.LabelSelectorRequirement{{
						Key:      "foo",
						Operator: metav1.LabelSelectorOpNotIn,
						Values:   []string{"bar", "baz", "qux"},
					}},
				},
			},
			labelSet:      map[string]sets.String{"foo": sets.NewString("foz", "quz")},
			expectedMatch: true,
		},
		{
			selector: &labels.Selector{
				LabelSelector: metav1.LabelSelector{
					MatchExpressions: []metav1.LabelSelectorRequirement{{
						Key:      "foo",
						Operator: metav1.LabelSelectorOpNotIn,
						Values:   []string{"bar", "baz", "qux"},
					}},
				},
			},
			labelSet:      map[string]sets.String{"foo": sets.NewString("bar", "qux")},
			expectedMatch: false,
		},
		{
			selector: &labels.Selector{
				LabelSelector: metav1.LabelSelector{
					MatchExpressions: []metav1.LabelSelectorRequirement{{
						Key:      "foo",
						Operator: metav1.LabelSelectorOpNotIn,
						Values:   []string{"bar", "baz", "qux"},
					}},
				},
			},
			labelSet:      map[string]sets.String{"foo": sets.NewString("bar", "foz")},
			expectedMatch: false,
		},
		// OpExists
		{
			selector: &labels.Selector{
				LabelSelector: metav1.LabelSelector{
					MatchExpressions: []metav1.LabelSelectorRequirement{{
						Key:      "foo",
						Operator: metav1.LabelSelectorOpExists,
					}},
				},
			},
			labelSet:      nil,
			expectedMatch: false,
		},
		{
			selector: &labels.Selector{
				LabelSelector: metav1.LabelSelector{
					MatchExpressions: []metav1.LabelSelectorRequirement{{
						Key:      "foo",
						Operator: metav1.LabelSelectorOpExists,
					}},
				},
			},
			labelSet:      map[string]sets.String{"foz": sets.NewString("bar", "qux")},
			expectedMatch: false,
		},
		{
			selector: &labels.Selector{
				LabelSelector: metav1.LabelSelector{
					MatchExpressions: []metav1.LabelSelectorRequirement{{
						Key:      "foo",
						Operator: metav1.LabelSelectorOpExists,
					}},
				},
			},
			labelSet:      map[string]sets.String{"foo": sets.NewString("bar", "qux")},
			expectedMatch: true,
		},
		// OpNotExists
		{
			selector: &labels.Selector{
				LabelSelector: metav1.LabelSelector{
					MatchExpressions: []metav1.LabelSelectorRequirement{{
						Key:      "foo",
						Operator: metav1.LabelSelectorOpDoesNotExist,
					}},
				},
			},
			labelSet:      nil,
			expectedMatch: true,
		},
		{
			selector: &labels.Selector{
				LabelSelector: metav1.LabelSelector{
					MatchExpressions: []metav1.LabelSelectorRequirement{{
						Key:      "foo",
						Operator: metav1.LabelSelectorOpDoesNotExist,
					}},
				},
			},
			labelSet:      map[string]sets.String{"foo": sets.NewString("bar", "qux")},
			expectedMatch: false,
		},
		{
			selector: &labels.Selector{
				LabelSelector: metav1.LabelSelector{
					MatchExpressions: []metav1.LabelSelectorRequirement{{
						Key:      "foo",
						Operator: metav1.LabelSelectorOpDoesNotExist,
					}},
				},
			},
			labelSet:      map[string]sets.String{"foz": sets.NewString("bar", "qux")},
			expectedMatch: true,
		},
	}

	for index, tt := range tests {
		t.Run(fmt.Sprintf("test%d", index), func(t *testing.T) {
			RegisterTestingT(t)
			matched := tt.selector.Matches(tt.labelSet)
			Expect(matched).Should(Equal(tt.expectedMatch))
		})
	}
}
