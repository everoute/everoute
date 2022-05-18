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
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/everoute/everoute/pkg/labels"
)

func TestAsSet(t *testing.T) {
	tests := []struct {
		labels           map[string]string
		extendLabels     map[string][]string
		expectedSet      labels.Set
		expectedHasError bool
	}{
		{
			expectedSet: labels.Set{},
		},
		{
			labels:      map[string]string{"foo": "bar"},
			expectedSet: labels.Set{"foo": sets.NewString("bar")},
		},
		{
			extendLabels: map[string][]string{"foo": {"bar", "baz"}},
			expectedSet:  labels.Set{"foo": sets.NewString("bar", "baz")},
		},
		{
			labels:       map[string]string{"foo": "bar"},
			extendLabels: map[string][]string{"foz": {"baz"}},
			expectedSet:  labels.Set{"foo": sets.NewString("bar"), "foz": sets.NewString("baz")},
		},
		{
			labels:       map[string]string{"foo": "bar"},
			extendLabels: map[string][]string{"foz": {"baz", "qux"}},
			expectedSet:  labels.Set{"foo": sets.NewString("bar"), "foz": sets.NewString("baz", "qux")},
		},
		{
			labels:       map[string]string{"foo": ""},
			extendLabels: map[string][]string{"bar": {""}},
			expectedSet:  labels.Set{"foo": sets.NewString(""), "bar": sets.NewString("")},
		},
		{
			extendLabels:     map[string][]string{"foo": nil},
			expectedHasError: true,
		},
		{
			labels:           map[string]string{"foo": "bar"},
			extendLabels:     map[string][]string{"foo": {"bar", "baz"}},
			expectedHasError: true,
		},
	}

	for index, tt := range tests {
		t.Run(fmt.Sprintf("test%d", index), func(t *testing.T) {
			RegisterTestingT(t)
			set, err := labels.AsSet(tt.labels, tt.extendLabels)
			Expect(tt.expectedHasError).Should(Equal(err != nil))
			Expect(tt.expectedSet).Should(Equal(set))
		})
	}
}

func TestEqual(t *testing.T) {
	tests := []struct {
		labelSet1 map[string][]string
		labelSet2 map[string][]string
		equal     bool
	}{
		{
			labelSet1: map[string][]string{},
			labelSet2: nil,
			equal:     true,
		},
		{
			labelSet1: map[string][]string{"foo": {"bar", "baz"}, "foz": {"qux"}},
			labelSet2: map[string][]string{"foz": {"qux"}, "foo": {"baz", "bar"}},
			equal:     true,
		},
		{
			labelSet1: map[string][]string{"foo": {"bar", "baz"}},
			labelSet2: map[string][]string{"foo": {"baz", "bar"}},
			equal:     true,
		},
		{
			labelSet1: map[string][]string{"foo": {"bar", "baz"}},
			labelSet2: map[string][]string{"foz": {"qux"}, "foo": {"baz", "bar"}},
			equal:     false,
		},
		{
			labelSet1: map[string][]string{"foo": {"bar", "baz", "qux"}},
			labelSet2: map[string][]string{"foo": {"baz", "bar"}},
			equal:     false,
		},
	}

	for index, tt := range tests {
		t.Run(fmt.Sprintf("test%d", index), func(t *testing.T) {
			RegisterTestingT(t)
			Expect(labels.Equals(tt.labelSet1, tt.labelSet2)).Should(Equal(tt.equal))
		})
	}
}
