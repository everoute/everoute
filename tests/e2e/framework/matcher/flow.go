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

package matcher

import (
	"fmt"

	"github.com/onsi/gomega"
	"github.com/onsi/gomega/format"
	"github.com/onsi/gomega/types"
	"k8s.io/apimachinery/pkg/util/errors"
)

// ContainsFlow succeeds only if actual contains all of expected flow. Actual must be
// type of map[string][]string or []string.
func ContainsFlow(expected []string) types.GomegaMatcher {
	return &FlowMatcher{
		Expected: expected,
	}
}

type FlowMatcher struct {
	Expected []string
}

func (matcher *FlowMatcher) Match(actual interface{}) (success bool, err error) {
	switch actualTyped := actual.(type) {
	case map[string][]string:
		var errList []error
		var succeed = true
		for key, flows := range actualTyped {
			ok, err := matcher.ContainsFlow(flows)
			if err != nil {
				errList = append(errList, fmt.Errorf("key %s match error: %s", key, err))
			}
			succeed = succeed && ok
		}
		return succeed, errors.NewAggregate(errList)
	case []string:
		return matcher.ContainsFlow(actualTyped)
	default:
		return false, fmt.Errorf("must be type of []string or map[string]string")
	}
}

func (matcher *FlowMatcher) ContainsFlow(actualFlows []string) (success bool, err error) {
	elements := make([]interface{}, 0, len(matcher.Expected))
	for _, slice := range matcher.Expected {
		elements = append(elements, slice)
	}
	return gomega.ContainElements(elements...).Match(actualFlows)
}

func (matcher *FlowMatcher) FailureMessage(actual interface{}) (message string) {
	return format.Message(actual, "to contains", matcher.Expected)
}

func (matcher *FlowMatcher) NegatedFailureMessage(actual interface{}) (message string) {
	return format.Message(actual, "not to contains", matcher.Expected)
}

type RelativeFlowMatcher struct {
	Expected map[string][]string
}

// ContainsFlow succeeds only if actual contains expected flow. Actual must be
// type of map[string][]string or []string.
func ContainsRelativeFlow(expected map[string][]string) types.GomegaMatcher {
	return &RelativeFlowMatcher{
		Expected: expected,
	}
}

func (matcher *RelativeFlowMatcher) Match(actual interface{}) (success bool, err error) {
	switch actualTyped := actual.(type) {
	case map[string][]string:
		var errList []error
		var succeed = true
		for key, flows := range actualTyped {
			// FlowMatcher of this agent
			flowMatcher := FlowMatcher{Expected: matcher.Expected[key]}
			ok, err := flowMatcher.ContainsFlow(flows)
			if err != nil {
				errList = append(errList, fmt.Errorf("key %s match error: %s", key, err))
			}
			succeed = succeed && ok
		}
		return succeed, errors.NewAggregate(errList)
	default:
		return false, fmt.Errorf("must be type of map[string]string")
	}
}

func (matcher *RelativeFlowMatcher) FailureMessage(actual interface{}) (message string) {
	return format.Message(actual, "to contains", matcher.Expected)
}

func (matcher *RelativeFlowMatcher) NegatedFailureMessage(actual interface{}) (message string) {
	return format.Message(actual, "not to contains", matcher.Expected)
}
