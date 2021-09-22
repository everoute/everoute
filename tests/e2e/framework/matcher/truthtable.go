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
	"reflect"

	"github.com/onsi/gomega/format"
	"github.com/onsi/gomega/types"

	"github.com/everoute/everoute/tests/e2e/framework/model"
)

func MatchTruthTable(expected *model.TruthTable, ignoreLoopback bool) types.GomegaMatcher {
	return &TruthTableMatcher{
		Expected:       expected,
		IgnoreLoopback: ignoreLoopback,
	}
}

type TruthTableMatcher struct {
	Expected       *model.TruthTable
	IgnoreLoopback bool
}

func (matcher *TruthTableMatcher) Match(actual interface{}) (success bool, err error) {
	if actual == nil && matcher.Expected == nil {
		return true, nil
	}

	actualTable, ok := actual.(*model.TruthTable)
	if !ok {
		return false, fmt.Errorf("must be type of %s", reflect.TypeOf(&model.TruthTable{}))
	}

	return actualTable.CompareResultBool(matcher.Expected, matcher.IgnoreLoopback), nil
}

func (matcher *TruthTableMatcher) FailureMessage(actual interface{}) (message string) {
	if actualTable, ok := actual.(*model.TruthTable); ok {
		return format.Message(actualTable.PrettyPrint(false), "to equal", matcher.Expected.PrettyPrint(false))
	}
	return format.Message(actual, "to equal", matcher.Expected.PrettyPrint(false))
}

func (matcher *TruthTableMatcher) NegatedFailureMessage(actual interface{}) (message string) {
	if actualTable, ok := actual.(*model.TruthTable); ok {
		return format.Message(actualTable.PrettyPrint(false), "to not equal", matcher.Expected.PrettyPrint(false))
	}
	return format.Message(actual, "to not equal", matcher.Expected.PrettyPrint(false))
}
