/*
Copyright 2020 The Kubernetes Authors.

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

package model

import (
	"sort"
	"strings"
	"sync"

	"github.com/fatih/color"
	"k8s.io/klog"
)

// TruthTable takes in n items and maintains an n x n table of booleans for each ordered pair
// This is forked from k8s.io/kubernetes/test/e2e/network/netpol.TruthTable
type TruthTable struct {
	lock sync.RWMutex

	froms []string
	tos   []string

	toSet  map[string]bool
	values map[string]map[string]bool
}

// NewTruthTableFromItems creates a new truth table with items
func NewTruthTableFromItems(items []string, defaultValue *bool) *TruthTable {
	return NewTruthTable(items, items, defaultValue)
}

// NewTruthTable creates a new truth table with froms and tos
func NewTruthTable(froms []string, tos []string, defaultValue *bool) *TruthTable {
	// sort froms and tos, convenient for comparison two truthTable
	sort.Strings(froms)
	sort.Strings(tos)
	values := map[string]map[string]bool{}
	for _, from := range froms {
		values[from] = map[string]bool{}
		for _, to := range tos {
			if defaultValue != nil {
				values[from][to] = *defaultValue
			}
		}
	}
	toSet := map[string]bool{}
	for _, to := range tos {
		toSet[to] = true
	}
	return &TruthTable{
		froms:  froms,
		tos:    tos,
		toSet:  toSet,
		values: values,
	}
}

// IsComplete returns true if there's a value set for every single pair of items, otherwise it returns false.
func (tt *TruthTable) IsComplete() bool {
	for _, from := range tt.froms {
		for _, to := range tt.tos {
			if _, ok := tt.values[from][to]; !ok {
				return false
			}
		}
	}
	return true
}

// Set sets the value for from->to
func (tt *TruthTable) Set(from string, to string, value bool) {
	tt.lock.Lock()
	defer tt.lock.Unlock()

	dict, ok := tt.values[from]
	if !ok {
		klog.Fatalf("from-key %s not found", from)
	}
	if _, ok := tt.toSet[to]; !ok {
		klog.Fatalf("to-key %s not allowed", to)
	}
	dict[to] = value
}

// SetAllFrom sets all values where from = 'from'
func (tt *TruthTable) SetAllFrom(from string, value bool) {
	tt.lock.Lock()
	defer tt.lock.Unlock()

	dict, ok := tt.values[from]
	if !ok {
		klog.Fatalf("from-key %s not found", from)
	}
	for _, to := range tt.tos {
		dict[to] = value
	}
}

// SetAllTo sets all values where to = 'to'
func (tt *TruthTable) SetAllTo(to string, value bool) {
	tt.lock.Lock()
	defer tt.lock.Unlock()

	if _, ok := tt.toSet[to]; !ok {
		klog.Fatalf("to-key %s not found", to)
	}
	for _, from := range tt.froms {
		tt.values[from][to] = value
	}
}

// Get gets the specified value
func (tt *TruthTable) Get(from string, to string) bool {
	tt.lock.RLock()
	defer tt.lock.RUnlock()

	dict, ok := tt.values[from]
	if !ok {
		klog.Fatalf("from-key %s not found", from)
	}
	val, ok := dict[to]
	if !ok {
		klog.Fatalf("to-key %s not found in map (%+v)", to, dict)
	}
	return val
}

// Compare is used to check two truth tables for equality, returning its
// result in the form of a third truth table.  Both tables are expected to
// have identical items.
func (tt *TruthTable) Compare(other *TruthTable) *TruthTable {
	tt.lock.RLock()
	defer tt.lock.RUnlock()

	if len(tt.froms) != len(other.froms) || len(tt.tos) != len(other.tos) {
		klog.Fatalf("cannot compare tables of different dimensions")
	}
	for i, fr := range tt.froms {
		if other.froms[i] != fr {
			klog.Fatalf("cannot compare: from keys at index %d do not match (%s vs %s)", i, other.froms[i], fr)
		}
	}
	for i, to := range tt.tos {
		if other.tos[i] != to {
			klog.Fatalf("cannot compare: to keys at index %d do not match (%s vs %s)", i, other.tos[i], to)
		}
	}

	values := map[string]map[string]bool{}
	for from, dict := range tt.values {
		values[from] = map[string]bool{}
		for to, val := range dict {
			values[from][to] = val == other.values[from][to]
		}
	}
	return &TruthTable{
		froms:  tt.froms,
		tos:    tt.tos,
		toSet:  tt.toSet,
		values: values,
	}
}

// CompareResultBool is used to check two truth tables for equality, return
// true when equality. IgnoreLoopback would ignore lookback equality.
func (tt *TruthTable) CompareResultBool(other *TruthTable, ignoreLoopback bool) bool {
	comparison := tt.Compare(other)
	if !comparison.IsComplete() {
		klog.Fatalf("observations not complete!")
	}
	var falseObs, trueObs, ignoredObs = 0, 0, 0
	for from, dict := range comparison.values {
		for to, val := range dict {
			if ignoreLoopback && from == to {
				// Never fail on loopback, because its not yet defined.
				ignoredObs++
			} else if val {
				trueObs++
			} else {
				falseObs++
			}
		}
	}
	return falseObs == 0
}

// PrettyPrint produces a nice visual representation.
func (tt *TruthTable) PrettyPrint(withColor bool) string {
	var printChar = [3]string{color.YellowString("-"), color.GreenString("."), color.RedString("x")}
	if !withColor {
		printChar = [3]string{"-", ".", "x"}
	}

	tt.lock.RLock()
	defer tt.lock.RUnlock()

	var header = strings.Join(append([]string{"-"}, tt.tos...), "\t")
	var lines = []string{header}

	for _, from := range tt.froms {
		newLine := []string{from}

		for _, to := range tt.tos {
			val, ok := tt.values[from][to]
			switch {
			case !ok:
				newLine = append(newLine, printChar[0])
			case val:
				newLine = append(newLine, printChar[1])
			default:
				newLine = append(newLine, printChar[2])
			}
		}
		lines = append(lines, strings.Join(newLine, "\t"))
	}

	return strings.Join(lines, "\n")
}
