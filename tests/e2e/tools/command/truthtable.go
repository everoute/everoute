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

package command

import (
	"github.com/fatih/color"
	"k8s.io/klog"
	"strings"
	"sync"
)

// TruthTable takes in n items and maintains an n x n table of booleans for each ordered pair
type TruthTable struct {
	lock sync.RWMutex

	froms []string
	tos   []string

	toSet  map[string]bool
	values map[string]map[string]bool
}

// NewTruthTable creates a new truth table with froms and tos
func NewTruthTable(froms []string, tos []string, defaultValue *bool) *TruthTable {
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

func (tt *TruthTable) PrintLength() int {
	tt.lock.Lock()
	defer tt.lock.Unlock()

	return len(tt.froms) + 1
}
