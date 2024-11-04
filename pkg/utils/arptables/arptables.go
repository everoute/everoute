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
package arptables

import (
	"bytes"
	"fmt"
	"os/exec"
	"reflect"
	"strconv"
	"strings"

	"k8s.io/apimachinery/pkg/util/sets"
)

type ArpRule struct {
	SrcIP     string
	DstIP     string
	SrcMac    string
	DstMac    string
	HwLength  string
	OpCode    string
	HwType    string
	ProtoType string
	InIface   string
	OutIface  string
	Target    string
	Match     string
}

func (a *ArpRule) ToSpec() []string {
	var rule []string
	if a.SrcIP != "" {
		rule = append(rule, "-s", a.SrcIP)
	}
	if a.DstIP != "" {
		rule = append(rule, "-d", a.DstIP)
	}
	if a.SrcMac != "" {
		rule = append(rule, "--src-mac", a.SrcMac)
	}
	if a.DstMac != "" {
		rule = append(rule, "--dst-mac", a.DstMac)
	}
	if a.HwLength != "" {
		rule = append(rule, "-l", a.HwLength)
	}
	if a.OpCode != "" {
		rule = append(rule, "--opcode", a.OpCode)
	}
	if a.HwType != "" {
		rule = append(rule, "--h-type", a.HwType)
	}
	if a.ProtoType != "" {
		rule = append(rule, "--proto-type", a.ProtoType)
	}
	if a.InIface != "" {
		rule = append(rule, "-i", a.InIface)
	}
	if a.OutIface != "" {
		rule = append(rule, "-o", a.OutIface)
	}
	if a.Target != "" {
		rule = append(rule, "-j", a.Target)
	}
	if a.Match != "" {
		rule = append(rule, "-m", a.Match)
	}

	return rule
}

func run(args ...string) error {
	_, err := runWithOutput(args...)
	return err
}

func runWithOutput(args ...string) ([]string, error) {
	path, err := exec.LookPath("arptables")
	if err != nil {
		return []string{}, err
	}

	var stderr bytes.Buffer
	var stdout bytes.Buffer
	cmd := exec.Cmd{
		Path:   path,
		Args:   append([]string{path}, args...),
		Stdout: &stdout,
		Stderr: &stderr,
	}
	if err := cmd.Run(); err != nil {
		switch err.(type) {
		case *exec.ExitError:
			return []string{}, fmt.Errorf(stderr.String())
		default:
			return []string{}, err
		}
	}

	return strings.Split(stdout.String(), "\n"), nil
}

func Parse(rulespec ...string) (*ArpRule, error) {
	cmdSet := sets.NewString(
		"-s", "-d", "--src-mac", "--dst-mac",
		"-l", "--opcode", "--h-type", "--proto-type",
		"-i", "-o", "-j", "-m")

	// reverse ! and next cmd
	i := 0
	for i < len(rulespec)-1 {
		if rulespec[i] == "!" {
			rulespec[i], rulespec[i+1] = rulespec[i+1], rulespec[i]
			i++
		}
		i++
	}

	i = 0
	rule := &ArpRule{}
	for i < len(rulespec) {
		// invalid args
		if i+1 == len(rulespec) || cmdSet.Has(rulespec[i+1]) {
			return nil, fmt.Errorf("invalid args %+v", rulespec)
		}

		// extract value
		cmd := rulespec[i]
		var value []string
		for {
			i++
			if i == len(rulespec) || cmdSet.Has(rulespec[i]) {
				break
			}
			value = append(value, rulespec[i])
		}
		valueStr := strings.Join(value, " ")

		switch cmd {
		case "-s":
			rule.SrcIP = valueStr
		case "-d":
			rule.DstIP = valueStr
		case "--src-mac":
			rule.SrcMac = valueStr
		case "--dst-mac":
			rule.DstMac = valueStr
		case "-i":
			rule.InIface = valueStr
		case "-o":
			rule.OutIface = valueStr
		case "-l":
			rule.HwLength = valueStr
		case "--opcode":
			rule.OpCode = valueStr
		case "--h-type":
			rule.HwType = valueStr
		case "--proto-type":
			rule.ProtoType = valueStr
		case "-j":
			rule.Target = valueStr
		case "-m":
			rule.Match = valueStr
		default:
			return nil, fmt.Errorf("unknown args %s", cmd)
		}
	}
	return rule, nil
}

func List(chain, table string) ([]*ArpRule, error) {
	var rules []*ArpRule

	cmd := []string{"-L", chain, "-t", table, "-n"}
	out, err := runWithOutput(cmd...)
	if err != nil {
		return rules, err
	}

	for _, rule := range out {
		if strings.HasPrefix(rule, "Chain") || strings.TrimSpace(rule) == "" {
			continue
		}
		if r, err := Parse(strings.Split(rule, " ")...); r != nil {
			rules = append(rules, r)
		} else if err != nil {
			return rules, err
		}
	}

	return rules, nil
}

func Exists(chain, table string, target *ArpRule) (bool, error) {
	rules, err := List(chain, table)
	if err != nil {
		return false, err
	}

	for _, rule := range rules {
		if reflect.DeepEqual(target, rule) {
			return true, nil
		}
	}

	return false, nil
}

func DeleteAll(chain, table string, rulespec ...string) {
	for {
		if Delete(chain, table, rulespec...) != nil {
			return
		}
	}
}

func Delete(chain, table string, rulespec ...string) error {
	cmd := append([]string{"-D", chain, "-t", table}, rulespec...)
	return run(cmd...)
}

func Flush(chain string) error {
	cmd := []string{"-F", chain}
	return run(cmd...)
}

func Append(chain, table string, rulespec ...string) error {
	cmd := append([]string{"-A", chain, "-t", table}, rulespec...)
	return run(cmd...)
}

func AppendUnique(chain, table string, rule *ArpRule) error {
	ok, err := Exists(chain, table, rule)
	if err != nil {
		return fmt.Errorf("check rule failed")
	} else if ok {
		return fmt.Errorf("rule existed")
	}

	cmd := append([]string{"-A", chain, "-t", table}, rule.ToSpec()...)
	return run(cmd...)
}

func Insert(chain, table string, pos int, rulespec ...string) error {
	cmd := append([]string{"-I", chain, strconv.Itoa(pos), "-t", table}, rulespec...)
	return run(cmd...)
}

func InsertUnique(chain, table string, pos int, rule *ArpRule) error {
	ok, err := Exists(chain, table, rule)
	if err != nil {
		return fmt.Errorf("check rule failed")
	} else if ok {
		return fmt.Errorf("rule existed")
	}

	cmd := append([]string{"-I", chain, strconv.Itoa(pos), "-t", table}, rule.ToSpec()...)
	return run(cmd...)
}
