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

package node

import (
	"fmt"
	"regexp"
	"strings"
)

type Agent struct {
	*Node
}

const (
	agentBinaryName = "everoute-agent"
)

func (n *Agent) Restart() error {
	return n.reRunProcess(agentBinaryName)
}

func (n *Agent) FetchLog() ([]byte, error) {
	return n.fetchFile(fmt.Sprintf("/var/log/%s.log", agentBinaryName))
}

func (n *Agent) GetName() string {
	return fmt.Sprintf("%s/%s", n.Name, agentBinaryName)
}

func (n *Agent) Healthz() (bool, error) {
	return n.checkProcess(agentBinaryName)
}

// DumpFlow dumps the flows and parse the Output
func (n *Agent) DumpFlow() ([]string, error) {
	flowDump, err := n.runOpenflowCmd("dump-flows")
	if err != nil {
		return nil, err
	}

	flowOutStr := string(flowDump)
	flowDB := strings.Split(flowOutStr, "\n")[1:]

	var flowList []string
	for _, flow := range flowDB {
		if !strings.HasPrefix(flow, " cookie=") {
			continue
		}
		felem := strings.Fields(flow)
		if len(felem) >= 5 {
			felem = append([]string{felem[2]}, felem[5:]...)
			fstr := strings.Join(felem, " ")

			// replace roundNum and sequenceNum with static format
			expr := `load:0x[0-9,a-f]+?->NXM_NX_XXREG0`
			re, _ := regexp.Compile(expr)

			flowList = append(flowList, re.ReplaceAllString(fstr, "load:0x->NXM_NX_XXREG0"))
		}
	}

	return flowList, nil
}

func (n *Agent) runOpenflowCmd(cmd string) ([]byte, error) {
	cmdStr := fmt.Sprintf("sudo /usr/bin/ovs-ofctl -O Openflow13 %s %s", cmd, fmt.Sprintf("%s-policy", n.BridgeName))
	rc, out, err := n.runCommand(cmdStr)
	if rc != 0 || err != nil {
		return nil, fmt.Errorf("error running ovs-ofctl %s %s. Error: %v", cmd, n.BridgeName, err)
	}
	return out, nil
}
