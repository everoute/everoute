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
	"strconv"
	"strings"

	"k8s.io/apimachinery/pkg/util/rand"
	"k8s.io/klog"
)

type Agent struct {
	*Node
}

const (
	agentBinaryName = "everoute-agent"
	ovsRestart      = "systemctl restart openvswitch"
)

func (n *Agent) Restart() error {
	if rand.Intn(2) == 0 {
		return n.reRunProcess(agentBinaryName)
	}
	_, _, err := n.runCommand(ovsRestart)
	return err
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

func (n *Agent) CheckConntrackExist(proto, srcIP, dstIP string, srcPort, dstPort uint16) (bool, error) {
	command := []string{"sudo conntrack", "-L"}

	if srcIP != "" {
		command = append(command, "-s", srcIP)
	}
	if dstIP != "" {
		command = append(command, "-d", dstIP)
	}
	command = append(command, "-p", proto)

	if proto == "TCP" || proto == "UDP" {
		if srcPort != 0 {
			command = append(command, "--sport", strconv.Itoa(int(srcPort)))
		}
		if dstPort != 0 {
			command = append(command, "--dport", strconv.Itoa(int(dstPort)))
		}
	}

	realCommand := strings.Join(command, " ")

	rc, out, err := n.runCommand(realCommand)
	if rc != 0 || err != nil {
		return false, fmt.Errorf("error running "+realCommand+", code: %d, error: %v", rc, err)
	}

	reg, _ := regexp.Compile("[0-9]+ flow entries")
	flowCount, err := strconv.Atoi(strings.TrimSpace(strings.Split(reg.FindStringSubmatch(string(out))[0], " ")[0]))
	if err != nil {
		klog.Error("error parse the number of flows, err:", err)
		return false, err
	}
	klog.Infof("Check conntrack exist find %d flows with command %s in agent %s", flowCount, realCommand, n.Name)

	return flowCount != 0, nil
}

func (n *Agent) CleanConntrack() error {
	var command string = "sudo conntrack -F"
	rc, _, err := n.runCommand(command)
	if rc != 0 || err != nil {
		return fmt.Errorf("error running "+command+". Return code: %d, error: %v", rc, err)
	}
	return nil
}

func (n *Agent) Sysctl(params ...string) (string, error) {
	cmdStr := fmt.Sprintf("sudo sysctl %s", strings.Join(params, " "))
	rc, out, err := n.runCommand(cmdStr)
	if rc != 0 || err != nil {
		return "", fmt.Errorf("error running %s. Error: %v", cmdStr, err)
	}
	return string(out), nil
}

func (n *Agent) runOpenflowCmd(cmd string) ([]byte, error) {
	cmdStr := fmt.Sprintf("sudo /usr/bin/ovs-ofctl -O Openflow13 %s %s", cmd, fmt.Sprintf("%s-policy", n.BridgeName))
	rc, out, err := n.runCommand(cmdStr)
	if rc != 0 || err != nil {
		return nil, fmt.Errorf("error running ovs-ofctl %s %s. Error: %v", cmd, n.BridgeName, err)
	}
	return out, nil
}
