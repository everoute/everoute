/*
Copyright 2021 The Lynx Authors.

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

package cases

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
)

const (
	startNewVM = `
		set -o errexit
		set -o pipefail
		set -o nounset
		set -o xtrace

		netns=${1}
		ipaddress=${2}
		tcp_port=${3:-0}
		udp_port=${4:-0}

		vethname="veth-${netns}"
		portname=${vethname}
		vethpeername="vethpeer-${netns}"
		defaultbridge="vlanLearnBridge"
		port_id_name="external_uuid"
		port_id_value="uuid-${netns}"
		ip_prefix_length=24

		ip netns add ${netns}
		ip link add ${vethname} type veth peer name ${vethpeername}
		ip link set ${vethname} up

		ip link set ${vethpeername} netns ${netns}
		ip netns exec ${netns} ip link set lo up
		ip netns exec ${netns} ip link set ${vethpeername} up
		ip netns exec ${netns} ip a add ${ipaddress}/${ip_prefix_length} dev ${vethpeername}

		ovs-vsctl add-port ${defaultbridge} ${portname} -- set port ${portname} external_ids=${port_id_name}=${port_id_value}

		if [[ ${tcp_port} != 0 ]]; then
			ip netns exec ${netns} iperf -Dsp ${tcp_port}
		fi

		if [[ ${udp_port} != 0 ]]; then
			ip netns exec ${netns} iperf -Dsup ${udp_port}
		fi
	`

	updateVMIP = `
		set -o errexit
		set -o pipefail
		set -o nounset
		set -o xtrace

		netns=${1}
		ipaddress=${2}
		vethpeername="vethpeer-${netns}"
		ip_prefix_length=24

		ip netns exec ${netns} ip a flush dev ${vethpeername}
		ip netns exec ${netns} ip a add ${ipaddress}/${ip_prefix_length} dev ${vethpeername}
	`

	destroyVM = `
		set -o nounset
		set -o xtrace

		netns=${1}
		vethname="veth-${netns}"
		portname=${vethname}

		kill -9 $(ip netns pids ${netns})
		ovs-vsctl del-port ${portname}
		ip netns del ${netns}
		ip link del ${vethname} || true
	`

	tcpReachable = `
		set -o errexit
		set -o pipefail
		set -o nounset
		set -o xtrace

		local_netns=${1}
		remote_ipaddr=${2}
		remote_port=${3}
		timeout=1

		ip netns exec ${local_netns} nc -zv -w ${timeout} ${remote_ipaddr} ${remote_port}
	`

	udpReachable = `
		set -o errexit
		set -o pipefail
		set -o nounset
		set -o xtrace

		local_netns=${1}
		remote_ipaddr=${2}
		remote_port=${3}
		timeout=1

		iperf_result=$(ip netns exec ${local_netns} iperf -t ${timeout} -n 100 -uc ${remote_ipaddr} -p ${remote_port} -x CMSDV 2>&1)
		if [[ ${iperf_result} =~ "not receive ack" ]]; then
			exit 1
		fi
	`

	icmpReachable = `
		set -o errexit
		set -o pipefail
		set -o nounset
		set -o xtrace

		local_netns=${1}
		remote_ipaddr=${2}
		ping_count=1
		timeout=1

		ip netns exec ${local_netns} ping -c ${ping_count} -W ${timeout} ${remote_ipaddr}
	`
)

func runScriptRemote(remote, script string, arg ...string) ([]byte, int, error) {
	// create tempfile and write script into tempfile
	fileScript, err := ioutil.TempFile("", "shell-script-")
	if err != nil {
		return nil, 0, err
	}
	defer os.Remove(fileScript.Name())

	if _, err := fileScript.Write([]byte(script)); err != nil {
		return nil, 0, err
	}

	// create tempfile and write ssh command into tempfile
	fileRemote, err := ioutil.TempFile("", "remote-script-")
	if err != nil {
		return nil, 0, err
	}
	defer os.Remove(fileRemote.Name())

	sshRemote := fmt.Sprintf("ssh -o StrictHostKeyChecking=no %s 'bash -s' < %s ${@}", remote, fileScript.Name())
	if _, err := fileRemote.Write([]byte(sshRemote)); err != nil {
		return nil, 0, err
	}

	out, err := exec.Command("bash", append([]string{fileRemote.Name()}, arg...)...).CombinedOutput()
	if _, ok := err.(*exec.ExitError); ok {
		return out, err.(*exec.ExitError).ExitCode(), nil
	}
	return out, 0, err
}
