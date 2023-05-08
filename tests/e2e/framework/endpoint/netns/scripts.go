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

package netns

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/ssh"
)

const (
	startNewEndpoint = `
		set -o errexit
		set -o pipefail
		set -o nounset
		set -o xtrace

		netns=${1}
		bridgeName=${2}
		ipAddr=${3}
		tcpPorts=${4:-}
		udpPorts=${5:-}
		vlanTag=${6:-[]}
		proto=${7:-}

		vethName="veth-${netns}"
		portName=${vethName}
		vethPeerName="vethpeer-${netns}"
		portExternalIDName="iface-id"
		portExternalIDValue="uuid-${netns}"

		ip netns add ${netns}
		ip link add ${vethName} type veth peer name ${vethPeerName}
		ip link set ${vethName} up

		ip link set ${vethPeerName} netns ${netns}
		ip netns exec ${netns} ip link set lo up
		ip netns exec ${netns} ip link set ${vethPeerName} up
		ip netns exec ${netns} ip a add ${ipAddr} dev ${vethPeerName}

		attached_mac=$(ip netns exec ${netns} cat /sys/class/net/${vethPeerName}/address)
		ovs-vsctl add-port ${bridgeName} ${portName} tag=${vlanTag} \
			-- set interface ${portName} external_ids=${portExternalIDName}=${portExternalIDValue} \
			-- set interface ${portName} external_ids:attached-mac="${attached_mac}"

		execCommand="ip netns exec ${netns} net-utils server -d -s"
		if [[ ${tcpPorts} != 0 ]]; then
			execCommand="${execCommand} --tcp-ports ${tcpPorts}"
		fi

		if [[ ${udpPorts} != 0 ]]; then
			execCommand="${execCommand} --udp-ports ${udpPorts}"
		fi

		if [[ ${proto} = "FTP" ]]; then
			ip=${ipAddr%/*}
			execCommand="${execCommand} --ftp-server ${ip}"
		fi

		eval ${execCommand}
	`

	updateEndpointIP = `
		set -o errexit
		set -o pipefail
		set -o nounset
		set -o xtrace

		netns=${1}
		ipAddr=${2}
		vethPeerName="vethpeer-${netns}"

		ip netns exec ${netns} ip a flush dev ${vethPeerName}
		ip netns exec ${netns} ip a add ${ipAddr} dev ${vethPeerName}
	`

	updateEndpointPort = `
		set -o errexit
		set -o pipefail
		set -o nounset
		set -o xtrace

		netns=${1}
		tcpPorts=${2:-}
		udpPorts=${3:-}

		## clean old net-utils process
		comm -12 <(pidof net-utils | tr " " "\n" | sort) <(ip netns pid ${netns} | sort) | xargs -rl kill -9

		execCommand="ip netns exec ${netns} net-utils server -d -s"
		if [[ ${tcpPorts} != 0 ]]; then
			execCommand="${execCommand} --tcp-ports ${tcpPorts}"
		fi

		if [[ ${udpPorts} != 0 ]]; then
			execCommand="${execCommand} --udp-ports ${udpPorts}"
		fi

		eval ${execCommand}
	`

	destroyEndpoint = `
		set -o nounset
		set -o xtrace

		netns=${1}
		vethName="veth-${netns}"
		portName=${vethName}

		kill -9 "$(ip netns pids ${netns})"
		ovs-vsctl del-port ${portName}
		ip netns del ${netns}
		ip link del ${vethName} || true
	`
)

func runStartNewEndpoint(client *ssh.Client, netns, bridgeName string, ipAddr string, tcpPort, udpPort int, vlanTag int, proto string) error {
	rc, out, err := runScriptRemote(client, startNewEndpoint, netns, bridgeName, ipAddr, strconv.Itoa(tcpPort), strconv.Itoa(udpPort), strconv.Itoa(vlanTag), proto)
	if err != nil {
		return err
	}
	if rc != 0 {
		return fmt.Errorf("exit code: %d, output: %s", rc, out)
	}
	return nil
}

func runUpdateEndpointIP(client *ssh.Client, netns string, ipaddr string) error {
	rc, out, err := runScriptRemote(client, updateEndpointIP, netns, ipaddr)
	if err != nil {
		return err
	}
	if rc != 0 {
		return fmt.Errorf("exit code: %d, output: %s", rc, out)
	}
	return nil
}

func runUpdateEndpointPort(client *ssh.Client, netns string, tcpPort, udpPort int) error {
	rc, out, err := runScriptRemote(client, updateEndpointPort, netns, strconv.Itoa(tcpPort), strconv.Itoa(udpPort))
	if err != nil {
		return err
	}
	if rc != 0 {
		return fmt.Errorf("exit code: %d, output: %s", rc, out)
	}
	return nil
}

func runDestroyEndpoint(client *ssh.Client, netns string) error {
	rc, out, err := runScriptRemote(client, destroyEndpoint, netns)
	if err != nil {
		return err
	}
	if rc != 0 {
		return fmt.Errorf("exit code: %d, output: %s", rc, out)
	}
	return nil
}

func runScriptRemote(client *ssh.Client, script string, arg ...string) (int, []byte, error) {
	session, err := client.NewSession()
	if err != nil {
		return 0, nil, err
	}
	defer session.Close()

	session.Stdin = bytes.NewBufferString(script)

	out, err := session.CombinedOutput("bash -s " + strings.Join(arg, " "))
	if _, ok := err.(*ssh.ExitError); ok {
		return err.(*ssh.ExitError).ExitStatus(), out, nil
	}

	return 0, out, err
}
