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

package framework

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
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

		# send arp packets so than lynx agent can learn ip addr
		ip netns exec ${netns} nohup arping -AI ${vethpeername} ${ipaddress} &>/dev/null &

		attached_mac=$(ip netns exec ${netns} cat /sys/class/net/${vethpeername}/address)
		ovs-vsctl add-port ${defaultbridge} ${portname} \
			-- set interface ${portname} external_ids=${port_id_name}=${port_id_value} \
			-- set interface ${portname} external_ids:attached-mac="${attached_mac}"

		if [[ ${tcp_port} != 0 ]]; then
			ip netns exec ${netns} iperf -Dsp ${tcp_port}
		fi

		if [[ ${udp_port} != 0 ]]; then
			ip netns exec ${netns} iperf -DUsup ${udp_port} -l 10
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

		comm -12 <(pidof arping | tr " " "\n" | sort) <(ip netns pid ${netns} | sort) | xargs -rl kill -9
		ip netns exec ${netns} nohup arping -AI ${vethpeername} ${ipaddress} &>/dev/null &

		sleep 1 # wait for nohup backend run
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

		iperf_result=$(ip netns exec ${local_netns} iperf -t ${timeout} -n 10 -uc ${remote_ipaddr} -p ${remote_port} -x CMSDV 2>&1)
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

	shutdownLynxController = `
        eval kill -9 "$(pidof lynx-controller)"
    `
	startLynxController = `
        lynx_controller_config="--kubeconfig /etc/lynx/kubeconfig/lynx-controller.yaml --leader-election-namespace kube-system --tls-certs-dir /etc/lynx/pki/ -v 10"
        nohup /usr/local/bin/lynx-controller ${lynx_controller_config} > /var/log/lynx-controller.log 2>&1 &
        sleep 10
    `
	shutdownLynxAgent = `
        eval kill -9 "$(pidof lynx-agent)"
    `
	startLynxAgent = `
        lynx_agent_kubeconfig="--kubeconfig /var/lib/lynx/agent-kubeconfig.yaml"
        nohup /usr/local/bin/lynx-agent ${lynx_agent_kubeconfig} > /var/log/lynx-agent.log 2>&1 &
    `
)

func runScriptRemote(client *ssh.Client, script string, arg ...string) ([]byte, int, error) {
	session, err := client.NewSession()
	if err != nil {
		return nil, 0, err
	}
	defer session.Close()

	session.Stdin = bytes.NewBufferString(script)

	out, err := session.CombinedOutput("bash -s " + strings.Join(arg, " "))
	if _, ok := err.(*ssh.ExitError); ok {
		return out, err.(*ssh.ExitError).ExitStatus(), nil
	}

	return out, 0, err
}

func runCommandVM(client *ssh.Client, netns string, arg ...string) (int, error) {
	session, err := client.NewSession()
	if err != nil {
		return 0, err
	}
	defer session.Close()

	session.Stdin = os.Stdin
	session.Stdout = os.Stdout
	session.Stderr = os.Stderr

	err = session.Run(fmt.Sprintf("ip netns exec %s %s", netns, strings.Join(arg, " ")))
	if _, ok := err.(*ssh.ExitError); ok {
		return err.(*ssh.ExitError).ExitStatus(), nil
	}

	return 0, err
}

func newSSHClient(user, remote string, port uint8, signer ssh.Signer) (*ssh.Client, error) {
	var config = &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         time.Second,
	}

	return ssh.Dial("tcp", fmt.Sprintf("%s:%d", remote, port), config)
}

func loadLocalSigner() (ssh.Signer, error) {
	signerFile := filepath.Join(os.Getenv("HOME"), ".ssh", "id_rsa")

	buffer, err := ioutil.ReadFile(signerFile)
	if err != nil {
		return nil, fmt.Errorf("error reading SSH key %s: '%v'", signerFile, err)
	}

	return ssh.ParsePrivateKey(buffer)
}
