#!/usr/bin/env bash

# Copyright 2021 The Everoute Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -o pipefail
set -o nounset

EVEROUTE_AGENT_HOSTLIST=${1:-127.0.0.1}

DEFAULT_BRIDGE="ovsbr1"
POLICY_BRIDGE="${DEFAULT_BRIDGE}-policy"
CLS_BRIDGE="${DEFAULT_BRIDGE}-cls"
UPLINK_BRIDGE="${DEFAULT_BRIDGE}-uplink"

echo "clean everoute controlplane on localhost"
eval kill -9 "$(pidof everoute-controller) $(pidof everoute-agent) $(pidof kube-apiserver) $(pidof etcd) $(pidof net-utils)"
rm -rf /etc/everoute/

for agent in $(IFS=','; echo "${EVEROUTE_AGENT_HOSTLIST}"); do
  printf "clean everoute-agent and ovsdb on host %s\n" "${agent}"
  ovs-vsctl \
			-- del-br ${DEFAULT_BRIDGE} \
			-- del-br ${POLICY_BRIDGE} \
			-- del-br ${CLS_BRIDGE} \
			-- del-br ${UPLINK_BRIDGE}

  ssh_args="-o StrictHostKeyChecking=no"

  ssh "${ssh_args}" "${agent}" 'bash -s' << "EOF"
    ovs-vsctl list-br | xargs -rl ovs-vsctl del-br
    ip netns list | awk '{print $1}' | xargs -rl ip netns pid | xargs -rl kill -9
    ip -all netns del
    ip a | grep veth | cut -d: -f2 | cut -d@ -f1 | xargs -rl ip link del
    pidof everoute-agent | xargs -r kill -9
EOF
done
