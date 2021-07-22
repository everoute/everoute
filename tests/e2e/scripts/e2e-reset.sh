#!/usr/bin/env bash

# Copyright 2021 The Lynx Authors.
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

LYNX_AGENT_HOSTLIST=${1:-127.0.0.1}

echo "clean lynx controlplane on localhost"
eval kill -9 "$(pidof lynx-controller) $(pidof lynx-agent) $(pidof kube-apiserver) $(pidof etcd) $(pidof net-utils)"
rm -rf /etc/lynx/

for agent in $(IFS=','; echo ${LYNX_AGENT_HOSTLIST}); do
  printf "clean lynx-agent and ovsdb on host %s\n" ${agent}

  ssh_args="-o StrictHostKeyChecking=no"

  ssh ${ssh_args} ${agent} 'bash -s' << "EOF"
    ovs-vsctl list-br | xargs -rl ovs-vsctl del-br
    ip netns list | awk '{print $1}' | xargs -rl ip netns pid | xargs -rl kill -9
    ip -all netns del
    ip a | grep veth | cut -d: -f2 | cut -d@ -f1 | xargs -rl ip link del
    pidof lynx-agent | xargs -r kill -9
EOF
done
