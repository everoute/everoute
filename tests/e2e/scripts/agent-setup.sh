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

set -o errexit
set -o pipefail
set -o nounset

UPLINK_IFACE=${1:-ens11}
KUBECONFIG_PATH=${2:-/var/lib/lynx/agent-kubeconfig.yaml}
DEFAULT_BRIDGE="vlanLearnBridge"
OFPORT_NUM=10
AGENT_CONFIG_PATH=/var/lib/lynx/agentconfig.yaml

echo "add vlan bridge and uplink port"
ovs-vsctl add-br ${DEFAULT_BRIDGE} -- set bridge ${DEFAULT_BRIDGE} protocols=OpenFlow10,OpenFlow11,OpenFlow12,OpenFlow13 fail_mode=secure
ovs-vsctl add-port ${DEFAULT_BRIDGE} ${UPLINK_IFACE} -- set Interface ${UPLINK_IFACE} ofport=${OFPORT_NUM}

echo "generate lynx-agent config"
mkdir -p "$(dirname ${AGENT_CONFIG_PATH})"

cat > ${AGENT_CONFIG_PATH} << EOF
bridgeName: ${DEFAULT_BRIDGE}
datapathName: vlanArpLearner
localIp: 127.0.0.1
rpcPort: 30000
ovsControllerPort: 30001
uplinkInfo:
    uplinkPortType: individual
    uplinkPortName: ${UPLINK_IFACE}
    links:
    - linkInterfaceName: ${UPLINK_IFACE}
      ofPortNo: ${OFPORT_NUM}
EOF

echo "start lynx-agent"
nohup /usr/local/bin/lynx-agent --kubeconfig ${KUBECONFIG_PATH} > /var/log/lynx-agent.log 2>&1 &
