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

set -o errexit
set -o pipefail
set -o nounset

UPLINK_IFACE=${1:-ens11}
KUBECONFIG_PATH=${2:-/var/lib/everoute/agent-kubeconfig.yaml}
OFPORT_NUM=10
AGENT_CONFIG_PATH=/var/lib/everoute/agentconfig.yaml

DEFAULT_BRIDGE="ovsbr1"
POLICY_BRIDGE="${DEFAULT_BRIDGE}-policy"
CLS_BRIDGE="${DEFAULT_BRIDGE}-cls"
UPLINK_BRIDGE="${DEFAULT_BRIDGE}-uplink"

LOCAL_TO_POLICY_PATCH="${DEFAULT_BRIDGE}-local-to-policy"
POLICY_TO_LOCAL_PATCH="${POLICY_BRIDGE}-policy-to-local"
POLICY_TO_CLS_PATCH="${POLICY_BRIDGE}-policy-to-cls"
CLS_TO_POLICY_PATCH="${CLS_BRIDGE}-cls-to-policy"
CLS_TO_UPLINK_PATCH="${CLS_BRIDGE}-cls-to-uplink"
UPLINK_TO_CLS_PATCH="${UPLINK_BRIDGE}-uplink-to-cls"

echo "add uplink interface if not exists"
ip link show "${UPLINK_IFACE}" || ip link add "${UPLINK_IFACE}" type bridge

echo "add bridge chain and uplink port"
ovs-vsctl add-br ${DEFAULT_BRIDGE} -- set bridge ${DEFAULT_BRIDGE} protocols=OpenFlow10,OpenFlow11,OpenFlow12,OpenFlow13 fail_mode=secure
ovs-vsctl add-br ${POLICY_BRIDGE} -- set bridge ${POLICY_BRIDGE} protocols=OpenFlow10,OpenFlow11,OpenFlow12,OpenFlow13 fail_mode=secure
ovs-vsctl add-br ${CLS_BRIDGE} -- set bridge ${CLS_BRIDGE} protocols=OpenFlow10,OpenFlow11,OpenFlow12,OpenFlow13 fail_mode=secure
ovs-vsctl add-br ${UPLINK_BRIDGE} -- set bridge ${UPLINK_BRIDGE} protocols=OpenFlow10,OpenFlow11,OpenFlow12,OpenFlow13 fail_mode=secure

ovs-vsctl \
    -- add-port ${DEFAULT_BRIDGE} ${LOCAL_TO_POLICY_PATCH} \
    -- set interface ${LOCAL_TO_POLICY_PATCH} type=patch options:peer=${POLICY_TO_LOCAL_PATCH} \
    -- add-port ${POLICY_BRIDGE} ${POLICY_TO_LOCAL_PATCH} \
    -- set interface ${POLICY_TO_LOCAL_PATCH} type=patch options:peer=${LOCAL_TO_POLICY_PATCH}

ovs-vsctl \
    -- add-port ${POLICY_BRIDGE} ${POLICY_TO_CLS_PATCH} \
    -- set interface ${POLICY_TO_CLS_PATCH} type=patch options:peer=${CLS_TO_POLICY_PATCH} \
    -- add-port ${CLS_BRIDGE} ${CLS_TO_POLICY_PATCH} \
    -- set interface ${CLS_TO_POLICY_PATCH} type=patch options:peer=${POLICY_TO_CLS_PATCH}

ovs-vsctl \
    -- add-port ${UPLINK_BRIDGE} ${UPLINK_TO_CLS_PATCH} \
    -- set interface ${UPLINK_TO_CLS_PATCH} type=patch options:peer=${CLS_TO_UPLINK_PATCH} \
    -- add-port ${CLS_BRIDGE} ${CLS_TO_UPLINK_PATCH} \
    -- set interface ${CLS_TO_UPLINK_PATCH} type=patch options:peer=${UPLINK_TO_CLS_PATCH}

ovs-vsctl add-port ${UPLINK_BRIDGE} "${UPLINK_IFACE}" -- set Port "${UPLINK_IFACE}" external_ids=uplink-port="true" -- set Interface "${UPLINK_IFACE}" ofport=${OFPORT_NUM}
ovs-ofctl add-flow ${UPLINK_BRIDGE} "table=0,priority=10,actions=normal"

echo "generate everoute-agent config"
mkdir -p "$(dirname ${AGENT_CONFIG_PATH})"
cat > ${AGENT_CONFIG_PATH} << EOF
datapathConfig:
    ${DEFAULT_BRIDGE}: ${DEFAULT_BRIDGE}
EOF

echo "start everoute-agent"
nohup /usr/local/bin/everoute-agent --kubeconfig "${KUBECONFIG_PATH}" > /var/log/everoute-agent.log 2>&1 &
