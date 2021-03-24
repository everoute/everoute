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

echo "========================================================="
echo " "
echo "Start setup lynx e2e test environment."
echo " "
echo "========================================================="

APISERVER_EXPOSE_IP=${1:-127.0.0.1}
LYNX_AGENT_HOSTLIST=${2:-127.0.0.1}
UPLINK_IFACE=${3:-ens11}
LOCAL_PATH=$(dirname "$(readlink -f ${0})")
LYNX_E2E_CONFIG_FILE="/etc/lynx/e2e-config.yaml"

echo "setup lynx controlplane on localhost"
bash ${LOCAL_PATH}/controlplane-setup.sh ${APISERVER_EXPOSE_IP}

make agent
for agent in $(IFS=','; echo ${LYNX_AGENT_HOSTLIST}); do
  printf "deploy lynx-agent on host %s\n" ${agent}

  agent_kubeconfig=/var/lib/lynx/agent-kubeconfig.yaml
  ssh_args="-o StrictHostKeyChecking=no"

  ssh ${ssh_args} ${agent} mkdir -p /usr/local/bin/ "$(dirname ${agent_kubeconfig})"
  scp ${ssh_args} bin/lynx-agent ${agent}:/usr/local/bin/lynx-agent
  scp ${ssh_args} /etc/lynx/kubeconfig/lynx-agent.yaml ${agent}:${agent_kubeconfig}

  ssh ${ssh_args} ${agent} 'bash -s' < ${LOCAL_PATH}/agent-setup.sh ${UPLINK_IFACE} ${agent_kubeconfig}
done

echo "generate lynx e2e environment config"
echo ${LYNX_AGENT_HOSTLIST} > ${LYNX_E2E_CONFIG_FILE}

echo "========================================================="
echo " "
echo "Installation is complete for lynx e2e environment!"
echo " "
echo "========================================================="
