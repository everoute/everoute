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

echo "========================================================="
echo " "
echo "Start setup everoute e2e test environment."
echo " "
echo "========================================================="

APISERVER_EXPOSE_IP=${1:-127.0.0.1}
EVEROUTE_AGENT_HOSTLIST=${2:-127.0.0.1}
UPLINK_IFACE=${3:-ens11}
PLATFORM=${4:-amd64}
LOCAL_PATH=$(dirname "$(readlink -f ${0})")

echo "setup everoute controlplane on localhost"
make controller
cp bin/everoute-controller /usr/local/bin/everoute-controller
bash ${LOCAL_PATH}/controlplane-setup.sh ${APISERVER_EXPOSE_IP} ${PLATFORM}

make agent
make e2e-tools
for agent in $(IFS=','; echo ${EVEROUTE_AGENT_HOSTLIST}); do
  printf "deploy everoute-agent on host %s\n" ${agent}

  agent_kubeconfig=/var/lib/everoute/agent-kubeconfig.yaml
  ssh_args="-o StrictHostKeyChecking=no"

  ssh ${ssh_args} ${agent} mkdir -p /usr/local/bin/ "$(dirname ${agent_kubeconfig})"
  scp ${ssh_args} bin/everoute-agent ${agent}:/usr/local/bin/everoute-agent
  scp ${ssh_args} bin/net-utils ${agent}:/usr/local/bin/net-utils
  scp ${ssh_args} /etc/everoute/kubeconfig/everoute-agent.yaml ${agent}:${agent_kubeconfig}

  ssh ${ssh_args} ${agent} 'bash -s' < ${LOCAL_PATH}/agent-setup.sh ${UPLINK_IFACE} ${agent_kubeconfig}
done

echo "generate everoute e2e environment config"
kubectl apply -f - << EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: everoute-e2e-framework-config
  namespace: kube-system
data:
  config: |-
    timeout: 60s
    nodes:
      disableControllerRestarter: true
      instances:
$(
  for agent in $(echo ${APISERVER_EXPOSE_IP},${EVEROUTE_AGENT_HOSTLIST} | sed "s/,/\n/g" | sort -u); do
    printf "      - name: %s\n" $agent
    printf "        roles: \n"
    printf "        - agent \n"
    if [[ $agent == "${APISERVER_EXPOSE_IP}" ]]; then
    printf "        - controller \n"
    fi
    printf "        user: %s\n" ${USER}
    printf "        dial-address: %s:22\n" $agent
    printf "        bridge-name: ovsbr1\n"
  done
)
EOF

echo "modprobe ftp moduels"
modprobe nf_nat_ftp
modprobe nf_conntrack_ftp

echo "create dir /ftp and file test-ftp"
mkdir -p /ftp
touch /ftp/test-ftp
echo "test-ftp" >> /ftp/test-ftp

echo "========================================================="
echo " "
echo "Installation is complete for everoute e2e environment!"
echo " "
echo "========================================================="
