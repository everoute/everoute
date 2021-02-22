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

function wait_for_up() {
  for i in {1..100}; do
    status=$(kubectl get po -Aowide | grep Running | grep ${1} || true)
    if [[ x${status} != x"" ]]; then
      echo "success wait ${1} setup"
      break
    fi
    if [[ ${i} == 100 ]]; then
      echo "failed wait for ${1} setup"
      exit 1
    fi
    sleep 2
    echo "${i} times, wait for ${1} setup ..."
  done
}

temp_dir=$(mktemp -d)
local_path=$(dirname "$(readlink -f ${0})")
crds_path=${local_path}/../deploy/crds
lynxcontroller_deploypath=${local_path}/../deploy/lynx-controller

echo "gen lynx controller tls certs"
(
  openssl req -x509 -newkey rsa:2048 -keyout ${temp_dir}/ca.key -out ${temp_dir}/ca.crt -days 365 -nodes -subj "/CN=ca"
  openssl genrsa -out ${temp_dir}/tls.key
  openssl req -new -key ${temp_dir}/tls.key -out ${temp_dir}/tls.csr -subj "/CN=server"
  openssl x509 -req -in ${temp_dir}/tls.csr -CA ${temp_dir}/ca.crt -CAkey ${temp_dir}/ca.key -CAcreateserial -out ${temp_dir}/tls.crt -days 36500 -extfile <(printf "subjectAltName=DNS:lynx-validator-webhook.kube-system.svc")
) 1>/dev/null 2>/dev/null

### create crds
kubectl apply -f ${crds_path}

### create secret for validate-webhook
kubectl create secret tls -n kube-system lynx-controller-tls --cert ${temp_dir}/tls.crt --key ${temp_dir}/tls.key

### create lynx-controller
cp -r ${lynxcontroller_deploypath} ${temp_dir}
sed -i "s/caBundle: Cg==/caBundle: $(base64 -w0 < ${temp_dir}/ca.crt)/g" ${temp_dir}/lynx-controller/webhook.yaml
kubectl apply -f ${temp_dir}/lynx-controller

### wait for pods setup
wait_for_up lynx-controller

echo "========================================================="
echo " "
echo "Installation is complete for lynx !"
echo " "
echo "========================================================="
