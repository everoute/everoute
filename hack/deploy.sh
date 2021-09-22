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

local_path=$(dirname "$(readlink -f ${0})")
kubectl apply -f ${local_path}/../deploy/everoute.yaml


### wait for pods setup
wait_for_up everoute-controller

echo "========================================================="
echo " "
echo "Installation is complete for everoute !"
echo " "
echo "========================================================="
