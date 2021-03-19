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

APISERVER_EXPOSE_IP=${1:-127.0.0.1}
LOCAL_PATH=$(dirname "$(readlink -f ${0})")

## setup kube-apiserver and etcd
bash ${LOCAL_PATH}/controlplane-setup.sh ${APISERVER_EXPOSE_IP}

## todo: auto deploy lynx-controller and lynx-agent
#bash -x ${LOCAL_PATH}/lynx-setup.sh
