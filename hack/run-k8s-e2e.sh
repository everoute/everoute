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

./kubernetes/_output/bin/ginkgo -nodes=20 --skip="named port|SCTP" --focus="NetworkPolicy" \
./kubernetes/_output/bin/e2e.test -- --disable-log-dump --provider="skeleton" \
--kubeconfig="/home/centos/.kube/config"
