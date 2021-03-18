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

function install_etcd() {
  local version=${1}
  local download_url=https://github.com/etcd-io/etcd/releases/download

  local -r tmp_file_name="etcd-${version}-linux-amd64"
  local -r download_path="$(mktemp -d)/${tmp_file_name}.tar"

  if [[ $(command -v etcd) ]]; then
    return 0
  fi

  curl -L ${download_url}/${version}/${tmp_file_name}.tar -o ${download_path}
  tar xf ${download_path} -C /usr/local/bin --strip-components=1 --extract ${tmp_file_name}/etcd ${tmp_file_name}/etcdctl
}

function install_kube_plugin() {
  local version=${1}
  local plugin=${2}
  local download_url=https://storage.googleapis.com/kubernetes-release/release

  if [[ $(command -v ${plugin}) ]]; then
    return 0
  fi

  curl -L ${download_url}/${version}/bin/linux/amd64/${plugin} -o /usr/local/bin/${plugin}
  chmod +x /usr/local/bin/${plugin}
}

function start_etcd() {
  if [[ $(pidof etcd) ]]; then
    printf "etcd has already run on pid %s, please run e2e-reset.sh first\n" "$(pidof etcd)"
    return 1
  fi

  mkdir -p /etc/lynx/etcd
  cp "${BASEDIR}/tests/e2e/config/etcd.yaml" /etc/lynx/etcd/etcd.yaml

  nohup etcd --config-file /etc/lynx/etcd/etcd.yaml > /var/log/kube-apiserver.log 2>&1 &
}

function start_apiserver() {
  local cert_path=${1}
  local apiserver_addr=${2}

  if [[ $(pidof kube-apiserver) ]]; then
    printf "kube-apiserver has already run on pid %s, please run e2e-reset.sh first\n" "$(pidof kube-apiserver)"
    return 1
  fi

  generate_certs ${cert_path} ${apiserver_addr}

  local apiserver_args="--advertise-address=0.0.0.0 --secure-port=6443 --insecure-port=0"
  local apiserver_cert_args="--client-ca-file=${cert_path}/ca.crt --cert-dir=${cert_path}"
  local apiserver_extra_args="--service-cluster-ip-range=10.0.0.0/24 --allow-privileged=true --authorization-mode RBAC --etcd-servers=http://127.0.0.1:2379"

  nohup kube-apiserver ${apiserver_args} ${apiserver_extra_args} ${apiserver_cert_args} > /var/log/kube-apiserver.log 2>&1 &
}

function generate_certs() {
  local cert_path=${1}
  local apiserver_addr=${2:-127.0.0.1}

  mkdir -p ${cert_path}

  local cakey_path=${cert_path}/ca.key
  local cacert_path=${cert_path}/ca.crt

  if [[ -f ${cakey_path} || -f ${cacert_path} ]]; then
    return 1
  fi

  (
    openssl req -x509 -newkey rsa:2048 -keyout ${cakey_path} -out ${cacert_path} -days 365 -nodes -subj "/CN=kubenetes"
    openssl genrsa -out ${cert_path}/apiserver.key
    openssl req -new -key ${cert_path}/apiserver.key -out ${cert_path}/apiserver.csr -subj "/CN=kube-apiserver"
    openssl x509 -req -in ${cert_path}/apiserver.csr -CA ${cacert_path} -CAkey ${cakey_path} -CAcreateserial -out ${cert_path}/apiserver.crt -days 36500 -extfile <(printf "subjectAltName=IP:%s" ${apiserver_addr})
  ) 1>/dev/null 2>/dev/null
}

function generate_lynx_controller_certs() {
  local cert_path=${1}

  mkdir -p ${cert_path}

  local cakey_path=${cert_path}/ca.key
  local cacert_path=${cert_path}/ca.crt

  (
    openssl genrsa -out ${cert_path}/tls.key
    openssl req -new -key ${cert_path}/tls.key -out ${cert_path}/tls.csr -subj "/CN=lynx-controller"
    openssl x509 -req -in ${cert_path}/tls.csr -CA ${cacert_path} -CAkey ${cakey_path} -CAcreateserial -out ${cert_path}/tls.crt -days 36500 -extfile <(printf "subjectAltName=DNS:lynx-validator-webhook.kube-system.svc")
  ) 1>/dev/null 2>/dev/null
}

function setup_crds() {
  local crds_path=${BASEDIR}/deploy/crds
  kubectl apply -f ${crds_path}
}

function setup_rbac() {
  local lynx_agent_rbac_path="${BASEDIR}/deploy/lynx-agent"
  local lynx_controller_rbac_path="${BASEDIR}/deploy/lynx-controller"

  kubectl apply -f ${lynx_agent_rbac_path}/role.yaml
  kubectl apply -f ${lynx_controller_rbac_path}/role.yaml

  kubectl apply -f ${lynx_agent_rbac_path}/rolebinding.yaml
  kubectl apply -f ${lynx_controller_rbac_path}/rolebinding.yaml
}

function setup_webhook() {
  local cacert_path=${cert_path}/ca.crt
  local lynx_webhook_path="${BASEDIR}/deploy/lynx-controller/webhook.yaml"

  sed "s/caBundle: Cg==/caBundle: $(base64 -w0 < ${cacert_path})/g" < ${lynx_webhook_path} | kubectl apply -f -

  # kube-proxy not deploy, so use dns to forward svc request
  sed -i "/ lynx-validator-webhook.kube-system.svc$/d" /etc/hosts
  echo "127.0.0.1 lynx-validator-webhook.kube-system.svc" >> /etc/hosts
}

function generate_kubeconfig() {
  local cert_path=${1}
  local user=${2}
  local org=${3}
  local kubeconfig_path=${4}
  local kube_apiserver_endpoint=${5:-127.0.0.1}

  local cakey_path=${cert_path}/ca.key
  local cacert_path=${cert_path}/ca.crt
  local kubernetes_entrypoint="https://${kube_apiserver_endpoint}:6443"

  local -r cert_tmp_dir=$(mktemp -d)

  (
    openssl genrsa -out ${cert_tmp_dir}/${user}.key
    openssl req -new -key ${cert_tmp_dir}/${user}.key -out ${cert_tmp_dir}/${user}.csr -subj "/CN=${user}/O=${org}"
    openssl x509 -req -in ${cert_tmp_dir}/${user}.csr -CA ${cacert_path} -CAkey ${cakey_path} -CAcreateserial -out ${cert_tmp_dir}/${user}.crt -days 36500
  ) 1>/dev/null 2>/dev/null

  mkdir -p "$(dirname ${kubeconfig_path})"

cat > ${kubeconfig_path} << EOF
apiVersion: v1
kind: Config
current-context: ${user}@kubernetes
clusters:
  - name: kubernetes
    cluster:
      certificate-authority-data: $(base64 -w0 < ${cacert_path})
      server: ${kubernetes_entrypoint}
contexts:
  - name: ${user}@kubernetes
    context:
      cluster: kubernetes
      user: ${user}
users:
  - name: ${user}
    user:
      client-certificate-data: $(base64 -w0 < ${cert_tmp_dir}/${user}.crt)
      client-key-data: $(base64 -w0 < ${cert_tmp_dir}/${user}.key)
EOF
}

echo "========================================================="
echo " "
echo "Start setup lynx e2e test environment."
echo " "
echo "========================================================="

ETCD_VERSION="v3.4.15"
KUBE_VERSION="v1.19.8"
CERT_PATH=/etc/lynx/pki
APISERVER_ADDR="${1:-127.0.0.1}"
LOCAL_PATH=$(dirname "$(readlink -f ${0})")
## lynx project basedir
BASEDIR=${LOCAL_PATH}/../../..

echo "install etcd and kube-apiserver to localhost"
install_etcd ${ETCD_VERSION}
install_kube_plugin ${KUBE_VERSION} kube-apiserver
install_kube_plugin ${KUBE_VERSION} kubectl

echo "start controlplane (etcd and apiserver)"
start_etcd
start_apiserver ${CERT_PATH} ${APISERVER_ADDR}

echo "generate kubeconfig for lynx-controller lynx-agent and kubectl"
##                  cert path    user name       org name         kubeconfig save path                      kube-apiserver address
generate_kubeconfig ${CERT_PATH} lynx-agent      "lynx"           /etc/lynx/kubeconfig/lynx-agent.yaml      ${APISERVER_ADDR}
generate_kubeconfig ${CERT_PATH} lynx-controller "lynx"           /etc/lynx/kubeconfig/lynx-controller.yaml ${APISERVER_ADDR}
generate_kubeconfig ${CERT_PATH} kubectl         "system:masters" ~/.kube/config                            ${APISERVER_ADDR}

echo "generate lynx controller certs used for validate webhook"
generate_lynx_controller_certs ${CERT_PATH}

echo "crds, rbac, validate webhook resource setup"
setup_crds
setup_rbac
## todo: enable validate webhook
#setup_webhook

echo "========================================================="
echo " "
echo "Installation is complete for lynx e2e environment!"
echo " "
echo "========================================================="
