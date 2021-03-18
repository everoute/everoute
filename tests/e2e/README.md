# e2e
This document show how to setup or reset the lynx e2e environment.

## setup environment

### requirement
- At least one linux virtual machine for e2e environment.
- Openvswitch should installed for every virtual machine.

### step
1. Clone [lynx](https://github.com/smartxworks/lynx.git) into you e2e test environment.
2. Run script `bash -x tests/e2e/scripts/e2e-setup.sh APISERVER_EXPOSE_IP`. If `APISERVER_EXPOSE_IP` not specified, will use 127.0.0.1. Kubeconfig for lynx controller and agent generate under `/etc/lynx/kubeconfig`. Certs for lynx webhook generate at `/etc/lynx/pki/{tls.key, tls.crt}`.
3. Then use `make bin` to generate lynx controller and lynx agent binary.
4. Copy `bin/{lynx-controller,lynx-agent}` and `/etc/lynx/kubeconfig` and `/etc/lynx/pki/{tls.crt,tls.key}` (for lynx controller) to where you want to deploy on.
5. Start lynx-controller use `lynx-controller --kubeconfig LYNX_CONTROLLER_KUBECONFIG_PATH --leader-election-namespace kube-system --tls-certs-dir LYNX_PKI_PATH`.
6. Start lynx-agent use `lynx-agent --kubeconfig LYNX_AGENT_KUBECONFIG_PATH`.

## reset environment
1. Run script `bash -x tests/e2e/scripts/e2e-reset.sh` on you e2e test environment.
2. Stop lynx-controller and lynx-agent where you deploy by `kill -9 $(pidof lynx-controller) $(pidof lynx-agent)`.
