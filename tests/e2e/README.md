# e2e
This document show how to setup or reset the lynx e2e environment.

## setup environment

### requirement
- At least one linux virtual machine for e2e environment.
- Openvswitch should be installed for every agent node.

### step
1. Clone [lynx](https://github.com/smartxworks/lynx.git) into you e2e test environment.
2. Enter folder lynx, run the following script to setup e2e environment.
```shell script
# APISERVER_EXPOSE_IP should be the ip address lynx-agent can connection with.
APISERVER_EXPOSE_IP=""
# LYNX_AGENT_HOSTLIST is a list of lynx-agent, multiple lynx-agent should write as "192.168.1.1,192.168.1.2"
LYNX_AGENT_HOSTLIST=""
# UPLINK_IFACE is the interface name for lynx-agent uplink port, default ens11.
UPLINK_IFACE=""
# PLATFORM is the system platform, default amd64
PLATFORM=""

bash -x tests/e2e/scripts/e2e-setup.sh ${APISERVER_EXPOSE_IP} ${LYNX_AGENT_HOSTLIST} ${UPLINK_IFACE} ${PLATFORM}
```

## reset environment
Run the following script to reset e2e environment.
```shell script
bash -x tests/e2e/scripts/e2e-reset.sh ${LYNX_AGENT_HOSTLIST}
```
