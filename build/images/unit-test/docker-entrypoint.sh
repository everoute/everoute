#!/usr/bin/env bash

set -o errexit
set -o pipefail
set -o nounset
set -o xtrace

# start ovs
modprobe openvswitch || depmod -a || modprobe openvswitch
/usr/share/openvswitch/scripts/ovs-ctl --system-id=random start

# start sshd
mkdir /run/sshd
/usr/sbin/sshd

eval $@
