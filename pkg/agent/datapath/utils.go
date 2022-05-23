/*
Copyright 2021 The Everoute Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package datapath

import (
	"fmt"
	"os/exec"
)

const (
	SetupBridgeChain = `
		set -o errexit
		set -o nounset
		set -o xtrace

		DEFAULT_BRIDGE=%s
		POLICY_BRIDGE="${DEFAULT_BRIDGE}-policy"
		CLS_BRIDGE="${DEFAULT_BRIDGE}-cls"
		UPLINK_BRIDGE="${DEFAULT_BRIDGE}-uplink"

		LOCAL_TO_POLICY_PATCH="${DEFAULT_BRIDGE}-local-to-policy"
		POLICY_TO_LOCAL_PATCH="${POLICY_BRIDGE}-policy-to-local"
		POLICY_TO_CLS_PATCH="${POLICY_BRIDGE}-policy-to-cls"
		CLS_TO_POLICY_PATCH="${CLS_BRIDGE}-cls-to-policy"
		CLS_TO_UPLINK_PATCH="${CLS_BRIDGE}-cls-to-uplink"
		UPLINK_TO_CLS_PATCH="${UPLINK_BRIDGE}-uplink-to-cls"

		echo "add bridge chain and uplink port"
		ovs-vsctl add-br ${DEFAULT_BRIDGE}
		ovs-vsctl add-br ${POLICY_BRIDGE}
		ovs-vsctl add-br ${CLS_BRIDGE}
		ovs-vsctl add-br ${UPLINK_BRIDGE}

		ovs-vsctl \
		    -- add-port ${DEFAULT_BRIDGE} ${LOCAL_TO_POLICY_PATCH} \
		    -- set interface ${LOCAL_TO_POLICY_PATCH} type=patch options:peer=${POLICY_TO_LOCAL_PATCH} \
		    -- add-port ${POLICY_BRIDGE} ${POLICY_TO_LOCAL_PATCH} \
		    -- set interface ${POLICY_TO_LOCAL_PATCH} type=patch options:peer=${LOCAL_TO_POLICY_PATCH}

		ovs-vsctl \
		    -- add-port ${POLICY_BRIDGE} ${POLICY_TO_CLS_PATCH} \
		    -- set interface ${POLICY_TO_CLS_PATCH} type=patch options:peer=${CLS_TO_POLICY_PATCH} \
		    -- add-port ${CLS_BRIDGE} ${CLS_TO_POLICY_PATCH} \
		    -- set interface ${CLS_TO_POLICY_PATCH} type=patch options:peer=${POLICY_TO_CLS_PATCH} 

		ovs-vsctl \
		    -- add-port ${UPLINK_BRIDGE} ${UPLINK_TO_CLS_PATCH} \
		    -- set interface ${UPLINK_TO_CLS_PATCH} type=patch options:peer=${CLS_TO_UPLINK_PATCH} \
		    -- add-port ${CLS_BRIDGE} ${CLS_TO_UPLINK_PATCH} \
		    -- set interface ${CLS_TO_UPLINK_PATCH} type=patch options:peer=${UPLINK_TO_CLS_PATCH} 

		ovs-ofctl add-flow ${UPLINK_BRIDGE} "table=0,priority=10,actions=normal"
    `
	CleanBridgeChain = `
		DEFAULT_BRIDGE=%s
		POLICY_BRIDGE="${DEFAULT_BRIDGE}-policy"
		CLS_BRIDGE="${DEFAULT_BRIDGE}-cls"
		UPLINK_BRIDGE="${DEFAULT_BRIDGE}-uplink"

		ovs-vsctl \
			-- del-br ${DEFAULT_BRIDGE} \
			-- del-br ${POLICY_BRIDGE} \
			-- del-br ${CLS_BRIDGE} \
			-- del-br ${UPLINK_BRIDGE}
    `
)

func ExcuteCommand(cmdStr, arg string) error {
	commandStr := fmt.Sprintf(cmdStr, arg)
	out, err := exec.Command("/bin/sh", "-c", commandStr).CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to excute cmd: %v, error: %v", string(out), err)
	}

	return nil
}

func ParseMacToUint64(b []byte) uint64 {
	_ = b[5]
	return uint64(b[5]) | uint64(b[4])<<8 | uint64(b[3])<<16 | uint64(b[2])<<24 |
		uint64(b[1])<<32 | uint64(b[0])<<40 | 0<<48 | 0<<56
}
