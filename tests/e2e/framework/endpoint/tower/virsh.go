/*
Copyright 2021 The Lynx Authors.

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

package tower

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/ssh"
)

type qemuAgentCommand struct {
	Execute   string          `json:"execute"`
	Arguments json.RawMessage `json:"arguments"`
}

type qemuAgentCommandReturn struct {
	Return json.RawMessage `json:"return"`
}

// virsh-exec-status return json type
type guestExecStatus struct {
	Exited       bool    `json:"exited"`
	Exitcode     *int    `json:"exitcode,omitempty"`
	Signal       *int    `json:"signal,omitempty"`
	OutData      *string `json:"out-data,omitempty"`
	ErrData      *string `json:"err-data,omitempty"`
	OutTruncated *bool   `json:"out-truncated,omitempty"`
	ErrTruncated *bool   `json:"err-truncated,omitempty"`
}

// virsh-exec request arguments
type guestExec struct {
	Path          string   `json:"path"`
	Arg           []string `json:"arg,omitempty"`
	Env           []string `json:"env,omitempty"`
	InputData     *string  `json:"input-data,omitempty"`
	CaptureOutput bool     `json:"capture-output,omitempty"`
}

// waitForGuestAgentReady will run true in the guest until successed or timeout
func waitForGuestAgentReady(client *ssh.Client, domain string, timeout time.Duration) error {
	startTime := time.Now()

	for {
		result, err := guestExecWait(client, domain, timeout, &guestExec{Path: "true"})
		if err == nil && *result.Exitcode == 0 {
			return nil
		}
		if timeout != 0 && time.Since(startTime) > timeout {
			// if timeout != 0, and wait for timeout, return error
			return errors.New("wait for command result timeout")
		}
	}
}

// guestExecWait run guestExec and wait for guestExecResult
func guestExecWait(client *ssh.Client, domain string, timeout time.Duration, args *guestExec) (*guestExecStatus, error) {
	data, err := json.Marshal(args)
	if err != nil {
		return nil, err
	}

	execResult, err := qemuAgentExecute(client, domain, timeout, &qemuAgentCommand{Execute: "guest-exec", Arguments: data})
	if err != nil {
		return nil, err
	}

	execStatus := guestExecStatus{}
	startTime := time.Now()

	for {
		statusResult, err := qemuAgentExecute(client, domain, timeout, &qemuAgentCommand{Execute: "guest-exec-status", Arguments: execResult.Return})
		if err != nil {
			return nil, err
		}
		if err = json.Unmarshal(statusResult.Return, &execStatus); err != nil {
			return nil, err
		}
		if execStatus.Exited {
			break
		}
		if timeout != 0 && time.Since(startTime) > timeout {
			// if timeout != 0, and wait for timeout, return error
			return nil, errors.New("wait for command result timeout")
		}
	}

	return &execStatus, nil
}

// qemuAgentExecute run "virsh qemu-agent-command" with gived client.
// More: https://github.com/qemu/qemu/blob/master/qga/qapi-schema.json
func qemuAgentExecute(client *ssh.Client, domain string, timeout time.Duration, cmd *qemuAgentCommand) (*qemuAgentCommandReturn, error) {
	data, err := json.Marshal(cmd)
	if err != nil {
		return nil, err
	}

	session, err := client.NewSession()
	if err != nil {
		return nil, err
	}
	defer session.Close()

	command := fmt.Sprintf("virsh qemu-agent-command --domain %s '%s'", domain, string(data))
	if timeout != 0 {
		command += fmt.Sprintf(" --timeout %d", timeout/time.Second)
	}

	var stdout, stderr bytes.Buffer
	session.Stdout = &stdout
	session.Stderr = &stderr

	if err = session.Run(command); err != nil {
		return nil, fmt.Errorf("err: %s, stderr: %s", err, stderr.String())
	}

	execResult := qemuAgentCommandReturn{}
	if err = json.Unmarshal(stdout.Bytes(), &execResult); err != nil {
		return nil, err
	}
	return &execResult, nil
}
