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

package command

import (
	"fmt"
	"github.com/spf13/cobra"

	"github.com/smartxworks/lynx/tests/e2e/framework"
)

func NewCheckCommand(f *framework.Framework) *cobra.Command {
	ac := &cobra.Command{
		Use:   "check <subcommand>",
		Short: "Check the health of lynx components",
	}

	ac.AddCommand(newCheckAgentCommand(f))

	return ac
}

func newCheckAgentCommand(f *framework.Framework) *cobra.Command {
	var port, timeout int

	cmd := &cobra.Command{
		Use:   "agent [options]",
		Short: "Agent show agent health",
		Run: func(cmd *cobra.Command, args []string) {
			checkAgent(f, port, timeout)
		},
	}

	cmd.PersistentFlags().IntVarP(&port, "port", "p", 30000, "lynx agent expose port")
	cmd.PersistentFlags().IntVarP(&timeout, "timeout", "t", 1, "timeout seconds, the default 0 is no timeout")

	return cmd
}

func checkAgent(f *framework.Framework, port, timeout int) {
	for agent, health := range f.CheckAgentHealth(port, timeout) {
		fmt.Printf("check agent %s health: %t\n", agent, health)
	}
}
