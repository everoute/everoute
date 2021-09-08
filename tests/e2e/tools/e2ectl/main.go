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

package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/smartxworks/lynx/tests/e2e/framework"
	"github.com/smartxworks/lynx/tests/e2e/tools/e2ectl/command"
)

func main() {
	if err := rootCommand().Execute(); err != nil {
		os.Exit(1)
	}
}

func rootCommand() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:   "e2ectl",
		Short: "E2ectl: help you quickly start lynx e2e test",
	}

	f, err := framework.NewFromKube(filepath.Join(os.Getenv("HOME"), ".kube", "config"))
	if err != nil {
		fmt.Printf("unable init e2e framework: %s\n", err)
		os.Exit(1)
	}

	rootCmd.Root().SilenceUsage = true
	rootCmd.Root().SetHelpCommand(&cobra.Command{Hidden: true})
	rootCmd.ResetFlags()

	rootCmd.AddCommand(command.NewEndpointCommand(f))
	rootCmd.AddCommand(command.NewReachCommand(f))

	return rootCmd
}
