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

package command

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"strconv"

	"github.com/spf13/cobra"

	"github.com/everoute/everoute/tests/e2e/framework"
	"github.com/everoute/everoute/tests/e2e/framework/model"
)

func NewEndpointCommand(f *framework.Framework) *cobra.Command {
	ac := &cobra.Command{
		Use:     "endpoint <subcommand>",
		Short:   "Endpoint related commands",
		Aliases: []string{"ep"},
	}

	ac.AddCommand(newEpAddCommand(f))
	ac.AddCommand(newEpSetCommand(f))
	ac.AddCommand(newEpDelCommand(f))
	ac.AddCommand(newEpListCommand(f))
	ac.AddCommand(newEpExecCommand(f))

	return ac
}

func newEpAddCommand(f *framework.Framework) *cobra.Command {
	var labels, ipAddr, proto string
	var tcpPort, udpPort int

	cmd := &cobra.Command{
		Use:   "add <endpoint name> [options]",
		Short: "Add a new endpoint",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return fmt.Errorf("endpoint add command requires endpoint name as its argument")
			}
			if ipAddr != "" {
				ipAddr = fmt.Sprintf("%s/32", ipAddr)
			}
			return f.EndpointManager().SetupMany(context.TODO(), &model.Endpoint{
				Name:         args[0],
				Labels:       labelsFromString(labels),
				ExpectSubnet: ipAddr,
				TCPPort:      tcpPort,
				UDPPort:      udpPort,
				Proto:        proto,
			})
		},
	}

	cmd.PersistentFlags().StringVar(&labels, "labels", "", "endpoint labels, example: group=group01,env=production")
	cmd.PersistentFlags().StringVar(&ipAddr, "ip", "", "endpoint ipaddress, example: 10.0.0.2")
	cmd.PersistentFlags().IntVar(&tcpPort, "tcp-port", 0, "endpoint expose tcp port")
	cmd.PersistentFlags().IntVar(&udpPort, "udp-port", 0, "endpoint expose udp port")
	cmd.PersistentFlags().StringVar(&proto, "proto", "", "proto beyond tcp and udp, such as FTP")

	return cmd
}

func newEpSetCommand(f *framework.Framework) *cobra.Command {
	var labels string
	var tcpPort, udpPort int

	cmd := &cobra.Command{
		Use:   "set <endpoint name> [options]",
		Short: "Set or update endpoint attributes",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return fmt.Errorf("endpoint set command requires endpoint name as its argument")
			}
			return updateEndpoint(f, cmd, args[0])
		},
	}

	cmd.PersistentFlags().StringVar(&labels, "labels", "", "endpoint labels, example: group=group01,env=production")
	cmd.PersistentFlags().IntVar(&tcpPort, "tcp-port", 0, "endpoint expose tcp port")
	cmd.PersistentFlags().IntVar(&udpPort, "udp-port", 0, "endpoint expose udp port")

	return cmd
}

func newEpDelCommand(f *framework.Framework) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "del <endpoint name>",
		Aliases: []string{"delete"},
		Short:   "Destroy an old endpoint",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return fmt.Errorf("endpoint delete command requires endpoint name as its argument")
			}
			return f.EndpointManager().CleanMany(context.TODO(), &model.Endpoint{Name: args[0]})
		},
	}

	return cmd
}

func newEpListCommand(f *framework.Framework) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List and show all endpoints",
		RunE: func(cmd *cobra.Command, args []string) error {
			epList, err := f.EndpointManager().List(context.TODO())
			if err != nil {
				return err
			}
			return printEndpoint(cmd.OutOrStdout(), epList)
		},
	}

	return cmd
}

func newEpExecCommand(f *framework.Framework) *cobra.Command {
	var script string

	cmd := &cobra.Command{
		Use:   "exec <endpoint name> [--script script-name] <cmd/args>",
		Short: "Exec command in the endpoint",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) < 1 {
				return fmt.Errorf("endpoint exec command requires endpoint name as its argument")
			}
			return execEndpoint(f, script, args[0], args[1:]...)
		},
		DisableFlagParsing: true,
	}

	cmd.PersistentFlags().StringVar(&script, "script", "", "script expected to execute")

	return cmd
}

func updateEndpoint(f *framework.Framework, cmd *cobra.Command, name string) error {
	ep, err := f.EndpointManager().Get(context.TODO(), name)
	if err != nil {
		return err
	}

	if flag := cmd.Flag("labels"); flag.Changed {
		ep.Labels = labelsFromString(flag.Value.String())
	}

	if flag := cmd.Flag("tcp-port"); flag.Changed {
		ep.TCPPort, _ = strconv.Atoi(flag.Value.String())
	}

	if flag := cmd.Flag("udp-port"); flag.Changed {
		ep.UDPPort, _ = strconv.Atoi(flag.Value.String())
	}

	return f.EndpointManager().UpdateMany(context.TODO(), ep)
}

func execEndpoint(f *framework.Framework, scriptName string, name string, args ...string) error {
	var rc int
	var output []byte
	var err error

	if scriptName != "" {
		// run script
		var script []byte
		if script, err = ioutil.ReadFile(scriptName); err != nil {
			return err
		}
		rc, output, err = f.EndpointManager().RunScript(context.TODO(), name, script, args...)
	} else {
		// run command
		if len(args) < 1 {
			return fmt.Errorf("exec command should not empty")
		}
		rc, output, err = f.EndpointManager().RunCommand(context.TODO(), name, args[0], args[1:]...)
	}

	fmt.Println(string(output))
	if err != nil {
		return err
	}

	os.Exit(rc)
	return nil
}
