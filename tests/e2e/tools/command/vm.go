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
	"context"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/errors"

	"github.com/smartxworks/lynx/pkg/apis/security/v1alpha1"
	"github.com/smartxworks/lynx/tests/e2e/framework"
)

func NewVMCommand(f *framework.Framework) *cobra.Command {
	ac := &cobra.Command{
		Use:   "vm <subcommand>",
		Short: "VM related commands",
	}

	ac.AddCommand(newVmAddCommand(f))
	ac.AddCommand(newVmSetCommand(f))
	ac.AddCommand(newVmDelCommand(f))
	ac.AddCommand(newVmListCommand(f))
	ac.AddCommand(newVmExecCommand(f))

	return ac
}

func newVmAddCommand(f *framework.Framework) *cobra.Command {
	var labels, ipAddr string
	var tcpPort, udpPort int

	cmd := &cobra.Command{
		Use:   "add <vm name> [options]",
		Short: "Add a new vm",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return fmt.Errorf("vm add command requires vm name as its argument")
			}
			return setupVM(f, args[0], labels, ipAddr, tcpPort, udpPort)
		},
	}

	cmd.PersistentFlags().StringVar(&labels, "labels", "", "vm labels, example: group=group01,env=production")
	cmd.PersistentFlags().StringVar(&ipAddr, "ip", "", "vm ipaddress, example: 10.0.0.2")
	cmd.PersistentFlags().IntVar(&tcpPort, "tcp-port", 0, "vm expose tcp port")
	cmd.PersistentFlags().IntVar(&udpPort, "udp-port", 0, "vm expose udp port")

	return cmd
}

// todo: now is only support labels and ipaddr
func newVmSetCommand(f *framework.Framework) *cobra.Command {
	var labels, ipAddr string

	cmd := &cobra.Command{
		Use:   "set <vm name> [options]",
		Short: "Set or update vm attributes",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return fmt.Errorf("vm set command requires vm name as its argument")
			}
			return setVM(f, args[0], labels, ipAddr)
		},
	}

	cmd.PersistentFlags().StringVar(&labels, "labels", "", "vm labels, example: group=group01,env=production")
	cmd.PersistentFlags().StringVar(&ipAddr, "ip", "", "vm ipaddress, example: 10.0.0.2")

	return cmd
}

func newVmDelCommand(f *framework.Framework) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "del <vm name>",
		Aliases: []string{"delete"},
		Short:   "Destroy an old vm",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return fmt.Errorf("vm delete command requires vm name as its argument")
			}
			return destroyVM(f, args[0])
		},
	}

	return cmd
}

func newVmListCommand(f *framework.Framework) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "ls",
		Aliases: []string{"list"},
		Short:   "List and show all vms",
		RunE: func(cmd *cobra.Command, args []string) error {
			return listVM(f, cmd.OutOrStdout())
		},
	}

	return cmd
}

func newVmExecCommand(f *framework.Framework) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "exec <vm name> <command>",
		Short: "Exec command in the vm",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) <= 1 {
				return fmt.Errorf("vm exec command requires vm name and command as its argument")
			}
			return execVM(f, args[0], args[1:]...)
		},
		DisableFlagParsing: true,
	}

	return cmd
}

func setupVM(f *framework.Framework, name, labels, ip string, tcpPort, udpPort int) error {
	if ip != "" {
		ip = fmt.Sprintf("%s/32", ip)
	}

	err := f.SetupVMs(&framework.VM{
		Name:       name,
		Labels:     labels,
		ExpectCidr: ip,
		TCPPort:    tcpPort,
		UDPPort:    udpPort,
	})

	if err != nil {
		return fmt.Errorf("unable setup vm %s: %s", name, err)
	}

	return nil
}

func destroyVM(f *framework.Framework, name string) error {
	vm, err := fetchVM(f, name)
	if err != nil {
		return err
	}

	return f.CleanVMs(vm)
}

func execVM(f *framework.Framework, name string, args ...string) error {
	vm, err := fetchVM(f, name)
	if err != nil {
		return err
	}

	rc, err := f.ExecCommand(vm, args...)
	if rc != 0 {
		os.Exit(rc)
	}

	return err
}

func setVM(f *framework.Framework, name, labels, ipAddr string) error {
	var errList []error

	switch labels {
	case "":
	case "-":
		errList = append(errList, setVMLabels(f, name, ""))
	default:
		errList = append(errList, setVMLabels(f, name, labels))
	}

	if ipAddr != "" {
		errList = append(errList, setVMIpAddr(f, name, ipAddr))
	}

	return errors.NewAggregate(errList)
}

func listVM(f *framework.Framework, output io.Writer) error {
	var client = f.GetClient()
	var epList = &v1alpha1.EndpointList{}

	err := client.List(context.TODO(), epList)
	if err != nil {
		return err
	}

	return printVM(output, epList.Items)
}

func setVMLabels(f *framework.Framework, name, labels string) error {
	vm, err := fetchVM(f, name)
	if err != nil {
		return err
	}

	vm.Labels = labels
	return f.UpdateVMLabels(vm)
}

func setVMIpAddr(f *framework.Framework, name, ipAddr string) error {
	vm, err := fetchVM(f, name)
	if err != nil {
		return err
	}

	vm.ExpectCidr = fmt.Sprintf("%s/32", ipAddr)
	return f.UpdateVMRandIP(vm)
}

func fetchVM(f *framework.Framework, name string) (*framework.VM, error) {
	var client = f.GetClient()
	var ep = &v1alpha1.Endpoint{}

	err := client.Get(context.TODO(), types.NamespacedName{Name: name}, ep)
	if err != nil {
		return nil, fmt.Errorf("unable fetch vm information: %s", err)
	}

	vm := &framework.VM{
		Name:   ep.Name,
		Labels: mapJoin(ep.Labels, "=", ","),
	}

	if len(ep.Status.IPs) == 0 {
		framework.SetVM(vm, ep.Annotations["Agent"], ep.Annotations["Netns"], "")
	} else {
		framework.SetVM(vm, ep.Annotations["Agent"], ep.Annotations["Netns"], ep.Status.IPs[0].String())
	}

	return vm, nil
}
