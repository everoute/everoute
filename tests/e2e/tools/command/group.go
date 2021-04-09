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

	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	groupv1alpha1 "github.com/smartxworks/lynx/pkg/apis/group/v1alpha1"
	"github.com/smartxworks/lynx/pkg/apis/security/v1alpha1"
	"github.com/smartxworks/lynx/tests/e2e/framework"
)

func NewGroupCommand(f *framework.Framework) *cobra.Command {
	ac := &cobra.Command{
		Use:   "group <subcommand>",
		Short: "Group related commands",
	}

	ac.AddCommand(newGroupAddCommand(f))
	ac.AddCommand(newGroupSetCommand(f))
	ac.AddCommand(newGroupDelCommand(f))
	ac.AddCommand(newGroupListCommand(f))

	return ac
}

func newGroupAddCommand(f *framework.Framework) *cobra.Command {
	var selector string

	cmd := &cobra.Command{
		Use:   "add <group name> [options]",
		Short: "Add a new endpoint group",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return fmt.Errorf("group add command requires group name as its argument")
			}
			return addGroup(f, args[0], selector)
		},
	}

	cmd.PersistentFlags().StringVar(&selector, "selector", "", "vm labels, example: group=group01,env=production")

	return cmd
}

func newGroupSetCommand(f *framework.Framework) *cobra.Command {
	var selector string

	cmd := &cobra.Command{
		Use:   "set <group name> [options]",
		Short: "Set or update group attributes",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return fmt.Errorf("group set command requires group name as its argument")
			}
			return setGroupSelector(f, args[0], selector)
		},
	}

	cmd.PersistentFlags().StringVar(&selector, "selector", "", "vm labels, example: group=group01,env=production")

	return cmd
}

func newGroupDelCommand(f *framework.Framework) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "del <vm name>",
		Aliases: []string{"delete"},
		Short:   "Delete an old group",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return fmt.Errorf("group delete command requires group name as its argument")
			}
			return delGroup(f, args[0])
		},
	}

	return cmd
}

func newGroupListCommand(f *framework.Framework) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "ls",
		Aliases: []string{"list"},
		Short:   "List and show all groups",
		RunE: func(cmd *cobra.Command, args []string) error {
			return listGroup(f, cmd.OutOrStdout())
		},
	}

	return cmd
}

func addGroup(f *framework.Framework, name string, selector string) error {
	group := &groupv1alpha1.EndpointGroup{}
	group.Name = name

	group.Spec.Selector = &metav1.LabelSelector{
		MatchLabels: framework.AsMapLables(selector),
	}

	return f.SetupObjects(group)
}

func delGroup(f *framework.Framework, name string) error {
	var client = f.GetClient()
	var group = &groupv1alpha1.EndpointGroup{}

	err := client.Get(context.TODO(), types.NamespacedName{Name: name}, group)
	if err != nil {
		return err
	}

	return client.Delete(context.TODO(), group)
}

func listGroup(f *framework.Framework, output io.Writer) error {
	var client = f.GetClient()
	var epList = &v1alpha1.EndpointList{}
	var groupList = &groupv1alpha1.EndpointGroupList{}

	err := client.List(context.TODO(), epList)
	if err != nil {
		return err
	}

	err = client.List(context.TODO(), groupList)
	if err != nil {
		return err
	}

	return printGroup(output, groupList.Items, epList.Items)
}

func setGroupSelector(f *framework.Framework, name string, selector string) error {
	var client = f.GetClient()
	var group = &groupv1alpha1.EndpointGroup{}

	err := client.Get(context.TODO(), types.NamespacedName{Name: name}, group)
	if err != nil {
		return err
	}

	group.Spec.Selector = &metav1.LabelSelector{
		MatchLabels: framework.AsMapLables(selector),
	}

	return client.Update(context.TODO(), group)
}
