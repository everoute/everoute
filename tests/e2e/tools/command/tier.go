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
	"k8s.io/klog"

	"github.com/smartxworks/lynx/pkg/apis/security/v1alpha1"
	"github.com/smartxworks/lynx/tests/e2e/framework"
)

func NewTierCommand(f *framework.Framework) *cobra.Command {
	ac := &cobra.Command{
		Use:   "tier <subcommand>",
		Short: "Tier related commands",
	}

	ac.AddCommand(newTierListCommand(f))
	ac.AddCommand(newTierInitCommand(f))

	return ac
}

func newTierInitCommand(f *framework.Framework) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Init default tier: tier0, tier1, tier2",
		RunE: func(cmd *cobra.Command, args []string) error {
			return initTier(f)
		},
	}

	return cmd
}

func newTierListCommand(f *framework.Framework) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "ls",
		Aliases: []string{"list"},
		Short:   "List and show all tiers",
		RunE: func(cmd *cobra.Command, args []string) error {
			return listTier(f, cmd.OutOrStdout())
		},
	}

	return cmd
}

func initTier(f *framework.Framework) error {
	err := f.SetupObjects(defaultTier(tier0), defaultTier(tier1), defaultTier(tier2))
	if err != nil {
		return fmt.Errorf("unable setup default tier: %s", err)
	}

	klog.Infof("setup default tier: %s, %s, %s\n", tier0, tier1, tier2)
	return nil
}

func listTier(f *framework.Framework, output io.Writer) error {
	var client = f.GetClient()
	var tierList = &v1alpha1.TierList{}

	err := client.List(context.TODO(), tierList)
	if err != nil {
		return err
	}

	return printTier(output, tierList.Items)
}

const (
	// default tier tier0, tier1, tier2
	tier0 = "tier0"
	tier1 = "tier1"
	tier2 = "tier2"
)

func defaultTier(name string) *v1alpha1.Tier {
	defaultTier := &v1alpha1.Tier{}
	defaultTier.Name = name
	defaultTier.Spec.TierMode = v1alpha1.TierWhiteList

	switch name {
	case tier0:
		defaultTier.Spec.Priority = 0
	case tier1:
		defaultTier.Spec.Priority = 1
	case tier2:
		defaultTier.Spec.Priority = 2
	default:
		klog.Fatalf("tier %s is not default tier", name)
	}

	return defaultTier
}
