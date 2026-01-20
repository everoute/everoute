package main

import (
	"os"

	"github.com/spf13/cobra"

	"github.com/everoute/everoute/pkg/config"
	tract "github.com/everoute/everoute/pkg/trafficredirect/action"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "erdeploy",
	Short: "do some operations when deploy everoute agent",
}

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "init before deploy everoute agent",
	Long:  `you should use [init tr]`,
}

var cleanCmd = &cobra.Command{
	Use:   "clean",
	Short: "clean after uninstall everoute agent",
	Long:  `you should use [clean tr]`,
}

var cleanTrCmd = &cobra.Command{
	Use:   "tr",
	Short: "clean trafficredirect after uninstall everoute agent",
	RunE: func(_ *cobra.Command, _ []string) (err error) {
		return tract.Reset(nil)
	},
}

var initTrCmd = &cobra.Command{
	Use:   "tr",
	Short: "init before deploy everoute agent",
	RunE: func(_ *cobra.Command, _ []string) (err error) {
		cfg, err := config.GetAgentConfig()
		if err != nil {
			return err
		}
		return tract.Reset(cfg)
	},
}

func init() {
	initCmd.AddCommand(initTrCmd)
	cleanCmd.AddCommand(cleanTrCmd)
	rootCmd.AddCommand(initCmd)
	rootCmd.AddCommand(cleanCmd)
}

func main() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}
