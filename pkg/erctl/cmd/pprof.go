package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/everoute/everoute/pkg/erctl"
)

var pprofCmd = &cobra.Command{
	Use:   "pprof",
	Short: "Manage agent pprof HTTP handlers",
}

var enablePprofCmd = &cobra.Command{
	Use:   "enable",
	Short: "Enable agent pprof HTTP handlers",
	Args:  cobra.NoArgs,
	RunE: func(_ *cobra.Command, _ []string) error {
		enabled, url, err := setPprofEnabled(true)
		if err != nil {
			return err
		}
		fmt.Printf("pprof enabled: %t, url: %s\n", enabled, url)
		return nil
	},
}

var disablePprofCmd = &cobra.Command{
	Use:   "disable",
	Short: "Disable agent pprof HTTP handlers",
	Args:  cobra.NoArgs,
	RunE: func(_ *cobra.Command, _ []string) error {
		enabled, url, err := setPprofEnabled(false)
		if err != nil {
			return err
		}
		fmt.Printf("pprof enabled: %t, url: %s\n", enabled, url)
		return nil
	},
}

var pprofStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Get agent pprof HTTP handler status",
	Args:  cobra.NoArgs,
	RunE: func(_ *cobra.Command, _ []string) error {
		if err := erctl.ConnectClient(); err != nil {
			return err
		}
		enabled, url, err := erctl.GetPprofStatus()
		if err != nil {
			return err
		}
		fmt.Printf("pprof enabled: %t, url: %s\n", enabled, url)
		return nil
	},
}

func setPprofEnabled(enabled bool) (bool, string, error) {
	if err := erctl.ConnectClient(); err != nil {
		return false, "", err
	}
	if enabled {
		return erctl.EnablePprof()
	}
	return erctl.DisablePprof()
}

func init() {
	pprofCmd.AddCommand(enablePprofCmd)
	pprofCmd.AddCommand(disablePprofCmd)
	pprofCmd.AddCommand(pprofStatusCmd)
	rootCmd.AddCommand(pprofCmd)
}
