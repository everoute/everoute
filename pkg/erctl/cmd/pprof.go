package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/everoute/everoute/pkg/erctl"
)

var setPprofCmd = &cobra.Command{
	Use:   "set-pprof [enable|disable]",
	Short: "Enable or disable agent pprof HTTP handlers",
	Args:  cobra.ExactArgs(1),
	RunE: func(_ *cobra.Command, args []string) error {
		if err := erctl.ConnectClient(); err != nil {
			return err
		}

		var (
			enabled bool
			url     string
			err     error
		)
		switch args[0] {
		case "enable":
			enabled, url, err = erctl.EnablePprof()
		case "disable":
			enabled, url, err = erctl.DisablePprof()
		default:
			return fmt.Errorf("pprof state must be enable or disable")
		}
		if err != nil {
			return err
		}
		fmt.Printf("pprof enabled: %t, url: %s\n", enabled, url)
		return nil
	},
}

var getPprofCmd = &cobra.Command{
	Use:   "get-pprof",
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

func init() {
	rootCmd.AddCommand(setPprofCmd)
	rootCmd.AddCommand(getPprofCmd)
}
