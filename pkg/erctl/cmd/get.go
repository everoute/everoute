package cmd

import (
	"github.com/spf13/cobra"
)

var getCmd = &cobra.Command{
	Use:   "get",
	Short: "get something",
	Long:  `you shold use [get rule] or [get flow]`,
}

func init() {
	rootCmd.AddCommand(getCmd)
}
