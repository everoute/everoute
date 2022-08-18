package cmd

import (
	"bytes"
	"os"

	"github.com/spf13/cobra"
)

var (
	outfile, infile                  string
	ruleIDs                          []string
	flowIDs                          []int64
	sortDifference, sortIntersection []string
	showDifference, showIntersection []string
	nextInput                        *bytes.Buffer
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "erctl",
	Short: "check completeRule",
	Long: "It's the root cmd of erctl, can't be called\n" +
		"you can use erctl get [-f|-r|nil] [--srcip --dstip --dstport --protocol]",
}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&outfile, "outfile", "o", "", "specify which file to print")
}
