package cmd

import (
	"github.com/spf13/cobra"
)

var showCmd = &cobra.Command{
	Use:   "show",
	Short: "specify which field you want show",
	Long: "[-D {fieldName...}] means don't show {fieldName...} (like blacklist)\n" +
		"[-I {fieldName...}] means only show {fieldName...} (like whitelist)",
	RunE: func(cmd *cobra.Command, args []string) error {
		ruleMaps, _, err := getRuleMapsFromSomewhere()
		if err != nil {
			return err
		}
		out, err := setOutput()
		if err != nil {
			return err
		}
		check := newCheck()
		for _, s := range showDifference {
			check.add(getCheckFunc(s, "", "delete"))
		}
		next := make([]map[string]interface{}, len(ruleMaps))
		for i := 0; i < len(next); i++ {
			next[i] = map[string]interface{}{}
		}
		for _, s := range showIntersection {
			check.add(getSetCheckFun(s, next))
		}
		for _, ruleMap := range ruleMaps {
			check.check(ruleMap)
		}
		if len(showIntersection) != 0 {
			ruleMaps = next
		}
		err = print(out, ruleMaps)
		if err != nil {
			return err
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(showCmd)
	showCmd.Flags().StringVarP(&infile, "infile", "f", "", "specify input file")
	showCmd.Flags().StringSliceVarP(&showDifference, "showdifference", "D",
		[]string{}, "control which field don't show")
	showCmd.Flags().StringSliceVarP(&showIntersection, "showintersection", "I",
		[]string{}, "control which field show, high priority")
}
