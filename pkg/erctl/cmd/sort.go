package cmd

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

var sortCmd = &cobra.Command{
	Use:   "sort",
	Short: "filter rules by the way you specify",
	Long: "provide [-d] difference set and [-i] intersection set\n" +
		"For example:\n" +
		"rule:[{foo:bar},{foo:aaa},{foo:bbb}]\n" +
		"[-i foo=bar] return [{foo:bar}]\n" +
		"[-d foo=bar] return [{foo:aaa},{foo:bbb}]",
	RunE: func(cmd *cobra.Command, args []string) error {
		ruleMaps, original, err := getRuleMapsFromSomewhere()
		if err != nil {
			return err
		}
		out, err := setOutput()
		if err != nil {
			return err
		}

		check := newCheck()

		if err = addCheck(sortIntersection, check, "=="); err != nil {
			return err
		}
		if err = addCheck(sortDifference, check, "!="); err != nil {
			return err
		}

		result := []map[string]interface{}{}
		for i, ruleMap := range ruleMaps {
			if put := check.check(ruleMap); put {
				result = append(result, original[i])
			}
		}
		err = print(out, result)
		if err != nil {
			return err
		}
		return nil
	},
}

func addCheck(conditions []string, check *check, way string) error {
	for _, condition := range conditions {
		kv := strings.Split(condition, "=")
		if len(kv) != 2 {
			return fmt.Errorf("you should give k=v, but you give %s", condition)
		}
		check.add(getCheckFunc(kv[0], kv[1], way))
	}
	return nil
}

func init() {
	rootCmd.AddCommand(sortCmd)
	sortCmd.Flags().StringVarP(&infile, "infile", "f", "", "specify input file")
	sortCmd.Flags().StringSliceVarP(&sortDifference, "sortdifference", "d",
		[]string{}, "it means !=")
	sortCmd.Flags().StringSliceVarP(&sortIntersection, "sortintersection", "i",
		[]string{}, "it means ==")
}
