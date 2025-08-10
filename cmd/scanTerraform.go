package cmd

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/salchaD-27/infra-check/internal/report"
	"github.com/salchaD-27/infra-check/internal/terraform"
)

var outputFormat string

// terraformCmd represents the terraform scan command
var terraformCmd = &cobra.Command{
	Use:   "terraform [path]",
	Short: "Scan Terraform files in the specified directory",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		path := args[0]

		findings, err := terraform.Scan(path)
		if err != nil {
			return err
		}

		switch strings.ToLower(reportFormat) {
		case "json":
			out, err := report.ExportJSON(findings)
			if err != nil {
				return err
			}
			fmt.Println(out)

		case "markdown":
			out, err := report.ExportMarkdown(findings)
			if err != nil {
				return err
			}
			fmt.Println(out)

		case "gha":
			out, err := report.ExportGitHubActions(findings)
			if err != nil {
				return err
			}
			fmt.Print(out)

		default:
			for _, f := range findings {
				fmt.Printf("[%s] %s: %s\n", f.Severity, f.File, f.Message)
			}
		}

		return nil
	},
}

func init() {
	terraformCmd.Flags().StringVarP(&reportFormat, "format", "f", "text", "Output format: text|json|markdown|gha")

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// terraformCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// terraformCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")

	scanCmd.AddCommand(terraformCmd)
}
