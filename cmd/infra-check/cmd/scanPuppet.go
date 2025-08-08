package cmd

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	// "github.com/salchaD-27/infra-check/internal/finding"
	"github.com/salchaD-27/infra-check/internal/puppet"
	"github.com/salchaD-27/infra-check/internal/report"
)

var reportFormat string

var puppetOutputFormat string

var puppetCmd = &cobra.Command{
	Use:   "puppet [path]",
	Short: "Scan Puppet manifests in the specified directory",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		path := args[0]

		findings, err := puppet.Scan(path)
		if err != nil {
			return err
		}

		// Export the findings in the requested format
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

		default: // plain text
			for _, f := range findings {
				fmt.Printf("[%s] %s: %s\n", f.Severity, f.File, f.Message)
			}
		}

		return nil
	},
}

func init() {
	puppetCmd.Flags().StringVarP(&reportFormat, "format", "f", "text", "Output format: text|json|markdown|gha")
	scanCmd.AddCommand(puppetCmd)
}
