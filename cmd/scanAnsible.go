package cmd

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/salchaD-27/infra-check/internal/ansible"
	"github.com/salchaD-27/infra-check/internal/report"
)

var ansibleOutputFormat string

var ansibleCmd = &cobra.Command{
	Use:   "ansible [path]",
	Short: "Scan Ansible playbooks in the specified directory",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		path := args[0]

		findings, err := ansible.Scan(path)
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
		default: // plain text
			for _, f := range findings {
				fmt.Printf("[%s] %s: %s\n", f.Severity, f.File, f.Message)
			}
		}

		return nil
	},
}

func init() {
	ansibleCmd.Flags().StringVarP(&reportFormat, "format", "f", "text", "Output format: text|json|markdown|gha")
	scanCmd.AddCommand(ansibleCmd)
}
