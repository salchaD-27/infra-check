package report

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/salchaD-27/infra-check/internal/finding"
)

// ExportMarkdown returns a Markdown formatted report string.
func ExportMarkdown(findings []finding.Finding) (string, error) {
	var b strings.Builder
	b.WriteString("# InfraCheck Report\n\n")

	if len(findings) == 0 {
		b.WriteString("✅ No issues found.\n")
		return b.String(), nil
	}

	for _, f := range findings {
		b.WriteString(fmt.Sprintf("- **[%s]** `%s`: %s\n", f.Severity, f.File, f.Message))
	}

	return b.String(), nil
}

// ExportJSON returns the JSON formatted report string.
func ExportJSON(findings []finding.Finding) (string, error) {
	data, err := json.MarshalIndent(findings, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// ExportGitHubActions returns a GitHub Actions annotation formatted string.
func ExportGitHubActions(findings []finding.Finding) (string, error) {
	var b strings.Builder
	for _, f := range findings {
		level := ""
		switch f.Severity {
		case finding.Error:
			level = "error"
		case finding.Warning:
			level = "warning"
		default:
			level = "notice"
		}
		b.WriteString(fmt.Sprintf("::%s file=%s::%s\n", level, f.File, escapeGHA(f.Message)))
	}
	return b.String(), nil
}

// escapeGHA escapes special characters for GitHub Actions annotations
// GitHub Actions supports annotations using special logs:
// ::error file=app.js,line=1,col=5::Missing semicolon
// ::warning file=app.js,line=2,col=1::Deprecated function usage
// ::notice file=app.js,line=3,col=1::Consider refactoring
func escapeGHA(msg string) string {
	replacements := []struct{ old, new string }{
		{"%", "%25"},
		{"\r", "%0D"},
		{"\n", "%0A"},
		{":", "%3A"},
		{",", "%2C"},
	}
	for _, r := range replacements {
		msg = strings.ReplaceAll(msg, r.old, r.new)
	}
	return msg
}
