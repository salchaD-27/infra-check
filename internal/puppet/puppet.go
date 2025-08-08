package puppet

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/salchaD-27/infra-check/internal/finding"
)

// List of known deprecated Puppet resource types (example)
var deprecatedResources = []string{
	"execpipe",           // Deprecated: use 'exec' with better practices
	"database",           // Deprecated in favor of dedicated DB modules or external management
	"concat::fragment",   // Replaced by native concat resource in Puppet 4+
	"filebucket",         // Deprecated in favor of external backup/version control
	"nagios_service",     // Deprecated, replaced by newer monitoring modules
	"package",            // Some providers (like gem) are deprecated, prefer specific package types
	"resources",          // Deprecated meta-type, avoid using
	"vcsrepo",            // Deprecated in some contexts, replaced by 'git' or other SCM modules
	"apache::vhost",      // Deprecated in favor of official Apache modules or newer Puppet Forge modules
	"mysql::db",          // Deprecated, use official MySQL module or external DB management
	"ssh_authorized_key", // Some parameters deprecated; check current docs
}

// List of known unmanaged or disallowed parameters
var disallowedParams = []string{
	"force_destroy",       // Dangerous: might delete resources unexpectedly
	"skip_final_snapshot", // Can lead to data loss if true
	"public_ip",           // Assigning public IP may be disallowed in secure environments
	"allow_remote_access", // Often disallowed due to security risks
	"password",            // Hardcoded passwords should be disallowed
	"secret_key",          // Sensitive keys should never be hardcoded
	"access_key",          // AWS access keys hardcoded in resources
	"enable_http_access",  // Disallowed if enabling insecure protocols
	"insecure_ssl",        // Disallowed to prevent insecure SSL configurations
	"admin_password",      // Hardcoded admin passwords are disallowed
}

// Regex for detecting class declarations
var classDeclRegex = regexp.MustCompile(`(?m)^\s*class\s+[\w:]+`)

// Regex for common hardcoded secrets (password-like)
var hardcodedSecretRegex = regexp.MustCompile(`(?i)password\s*=>\s*["'].*["']`)

// Check for trailing whitespace (space or tab)
var trailingWhitespaceRegex = regexp.MustCompile(`\s+$`)

// Scan scans Puppet manifests and returns findings.
func Scan(path string) ([]finding.Finding, error) {
	var findings []finding.Finding

	err := filepath.Walk(path, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		if filepath.Ext(p) != ".pp" {
			return nil
		}

		// 1. Run puppet-lint
		puppetLintFindings, err := runPuppetLint(p)
		if err != nil {
			findings = append(findings, finding.Finding{
				File:     p,
				Severity: finding.Error,
				Message:  fmt.Sprintf("puppet-lint error: %v", err),
			})
		}
		findings = append(findings, puppetLintFindings...)

		// 2. Read file content for static checks
		contentBytes, err := os.ReadFile(p)
		if err != nil {
			findings = append(findings, finding.Finding{
				File:     p,
				Severity: finding.Error,
				Message:  fmt.Sprintf("failed to read file: %v", err),
			})
			return nil
		}
		content := string(contentBytes)

		// 3. Deprecated resource checks
		for _, dr := range deprecatedResources {
			if strings.Contains(content, dr) {
				findings = append(findings, finding.Finding{
					File:     p,
					Severity: finding.Warning,
					Message:  fmt.Sprintf("Deprecated resource type '%s' used", dr),
				})
			}
		}

		// 4. Missing class declaration
		if !classDeclRegex.MatchString(content) {
			findings = append(findings, finding.Finding{
				File:     p,
				Severity: finding.Warning,
				Message:  "No class declaration found in manifest",
			})
		}

		// 5. Hardcoded secrets detection
		if loc := hardcodedSecretRegex.FindStringIndex(content); loc != nil {
			findings = append(findings, finding.Finding{
				File:     p,
				Severity: finding.Error,
				Message:  "Possible hardcoded password detected",
			})
		}

		// 6. Trailing whitespace
		lines := strings.Split(content, "\n")
		for i, line := range lines {
			if trailingWhitespaceRegex.MatchString(line) {
				findings = append(findings, finding.Finding{
					File:     p,
					Severity: finding.Warning,
					Message:  fmt.Sprintf("Trailing whitespace on line %d", i+1),
				})
			}
		}

		// 7. Disallowed parameters
		for _, param := range disallowedParams {
			if strings.Contains(content, param) {
				findings = append(findings, finding.Finding{
					File:     p,
					Severity: finding.Warning,
					Message:  fmt.Sprintf("Disallowed parameter '%s' used", param),
				})
			}
		}

		return nil
	})

	return findings, err
}

// runPuppetLint runs puppet-lint and parses the output
func runPuppetLint(filePath string) ([]finding.Finding, error) {
	var findings []finding.Finding

	cmd := exec.Command("puppet-lint", filePath)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil && stdout.Len() == 0 {
		return findings, fmt.Errorf("%s", strings.TrimSpace(stderr.String()))
	}

	scanner := bufio.NewScanner(&stdout)
	for scanner.Scan() {
		line := scanner.Text()
		findings = append(findings, finding.Finding{
			File:     filePath,
			Severity: finding.Warning,
			Message:  line,
		})
	}
	if scanErr := scanner.Err(); scanErr != nil {
		return findings, fmt.Errorf("error parsing puppet-lint output: %v", scanErr)
	}

	return findings, nil
}
