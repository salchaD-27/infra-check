package ansible

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/salchaD-27/infra-check/internal/finding"
)

type Task map[string]interface{}

type Play struct {
	Hosts interface{}            `yaml:"hosts"` // required field check
	Tasks []Task                 `yaml:"tasks"`
	Vars  map[string]interface{} `yaml:"vars,omitempty"` // Add this field
}

// FindingSeverity types
type Severity string

const (
	Info    Severity = "INFO"
	Warning Severity = "WARN"
	Error   Severity = "ERROR"
)

// Finding struct to represent analysis results
type Finding struct {
	File     string
	Severity Severity
	Message  string
}

var deprecatedModules = map[string]string{
	"raw":       "The 'raw' module is deprecated; consider using 'command' or other modules.",
	"command":   "The 'command' module is sometimes discouraged in favor of more specific modules.",
	"shell":     "The 'shell' module can be risky and is discouraged for idempotency reasons.",
	"ec2":       "The 'ec2' module is deprecated; use 'amazon.aws.ec2_instance' from the Amazon AWS Collection instead.",
	"docker":    "The 'docker' module is deprecated; use 'community.docker.docker_container' instead.",
	"git":       "Older 'git' module versions might be deprecated; ensure you use the latest from 'community.general.git'.",
	"service":   "The 'service' module is discouraged in favor of OS-specific modules like 'systemd' or 'service_facts'.",
	"yum":       "The 'yum' module is discouraged for newer systems; use 'dnf' module on Fedora/RHEL 8+.",
	"apt":       "The 'apt' module should be replaced with 'apt_key' and 'apt_repository' for finer control where applicable.",
	"setup":     "Some facts gathered by 'setup' module may be deprecated; use 'ansible_facts' with targeted filters.",
	"iptables":  "Deprecated in favor of 'community.general.iptables' or 'ufw' modules depending on your firewall system.",
	"firewalld": "Legacy 'firewalld' module replaced by 'community.general.firewalld'.",
	"user":      "Deprecated options in 'user' module replaced with improved parameters in latest versions.",
}

// Keywords to detect hardcoded secrets in variables or task fields
var secretKeywords = []string{"password", "secret", "token", "key", "pwd"}

// Helper to check if a string contains any sensitive keyword
func containsSecretKeyword(s string) bool {
	s = strings.ToLower(s)
	for _, kw := range secretKeywords {
		if strings.Contains(s, kw) {
			return true
		}
	}
	return false
}

// Scans for Ansible playbooks (*.yml or *.yaml files) recursively in the given path.
// Parses each YAML file into a slice of Play structures, where each Play contains a list of Tasks.

// Iterates over each task in each play and checks the presence and value of the 'become' field:
// If the become field is missing:
// Reports a Warning finding stating:
// "Task missing 'become' field (no privilege escalation specified)"
// If the become field is present but set to false:
// Reports a Warning finding stating:
// "'become' is false in task (possible privilege issue)"

func Scan(path string) ([]finding.Finding, error) {
	var findings []finding.Finding

	err := filepath.Walk(path, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}

		ext := filepath.Ext(p)
		if ext != ".yml" && ext != ".yaml" {
			return nil
		}

		data, err := ioutil.ReadFile(p)
		if err != nil {
			findings = append(findings, finding.Finding{
				File:     p,
				Severity: finding.Error,
				Message:  fmt.Sprintf("Failed to read file: %v", err),
			})
			return nil
		}

		var plays []Play
		if err := yaml.Unmarshal(data, &plays); err != nil {
			findings = append(findings, finding.Finding{
				File:     p,
				Severity: finding.Error,
				Message:  fmt.Sprintf("YAML parse error: %v", err),
			})
			return nil
		}

		// Track variables defined and used to detect unused ones
		definedVars := make(map[string]bool)
		usedVars := make(map[string]bool)

		for _, play := range plays {
			// Check required field 'hosts'
			if play.Hosts == nil {
				findings = append(findings, finding.Finding{
					File:     p,
					Severity: finding.Warning,
					Message:  "Play missing required field 'hosts'",
				})
			}

			// Track defined variables in play vars
			for varName := range play.Vars {
				definedVars[varName] = true
			}

			for _, task := range play.Tasks {
				// Check missing or false 'become'
				become, exists := task["become"]
				if !exists {
					findings = append(findings, finding.Finding{
						File:     p,
						Severity: finding.Warning,
						Message:  "Task missing 'become' field (no privilege escalation specified)",
					})
				} else if val, ok := become.(bool); ok && !val {
					findings = append(findings, finding.Finding{
						File:     p,
						Severity: finding.Warning,
						Message:  "'become' is false in task (possible privilege issue)",
					})
				}

				// Required task field 'name'
				if _, ok := task["name"]; !ok {
					findings = append(findings, finding.Finding{
						File:     p,
						Severity: finding.Warning,
						Message:  "Task missing required field 'name'",
					})
				}

				// Check for deprecated module usage (task keys except known keys)
				for key := range task {
					if key != "name" && key != "become" && key != "vars" {
						if msg, deprecated := deprecatedModules[key]; deprecated {
							findings = append(findings, finding.Finding{
								File:     p,
								Severity: finding.Warning,
								Message:  fmt.Sprintf("Use of deprecated module '%s': %s", key, msg),
							})
						}
					}
				}

				// Detect hardcoded secrets in task attributes
				for attr, val := range task {
					attrLower := strings.ToLower(attr)
					if containsSecretKeyword(attrLower) {
						if strVal, ok := val.(string); ok && strings.TrimSpace(strVal) != "" {
							findings = append(findings, finding.Finding{
								File:     p,
								Severity: finding.Error,
								Message:  fmt.Sprintf("Possible hardcoded secret in attribute '%s'", attr),
							})
						}
					}

					// Detect usage of variables in string templates "{{ var }}"
					if strVal, ok := val.(string); ok {
						if strings.Contains(strVal, "{{") && strings.Contains(strVal, "}}") {
							// Simple extraction of variables inside {{ }}
							parts := strings.Split(strVal, "{{")
							for _, part := range parts[1:] {
								varName := strings.TrimSpace(strings.Split(part, "}}")[0])
								if len(varName) > 0 {
									usedVars[varName] = true
								}
							}
						}
					}
				}
			}
		}

		// Detect unused variables
		for varName := range definedVars {
			if !usedVars[varName] {
				findings = append(findings, finding.Finding{
					File:     p,
					Severity: finding.Warning,
					Message:  fmt.Sprintf("Variable '%s' defined but not used", varName),
				})
			}
		}

		return nil
	})

	return findings, err
}
