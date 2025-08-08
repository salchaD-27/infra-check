package terraform

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclparse"
	"github.com/zclconf/go-cty/cty"

	"github.com/salchaD-27/infra-check/internal/finding"
)

func looksLikeSecret(varName, value string) bool {
	// Simple heuristic — improve as needed
	sensitiveKeywords := []string{"password", "secret", "token", "key"}
	for _, keyword := range sensitiveKeywords {
		if strings.Contains(strings.ToLower(varName), keyword) || strings.Contains(strings.ToLower(value), keyword) {
			return true
		}
	}
	return false
}

func isSensitiveKeyword(name string) bool {
	sensitive := []string{"password", "secret", "token", "key", "access"}
	for _, s := range sensitive {
		if strings.Contains(name, s) {
			return true
		}
	}
	return false
}

var deprecatedResources = map[string]string{
	"aws_db_instance":                   "This resource is deprecated, use aws_rds_instance instead.",
	"aws_elb":                           "This resource is deprecated, use aws_lb instead.",
	"aws_elasticsearch_domain":          "This resource is deprecated, use aws_opensearch_domain instead.",
	"aws_iam_policy_attachment":         "This resource is deprecated, use aws_iam_role_policy_attachment or aws_iam_user_policy_attachment instead.",
	"aws_launch_configuration":          "This resource is deprecated, use aws_autoscaling_group with launch template instead.",
	"aws_acm_certificate_validation":    "Deprecated in favor of aws_acm_certificate with validation blocks.",
	"aws_cloudwatch_event_rule":         "This resource is deprecated, use aws_cloudwatch_event_rule (newer schema) or aws_eventbridge_rule.",
	"aws_route53_record":                "Use caution, certain types or configurations may be deprecated; check latest provider docs.",
	"aws_sns_topic_subscription":        "Deprecated in favor of aws_sns_subscription.",
	"aws_spot_instance_request":         "This resource is deprecated, use aws_spot_fleet_request or aws_ec2_spot_fleet instead.",
	"aws_elastic_beanstalk_environment": "Check if using legacy configs; aws_elastic_beanstalk_environment is still supported but monitor provider updates.",
	"aws_iam_group_policy_attachment":   "Deprecated, prefer aws_iam_group_policy.",
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

// func Scan(path string) error {
// 	return filepath.Walk(path, func(p string, info os.FileInfo, err error) error {
// 		if err != nil {
// 			return err
// 		}
// 		if filepath.Ext(p) == ".tf" {
// 			fmt.Println("Found Terraform file:", p)
// 			// TODO: Parse and analyze file content here
// 		}
// 		return nil
// 	})
// }

// Parse .tf files using the official HCL parser (github.com/hashicorp/hcl/v2), extract resource blocks and variables, and perform simple checks such as detecting public S3 buckets.
// Key Steps:
// Use the HCL parser to parse Terraform files into an abstract syntax tree (AST).
// Traverse the AST to find and extract relevant blocks (resource, variable, etc.).
// Analyze resource blocks for specific attributes (e.g., an aws_s3_bucket resource with acl = "public-read").

// Scan parses Terraform files under the path and runs checks such as:
// - Publicly readable S3 buckets (acl = "public-read")
// - Hardcoded secrets in variables and resource attributes
// - Missing required tags on resources
// - Deprecated resource types warning
func Scan(path string) ([]finding.Finding, error) {
	parser := hclparse.NewParser()
	var findings []finding.Finding
	// Keywords for detecting secrets in variable/resource attribute names
	secretKeywords := []string{"password", "secret", "token", "key", "pwd"}
	// Required tags on resources to check
	requiredTags := []string{"Environment", "Owner", "Project"}

	err := filepath.Walk(path, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		if filepath.Ext(p) != ".tf" {
			return nil
		}

		file, diag := parser.ParseHCLFile(p)
		if diag.HasErrors() {
			findings = append(findings, finding.Finding{
				File:     p,
				Severity: finding.Error,
				Message:  fmt.Sprintf("Failed to parse HCL file: %s", diag.Error()),
			})
			return nil
		}

		content, _, diag := file.Body.PartialContent(&hcl.BodySchema{
			Blocks: []hcl.BlockHeaderSchema{
				{Type: "resource"},
				{Type: "variable"},
			},
		})
		if diag.HasErrors() {
			findings = append(findings, finding.Finding{
				File:     p,
				Severity: finding.Error,
				Message:  fmt.Sprintf("Failed to parse blocks: %s", diag.Error()),
			})
			return nil
		}

		// Track declared and used variables for unused variable detection
		var declaredVars = make(map[string]bool)
		// var usedVars = make(map[string]bool)

		for _, block := range content.Blocks {
			switch block.Type {
			case "resource":
				if len(block.Labels) != 2 {
					continue // invalid resource block, skip
				}
				resourceType := block.Labels[0]
				resourceName := block.Labels[1]
				_ = resourceName

				// Check deprecated resource type
				if msg, deprecated := deprecatedResources[resourceType]; deprecated {
					findings = append(findings, finding.Finding{
						File:     p,
						Severity: finding.Warning,
						Message:  fmt.Sprintf("Resource type '%s' is deprecated: %s", resourceType, msg),
					})
				}

				attrs, diags := block.Body.JustAttributes()
				if diags.HasErrors() {
					continue
				}

				// Check for public-read S3 bucket ACL
				if resourceType == "aws_s3_bucket" {
					if aclAttr, exists := attrs["acl"]; exists {
						val, diag := aclAttr.Expr.Value(nil)
						if diag.HasErrors() {
							continue
						}
						if val.Type() == cty.String && val.AsString() == "public-read" {
							findings = append(findings, finding.Finding{
								File:     p,
								Severity: finding.Warning,
								Message:  "S3 bucket ACL is set to public-read (publicly readable)",
							})
						}
					}
				}

				// Check for missing required tags on resource
				if tagsAttr, exists := attrs["tags"]; exists {
					val, diag := tagsAttr.Expr.Value(nil)
					if diag.HasErrors() || !val.Type().IsObjectType() {
						continue
					}
					tagsMap := val.AsValueMap()
					for _, tag := range requiredTags {
						if _, ok := tagsMap[tag]; !ok {
							findings = append(findings, finding.Finding{
								File:     p,
								Severity: finding.Warning,
								Message:  fmt.Sprintf("Resource missing required tag '%s'", tag),
							})
						}
					}
				} else {
					findings = append(findings, finding.Finding{
						File:     p,
						Severity: finding.Warning,
						Message:  "Resource missing 'tags' attribute entirely",
					})
				}

				// Check resource attributes for hardcoded secrets
				for attrName, attr := range attrs {
					lowerName := strings.ToLower(attrName)
					for _, kw := range secretKeywords {
						if strings.Contains(lowerName, kw) {
							val, diag := attr.Expr.Value(nil)
							if diag.HasErrors() || val.IsNull() {
								continue
							}
							if val.Type() == cty.String && val.AsString() != "" {
								findings = append(findings, finding.Finding{
									File:     p,
									Severity: finding.Error,
									Message:  fmt.Sprintf("Resource attribute '%s' may contain hardcoded secret", attrName),
								})
							}
							break
						}
					}
				}

			case "variable":
				if len(block.Labels) != 1 {
					continue // invalid variable block
				}
				varName := block.Labels[0]
				declaredVars[varName] = true

				attrs, diags := block.Body.JustAttributes()
				if diags.HasErrors() {
					continue
				}
				if defaultAttr, exists := attrs["default"]; exists {
					val, diag := defaultAttr.Expr.Value(nil)
					if diag.HasErrors() || val.IsNull() {
						continue
					}
					if val.Type() == cty.String {
						strVal := val.AsString()
						lowerName := strings.ToLower(varName)
						for _, kw := range secretKeywords {
							if strings.Contains(lowerName, kw) && strVal != "" {
								findings = append(findings, finding.Finding{
									File:     p,
									Severity: finding.Error,
									Message:  fmt.Sprintf("Variable '%s' has a hardcoded default secret", varName),
								})
								break
							}
						}
					}
				}
			}
		}

		return nil
	})

	return findings, err
}
