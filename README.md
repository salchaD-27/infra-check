# InfraCheck

InfraCheck is a security and best practice scanner for Infrastructure as Code (IaC) tools including **Terraform**, **Ansible**, and **Puppet**. It helps detect common misconfigurations, hardcoded secrets, deprecated usage, missing tags, privilege escalation issues, and more to improve your IaC code quality and security posture.

---

## Features

### Terraform scans
- Detect publicly readable S3 buckets
- Find hardcoded secrets in variables and resource attributes
- Flag deprecated resource types usage
- Check for missing required tags on resources
- Heuristically detect unused variables

### Ansible scans
- Identify tasks missing or disabling privilege escalation (`become`)
- Detect deprecated module usage
- Find hardcoded secrets in tasks
- Check for missing required fields like `name` and `hosts`
- Detect unused variables

### Puppet scans
- Integrate `puppet-lint` warnings and errors
- Detect deprecated resource types and disallowed parameters
- Check for missing class declarations
- Find hardcoded credentials
- Detect trailing whitespace and other style issues

### Reporting
- Outputs in human-friendly **Markdown**, machine-readable **JSON**, and **GitHub Actions** annotation formats for inline pull request feedback
- Supports integration with popular CI/CD systems like GitHub Actions, Jenkins, and Tekton

---
## Installation

Make sure you have Go installed (version 1.20 or higher recommended).

```bash
git clone https://github.com/salchaD-27/infra-check.git
cd infra-check
go build -o infra-check ./cmd/main.go

```
## Usage
InfraCheck provides a root command `scan` with subcommands for each IaC tool.

```
infra-check scan [terraform|ansible|puppet] <path> [flags]


`<path>`: Directory containing your IaC files to scan.
```
---

### Scan Terraform

```

infra-check scan terraform ./terraform --format markdown

```

Scan Terraform files and output findings. Supported formats:

- `text` (default)
- `json`
- `markdown`
- `gha` (GitHub Actions annotations)

---

### Scan Ansible

```

infra-check scan ansible ./ansible-playbooks --format json

```

Scan Ansible playbooks (`.yml` or `.yaml`) checking privilege escalation, deprecated modules, secrets, task correctness, and more.

---

### Scan Puppet

```

infra-check scan puppet ./puppet-manifests --format gha

```

Scan Puppet manifests (`.pp`), including integration with `puppet-lint` and custom static checks.

---

## Flags

| Flag           | Description                                      | Default |
|----------------|------------------------------------------------|---------|
| `--format`, `-f` | Output format: `text`, `json`, `markdown`, `gha` | `text`  |
| `--fail-on`    | Minimum severity to cause process failure: `info`, `warn`, `error` | `error` |

---

### Example: Fail-on flag usage

```

infra-check scan terraform ./terraform --fail-on warn

```

This causes InfraCheck to exit with failure if any warnings or errors are found, ideal for enforcing quality gates in CI pipelines.

---

## Integration with CI/CD

### GitHub Actions

Use the example workflow in `.github/workflows/infra-check.yml`:

- Checks out your code
- Builds the InfraCheck CLI
- Runs scans with `--format gha` to enable inline PR annotations


---

## Appendix: Sample Commands

```


# Default plain text output
infra-check scan terraform ./terraform

# Markdown formatted report
infra-check scan ansible ./ansible --format markdown

# JSON output for tool integrations
infra-check scan puppet ./puppet --format json

# GitHub Actions annotation output (ideal for CI)
infra-check scan terraform ./terraform --format gha

```

