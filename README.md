# kubebaseline

**Define, measure, improve your Kubernetes baseline**

`kbase` is a CLI tool that produces comprehensive reports regarding adherence to Kubernetes best practices, using the kubeconfig set in your local terminal.

## Features

- 🔍 **Comprehensive Auditing**: Checks 20+ categories of Kubernetes best practices
- 📊 **Detailed Reports**: Generates markdown reports with actionable recommendations
- 🚨 **Risk Assessment**: Identifies critical security and compliance issues
- ⚡ **Fast & Efficient**: Scans clusters quickly with minimal overhead
- 🔧 **Flexible Configuration**: Exclude namespaces, choose output formats

## Installation

### From Source

```bash
# Clone the repository
git clone <repository-url>
cd kubebaseline

# Install dependencies
pip install -r requirements.txt

# Install the package
pip install -e .

# Or install directly with pip
pip install .
```

### Development Installation

```bash
# Install with development dependencies
pip install -e ".[dev]"
```

## Quick Start

### Basic Usage

```bash
# Generate a compliance report (outputs to stdout)
kbase report

# Save report to file
kbase report --output report.md

# Use a specific kubeconfig and context
kbase report --kubeconfig ~/.kube/config --context my-cluster

# Exclude specific namespaces
kbase report --exclude-namespaces kube-system,monitoring
```

### Command Options

```bash
kbase report [OPTIONS]

Options:
  --kubeconfig PATH        Path to kubeconfig file (defaults to ~/.kube/config)
  --context TEXT           Kubernetes context to use
  --exclude-namespaces TEXT  Comma-separated list of namespaces to exclude
  --output, -o PATH        Output file path (default: stdout)
  --format [markdown|json] Output format (default: markdown)
  --verbose, -v            Enable verbose output
  --help                   Show this message and exit
```

## Best Practices Covered

The tool audits your cluster against best practices in the following categories:

1. **Security Best Practices**
   - Pod Security Standards
   - Privileged containers
   - Root users
   - Security context
   - Capabilities
   - Host namespace sharing

2. **Resource Management**
   - CPU and memory requests
   - CPU and memory limits
   - Resource ratios

3. **Pod Configuration**
   - Required labels
   - Health checks

4. **Network Security**
   - Network policies

5. **RBAC & Access Control**
   - Service accounts

Additional checks can be added by extending the check modules.

## Report Structure

The generated report includes:

- **Executive Summary**: High-level compliance overview
- **Cluster Information**: Cluster metadata and resource counts
- **Overall Compliance Score**: Visual compliance metrics
- **Compliance by Category**: Breakdown by best practice category
- **Critical Findings**: Detailed analysis of critical issues
- **Findings by Category**: Comprehensive findings organized by category
- **Recommendations**: Prioritized, actionable recommendations
- **Appendix**: Technical details and references

See [REPORT_STRUCTURE.md](REPORT_STRUCTURE.md) for complete report structure documentation.

## Examples

### Example 1: Basic Report

```bash
$ kbase report

🔍 Connecting to Kubernetes cluster...
✅ Connected to cluster (Kubernetes v1.28.3)

🔬 Running compliance checks...
📊 Generating report...

================================================================================
# Kubernetes Best Practices Compliance Report
...
```

### Example 2: Save to File

```bash
$ kbase report --output compliance-report-$(date +%Y%m%d).md

✅ Report saved to: compliance-report-20240201.md
```

### Example 3: JSON Output

```bash
$ kbase report --format json --output report.json

✅ Report saved to: report.json
```

### Example 4: Exclude Namespaces

```bash
$ kbase report --exclude-namespaces kube-system,kube-public,monitoring
```

## Exit Codes

- `0`: Success (no critical issues, warnings may exist)
- `1`: Failure (critical issues found or error occurred)

## Configuration

### Default Excluded Namespaces

The following namespaces are excluded by default:
- `kube-system`
- `kube-public`
- `kube-node-lease`

Additional namespaces can be excluded using the `--exclude-namespaces` flag.

## Troubleshooting

### Permission Issues

The tool requires read access to Kubernetes API resources. Ensure your kubeconfig has appropriate permissions:

```bash
# Test connectivity
kubectl get pods --all-namespaces
```

### Connection Errors

If you encounter connection errors:

1. Verify your kubeconfig is set correctly:
   ```bash
   kubectl config current-context
   ```

2. Check cluster connectivity:
   ```bash
   kubectl cluster-info
   ```

3. Use verbose mode for debugging:
   ```bash
   kbase report --verbose
   ```

## Contributing

Contributions are welcome! Areas for improvement:

- Additional best practice checks
- More output formats (HTML, PDF)
- Historical comparison and trending
- Integration with CI/CD pipelines
- Policy-as-code integration (OPA, Kyverno)

## Related Documentation

- [KUBERNETES_BEST_PRACTICES.md](KUBERNETES_BEST_PRACTICES.md) - Complete list of best practices
- [REPORT_STRUCTURE.md](REPORT_STRUCTURE.md) - Report structure documentation

## License

Apache License 2.0 - see [LICENSE](LICENSE) file for details.

## Acknowledgments

Inspired by:
- [CIS Kubernetes Benchmark](https://www.cisecurity.org/benchmark/kubernetes)
- [Kubernetes Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [CNCF Best Practices](https://www.cncf.io/)
