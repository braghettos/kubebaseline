"""Report generator for markdown output."""

from typing import List, Optional
from kbase.models import ScanResult, Finding, Severity, CategoryResult
from kbase.client import KubernetesClient


class ReportGenerator:
    """Generates markdown compliance reports."""

    def __init__(self, result: ScanResult, client: KubernetesClient):
        """Initialize report generator.
        
        Args:
            result: Scan result to generate report from
            client: Kubernetes client for resource queries
        """
        self.result = result
        self.client = client

    def generate(self) -> str:
        """Generate markdown report."""
        lines = []
        
        lines.extend(self._generate_header())
        lines.extend(self._generate_executive_summary())
        lines.extend(self._generate_cluster_info())
        lines.extend(self._generate_compliance_score())
        lines.extend(self._generate_compliance_by_category())
        lines.extend(self._generate_critical_findings())
        lines.extend(self._generate_findings_by_category())
        lines.extend(self._generate_recommendations())
        lines.extend(self._generate_appendix())
        
        return "\n".join(lines)

    def _generate_header(self) -> List[str]:
        """Generate report header."""
        return [
            "# Kubernetes Best Practices Compliance Report",
            "",
            f"**Generated**: {self.result.scan_date.strftime('%Y-%m-%d %H:%M:%S UTC')}",
            f"**Scan Duration**: {self.result.scan_duration:.2f} seconds",
            "",
            "---",
            "",
        ]

    def _generate_executive_summary(self) -> List[str]:
        """Generate executive summary section."""
        critical_count = self.result.total_critical
        warning_count = self.result.total_warnings
        passed_count = self.result.total_passed
        total_count = self.result.total_resources
        
        compliance_pct = self.result.overall_compliance
        
        # Determine risk level
        if critical_count > 50 or compliance_pct < 60:
            risk_level = "High"
            risk_emoji = "🔴"
        elif critical_count > 20 or compliance_pct < 75:
            risk_level = "Medium"
            risk_emoji = "⚠️"
        else:
            risk_level = "Low"
            risk_emoji = "✅"
        
        critical_findings = self.result.get_critical_findings()
        top_findings = critical_findings[:5]  # Top 5 critical findings
        
        lines = [
            "## Executive Summary",
            "",
            "### Compliance Overview",
            f"- **Overall Compliance Score**: {compliance_pct:.1f}%",
            f"- **Total Resources Audited**: {total_count}",
            f"- **Critical Issues Found**: {critical_count}",
            f"- **Warning Issues Found**: {warning_count}",
            f"- **Passing Checks**: {passed_count}",
            "",
            "### Risk Assessment",
            f"- **Security Risk Level**: {risk_level} {risk_emoji}",
            f"- **Overall Risk Level**: {risk_level} {risk_emoji}",
            "",
            "### Key Findings",
        ]
        
        # Group critical findings by category
        by_category = {}
        for finding in critical_findings[:10]:
            cat = finding.category
            if cat not in by_category:
                by_category[cat] = []
            by_category[cat].append(finding)
        
        for category, findings in list(by_category.items())[:5]:
            count = len(findings)
            lines.append(f"- {count} critical issue(s) in {category}")
        
        lines.append("")
        lines.append("### Priority Actions Required")
        
        # Get unique critical findings by check
        seen_checks = set()
        action_num = 1
        for finding in critical_findings[:5]:
            if finding.check_id not in seen_checks:
                seen_checks.add(finding.check_id)
                lines.append(
                    f"{action_num}. **[CRITICAL]** {finding.check_name}: {finding.message[:100]}..."
                )
                action_num += 1
        
        lines.extend(["", "---", ""])
        return lines

    def _generate_cluster_info(self) -> List[str]:
        """Generate cluster information section."""
        info = self.result.cluster_info
        nodes = info.get("nodes", [])
        
        lines = [
            "## Cluster Information",
            "",
            "### Cluster Metadata",
            f"- **Kubernetes Version**: {info.get('version', 'unknown')}",
            f"- **Node Count**: {info.get('node_count', 0)}",
            "",
        ]
        
        # Count resources
        pods = self.client.list_pods()
        namespaces = self.client.list_namespaces()
        deployments = self.client.list_deployments()
        services = self.client.list_services()
        
        app_namespaces = [ns for ns in namespaces if not ns.metadata.name.startswith("kube-")]
        
        lines.extend([
            "### Cluster Resources",
            f"- **Namespaces**: {len(namespaces)}",
            f"  - System: {len(namespaces) - len(app_namespaces)}",
            f"  - Application: {len(app_namespaces)}",
            f"- **Total Pods**: {len(pods)}",
            f"- **Total Deployments**: {len(deployments)}",
            f"- **Total Services**: {len(services)}",
            "",
        ])
        
        if nodes:
            lines.extend([
                "### Node Information",
                "| Node Name | Kubelet Version | OS | CPU Capacity | Memory Capacity |",
                "|-----------|-----------------|----|--------------|-----------------|",
            ])
            for node in nodes[:10]:  # Limit to 10 nodes
                name = node.get("name", "unknown")
                kubelet = node.get("kubelet_version", "unknown")
                os = node.get("os", "unknown")
                cpu = node.get("cpu_capacity", "0")
                mem = node.get("memory_capacity", "0")
                lines.append(f"| {name} | {kubelet} | {os} | {cpu} | {mem} |")
            
            if len(nodes) > 10:
                lines.append(f"| ... ({len(nodes) - 10} more) | ... | ... | ... | ... |")
            
            lines.append("")
        
        lines.extend(["---", ""])
        return lines

    def _generate_compliance_score(self) -> List[str]:
        """Generate compliance score section."""
        compliance_pct = self.result.overall_compliance
        critical_count = self.result.total_critical
        warning_count = self.result.total_warnings
        passed_count = self.result.total_passed
        total_count = self.result.total_resources
        
        # Create progress bar
        bars_passed = int(compliance_pct / 5)
        bars_remaining = 20 - bars_passed
        progress_bar = "█" * bars_passed + "░" * bars_remaining
        
        lines = [
            "## Overall Compliance Score",
            "",
            "### Score Breakdown",
            "",
            f"Compliance Score: {compliance_pct:.1f}% {progress_bar}",
            "",
            "By Severity:",
        ]
        
        if total_count > 0:
            passed_pct = (passed_count / total_count) * 100
            warning_pct = (warning_count / total_count) * 100
            critical_pct = (critical_count / total_count) * 100
            
            lines.extend([
                f"  ✓ Pass:    {passed_count} checks ({passed_pct:.1f}%)",
                f"  ⚠ Warning: {warning_count} checks ({warning_pct:.1f}%)",
                f"  ✗ Critical: {critical_count} checks ({critical_pct:.1f}%)",
            ])
        
        lines.extend(["", "---", ""])
        return lines

    def _generate_compliance_by_category(self) -> List[str]:
        """Generate compliance by category table."""
        lines = [
            "## Compliance by Category",
            "",
            "| Category | Compliance | Critical | Warning | Pass | Total | Status |",
            "|----------|------------|----------|---------|------|-------|--------|",
        ]
        
        for cat_result in self.result.categories:
            compliance = cat_result.compliance_percentage
            status = self._get_status_emoji(compliance)
            
            lines.append(
                f"| {cat_result.category} | {compliance:.0f}% | "
                f"{cat_result.total_critical} | {cat_result.total_warnings} | "
                f"{cat_result.total_passed} | {cat_result.total_resources} | {status} |"
            )
        
        lines.extend(["", "---", ""])
        return lines

    def _generate_critical_findings(self) -> List[str]:
        """Generate critical findings section."""
        critical_findings = self.result.get_critical_findings()
        
        lines = [
            "## Critical Findings",
            "",
            "### Severity Definitions",
            "- **CRITICAL**: Security vulnerabilities, compliance violations, or issues that pose immediate risk",
            "- **WARNING**: Best practice violations that should be addressed but don't pose immediate risk",
            "- **INFO**: Informational findings or recommendations for improvement",
            "",
        ]
        
        if not critical_findings:
            lines.extend([
                "### No Critical Findings",
                "",
                "✅ All checks passed! No critical issues found.",
                "",
            ])
        else:
            # Group by check
            by_check = {}
            for finding in critical_findings[:20]:  # Top 20
                key = finding.check_id
                if key not in by_check:
                    by_check[key] = []
                by_check[key].append(finding)
            
            lines.append("### Top Critical Issues")
            lines.append("")
            
            issue_num = 1
            for check_id, findings in list(by_check.items())[:10]:
                first = findings[0]
                lines.extend([
                    f"#### {issue_num}. [CRITICAL] {first.check_name}",
                    f"**Category**: {first.category}",
                    f"**Severity**: CRITICAL",
                    f"**Affected Resources**: {len(findings)} resource(s)",
                    f"**Impact**: {first.message[:200]}",
                    "",
                    "**Affected Resources**:",
                ])
                
                for finding in findings[:10]:  # Show first 10
                    ns = finding.resource_namespace or "default"
                    lines.append(f"- `{ns}/{finding.resource_name}`")
                
                if len(findings) > 10:
                    lines.append(f"- ... ({len(findings) - 10} more)")
                
                if first.recommendation:
                    lines.append("")
                    lines.append(f"**Recommendation**: {first.recommendation}")
                
                if first.remediation:
                    lines.append("")
                    lines.append(f"**Remediation**: {first.remediation}")
                
                lines.extend(["", "---", ""])
                issue_num += 1
        
        return lines

    def _generate_findings_by_category(self) -> List[str]:
        """Generate detailed findings by category."""
        lines = [
            "## Findings by Category",
            "",
        ]
        
        for cat_result in self.result.categories:
            compliance = cat_result.compliance_percentage
            status = self._get_status_emoji(compliance)
            
            lines.extend([
                f"### {cat_result.category}",
                "",
                f"**Overall Compliance**: {compliance:.1f}% ({cat_result.total_passed}/{cat_result.total_resources} checks passed)",
                "",
            ])
            
            # Group findings by check
            by_check = {}
            for check_result in cat_result.checks:
                by_check[check_result.check_id] = check_result
            
            for check_id, check_result in by_check.items():
                if not check_result.findings:
                    continue
                
                severity_icon = "❌" if any(f.severity == Severity.CRITICAL for f in check_result.findings) else "⚠️"
                
                lines.extend([
                    f"#### {check_result.check_name}",
                    f"**Status**: {severity_icon} {len(check_result.findings)} issue(s) found",
                    f"**Compliance**: {check_result.compliance_percentage:.1f}% ({check_result.passed_count}/{check_result.resource_count})",
                    "",
                ])
                
                # Show sample findings
                for finding in check_result.findings[:5]:
                    ns = finding.resource_namespace or "default"
                    lines.append(f"- **{finding.severity.value.upper()}**: `{ns}/{finding.resource_name}` - {finding.message}")
                
                if len(check_result.findings) > 5:
                    lines.append(f"- ... ({len(check_result.findings) - 5} more)")
                
                lines.append("")
            
            lines.extend(["---", ""])
        
        return lines

    def _generate_recommendations(self) -> List[str]:
        """Generate recommendations section."""
        critical_findings = self.result.get_critical_findings()
        warning_findings = self.result.get_warning_findings()
        
        lines = [
            "## Recommendations",
            "",
        ]
        
        # Priority 1: Critical
        if critical_findings:
            lines.extend([
                "### Priority 1: Critical Security Issues (Fix within 1 week)",
                "",
            ])
            
            by_check = {}
            for finding in critical_findings[:10]:
                if finding.check_id not in by_check:
                    by_check[finding.check_id] = finding
            
            for i, (check_id, finding) in enumerate(list(by_check.items())[:5], 1):
                count = len([f for f in critical_findings if f.check_id == check_id])
                lines.extend([
                    f"#### {i}. {finding.check_name}",
                    f"**Priority**: P1 - Critical",
                    f"**Effort**: Medium",
                    f"**Impact**: High",
                    f"**Category**: {finding.category}",
                    "",
                    f"**Action Items**:",
                    f"1. Fix {count} affected resource(s)",
                    f"2. {finding.recommendation or 'Review and remediate issues'}",
                    "",
                    f"**Remediation**: {finding.remediation or 'See category details above'}",
                    "",
                ])
        
        # Priority 2: Warnings
        if warning_findings:
            lines.extend([
                "### Priority 2: Important Best Practices (Fix within 1 month)",
                "",
            ])
            
            by_check = {}
            for finding in warning_findings[:10]:
                if finding.check_id not in by_check:
                    by_check[finding.check_id] = finding
            
            for i, (check_id, finding) in enumerate(list(by_check.items())[:5], 1):
                count = len([f for f in warning_findings if f.check_id == check_id])
                lines.extend([
                    f"#### {i}. {finding.check_name}",
                    f"**Priority**: P2 - Important",
                    f"**Affected Resources**: {count}",
                    f"**Recommendation**: {finding.recommendation or 'Review best practices'}",
                    "",
                ])
        
        lines.extend(["---", ""])
        return lines

    def _generate_appendix(self) -> List[str]:
        """Generate appendix section."""
        return [
            "## Appendix",
            "",
            "### Report Metadata",
            f"- **Generated By**: kubebaseline v1.0.0",
            f"- **Report Version**: 1.0",
            f"- **Generation Time**: {self.result.scan_duration:.2f} seconds",
            f"- **Kubernetes Version**: {self.result.cluster_info.get('version', 'unknown')}",
            f"- **Report Format**: Markdown",
            "",
            "### Excluded Namespaces",
        ] + [f"- `{ns}`" for ns in self.result.excluded_namespaces] + [
            "",
            "### References",
            "- [Kubernetes Documentation](https://kubernetes.io/docs/)",
            "- [Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)",
            "- [Network Policies](https://kubernetes.io/docs/concepts/services-networking/network-policies/)",
            "",
        ]

    def _get_status_emoji(self, compliance: float) -> str:
        """Get status emoji based on compliance percentage."""
        if compliance >= 90:
            return "✅ Excellent"
        elif compliance >= 75:
            return "✅ Good"
        elif compliance >= 60:
            return "⚠️ Needs Attention"
        else:
            return "❌ Critical"
