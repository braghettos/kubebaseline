"""Main scanner that runs all checks."""

import time
from typing import List, Optional
from datetime import datetime
from kbase.client import KubernetesClient
from kbase.checks import get_all_checks
from kbase.models import ScanResult, CategoryResult, Finding, Severity


class Scanner:
    """Main scanner that orchestrates all compliance checks."""

    def __init__(
        self,
        client: KubernetesClient,
        excluded_namespaces: Optional[List[str]] = None,
    ):
        """Initialize scanner.
        
        Args:
            client: Kubernetes API client
            excluded_namespaces: Additional namespaces to exclude
        """
        self.client = client
        excluded = excluded_namespaces or []
        default_excluded = ["kube-system", "kube-public", "kube-node-lease"]
        self.excluded_namespaces = list(set(excluded + default_excluded))

    def scan(self) -> ScanResult:
        """Run all compliance checks and return results."""
        start_time = time.time()
        
        # Get cluster info
        cluster_info = self.client.get_cluster_info()
        
        # Run all checks
        all_findings: List[Finding] = []
        category_results: List[CategoryResult] = []
        
        for check_class in get_all_checks():
            check_instance = check_class(self.client, self.excluded_namespaces)
            category = check_instance.get_category()
            
            # Run all checks in this category
            check_results = check_instance.run_all_checks()
            
            # Collect findings
            category_findings: List[Finding] = []
            for result in check_results:
                category_findings.extend(result.findings)
                all_findings.extend(result.findings)
            
            # Calculate category totals
            total_resources = sum(c.resource_count for c in check_results)
            total_passed = sum(c.passed_count for c in check_results)
            total_failed = sum(c.failed_count for c in check_results)
            total_warnings = len([f for f in category_findings if f.severity == Severity.WARNING])
            total_critical = len([f for f in category_findings if f.severity == Severity.CRITICAL])
            
            category_result = CategoryResult(
                category=category,
                checks=check_results,
                total_resources=total_resources,
                total_passed=total_passed,
                total_failed=total_failed,
                total_warnings=total_warnings,
                total_critical=total_critical,
            )
            category_results.append(category_result)
        
        scan_duration = time.time() - start_time
        
        return ScanResult(
            cluster_info=cluster_info,
            scan_date=datetime.now(),
            scan_duration=scan_duration,
            categories=category_results,
            all_findings=all_findings,
            excluded_namespaces=self.excluded_namespaces,
        )
