"""Namespace management checks."""

from typing import List
from kbase.checks.base import BaseCheck
from kbase.models import CheckResult, Finding, Severity


class NamespaceChecks(BaseCheck):
    """Namespace management checks."""

    def get_category(self) -> str:
        return "Namespace Management"

    def run_all_checks(self) -> List[CheckResult]:
        """Run all namespace checks."""
        return [
            self.check_namespace_labels(),
            self.check_namespace_annotations(),
        ]

    def check_namespace_labels(self) -> CheckResult:
        """Check for required labels on namespaces."""
        check_id = "NS-001"
        check_name = "Namespace Labels"
        namespaces = self.client.list_namespaces()
        
        findings = []
        total_count = 0
        passed_count = 0
        
        # Common labels that should be present
        recommended_labels = ["app.kubernetes.io/name", "environment", "team"]

        for namespace in namespaces:
            namespace_name = namespace.metadata.name
            
            if self.should_exclude_namespace(namespace_name):
                continue
            
            # Skip system namespaces
            if namespace_name.startswith("kube-"):
                continue

            total_count += 1
            labels = namespace.metadata.labels or {}
            
            # Check if any recommended labels are present
            has_recommended = any(label in labels for label in recommended_labels)
            
            if not has_recommended:
                findings.append(
                    Finding(
                        check_id=check_id,
                        check_name=check_name,
                        category=self.get_category(),
                        severity=Severity.INFO,
                        message=f"Namespace '{namespace_name}' is missing recommended labels",
                        resource_type="Namespace",
                        resource_namespace=None,
                        resource_name=namespace_name,
                        details={"recommended_labels": recommended_labels, "current_labels": list(labels.keys())},
                        recommendation="Add standard labels for better organization and resource management",
                        remediation="Add labels such as app.kubernetes.io/name, environment, team to namespace metadata",
                        references=["https://kubernetes.io/docs/concepts/overview/working-with-objects/common-labels/"],
                    )
                )
            else:
                passed_count += 1

        return CheckResult(
            check_id=check_id,
            check_name=check_name,
            category=self.get_category(),
            passed=len(findings) == 0,
            findings=findings,
            resource_count=total_count,
            passed_count=passed_count,
            failed_count=len(findings),
        )

    def check_namespace_annotations(self) -> CheckResult:
        """Check for recommended annotations on namespaces."""
        check_id = "NS-002"
        check_name = "Namespace Annotations"
        namespaces = self.client.list_namespaces()
        
        findings = []
        total_count = 0
        passed_count = 0
        
        # Common annotations that might be useful
        recommended_annotations = [
            "pod-security.kubernetes.io/enforce",
            "pod-security.kubernetes.io/audit",
            "pod-security.kubernetes.io/warn",
        ]

        for namespace in namespaces:
            namespace_name = namespace.metadata.name
            
            if self.should_exclude_namespace(namespace_name):
                continue
            
            # Skip system namespaces
            if namespace_name.startswith("kube-"):
                continue

            total_count += 1
            annotations = namespace.metadata.annotations or {}
            
            # Check for pod security annotations (most important)
            has_pod_security = any(ann in annotations for ann in recommended_annotations)
            
            if not has_pod_security:
                findings.append(
                    Finding(
                        check_id=check_id,
                        check_name=check_name,
                        category=self.get_category(),
                        severity=Severity.INFO,
                        message=f"Namespace '{namespace_name}' has no Pod Security Standards annotations",
                        resource_type="Namespace",
                        resource_namespace=None,
                        resource_name=namespace_name,
                        recommendation="Add Pod Security Standards annotations for security policy enforcement",
                        remediation="Add pod-security.kubernetes.io/enforce annotation (baseline or restricted)",
                        references=["https://kubernetes.io/docs/concepts/security/pod-security-standards/"],
                    )
                )
            else:
                passed_count += 1

        return CheckResult(
            check_id=check_id,
            check_name=check_name,
            category=self.get_category(),
            passed=len(findings) == 0,
            findings=findings,
            resource_count=total_count,
            passed_count=passed_count,
            failed_count=len(findings),
        )