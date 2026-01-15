"""Pod configuration checks."""

from typing import List
from kbase.checks.base import BaseCheck
from kbase.models import CheckResult, Finding, Severity
from kubernetes.client.models import V1Pod


class PodConfigurationChecks(BaseCheck):
    """Pod configuration checks."""

    def get_category(self) -> str:
        return "Pod Configuration"

    def run_all_checks(self) -> List[CheckResult]:
        """Run all pod configuration checks."""
        return [
            self.check_required_labels(),
            self.check_health_checks(),
            self.check_startup_probes(),
            self.check_termination_grace_period(),
            self.check_prestop_hooks(),
        ]

    def check_required_labels(self) -> CheckResult:
        """Check for required Kubernetes labels."""
        check_id = "POD-001"
        check_name = "Required Labels"
        pods = self.client.list_pods()
        
        required_labels = ["app.kubernetes.io/name", "app"]
        findings = []
        total_count = 0
        passed_count = 0

        for pod in pods:
            if self.should_exclude_namespace(pod.metadata.namespace):
                continue

            total_count += 1
            labels = pod.metadata.labels or {}
            
            # Check if at least one of the required labels exists
            has_required = any(label in labels for label in required_labels)
            
            if not has_required:
                findings.append(
                    Finding(
                        check_id=check_id,
                        check_name=check_name,
                        category=self.get_category(),
                        severity=Severity.WARNING,
                        message=f"Pod '{pod.metadata.name}' is missing required labels",
                        resource_type="Pod",
                        resource_namespace=pod.metadata.namespace,
                        resource_name=pod.metadata.name,
                        details={
                            "required_labels": required_labels,
                            "current_labels": list(labels.keys()),
                        },
                        recommendation="Add standard Kubernetes labels: app.kubernetes.io/name or app",
                        remediation="Add labels.app.kubernetes.io/name or labels.app to pod metadata",
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

    def check_startup_probes(self) -> CheckResult:
        """Check for startup probes on containers."""
        check_id = "POD-003"
        check_name = "Startup Probes"
        pods = self.client.list_pods()
        
        findings = []
        total_count = 0
        passed_count = 0

        for pod in pods:
            if self.should_exclude_namespace(pod.metadata.namespace):
                continue

            if not pod.spec.containers:
                continue

            for container in pod.spec.containers:
                total_count += 1
                has_startup = container.startup_probe is not None
                
                # Startup probes are recommended for slow-starting containers
                # We'll flag containers that have liveness probes but no startup probe
                has_liveness = container.liveness_probe is not None
                
                if has_liveness and not has_startup:
                    findings.append(
                        Finding(
                            check_id=check_id,
                            check_name=check_name,
                            category=self.get_category(),
                            severity=Severity.INFO,
                            message=f"Container '{container.name}' in pod '{pod.metadata.name}' has liveness probe but no startup probe",
                            resource_type="Pod",
                            resource_namespace=pod.metadata.namespace,
                            resource_name=pod.metadata.name,
                            details={"container": container.name},
                            recommendation="Add startup probe for slow-starting containers to prevent premature restarts",
                            remediation="Add startupProbe to container spec",
                            references=["https://kubernetes.io/docs/tasks/configure-pod-container/configure-liveness-readiness-startup-probes/#define-startup-probes"],
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

    def check_termination_grace_period(self) -> CheckResult:
        """Check for termination grace period configuration."""
        check_id = "POD-004"
        check_name = "Termination Grace Period"
        pods = self.client.list_pods()
        
        findings = []
        total_count = 0
        passed_count = 0

        for pod in pods:
            if self.should_exclude_namespace(pod.metadata.namespace):
                continue

            total_count += 1
            grace_period = pod.spec.termination_grace_period_seconds
            
            # Default is 30 seconds, which is usually fine
            # Flag if explicitly set to 0 or very high (>300)
            if grace_period == 0:
                findings.append(
                    Finding(
                        check_id=check_id,
                        check_name=check_name,
                        category=self.get_category(),
                        severity=Severity.WARNING,
                        message=f"Pod '{pod.metadata.name}' has termination grace period set to 0",
                        resource_type="Pod",
                        resource_namespace=pod.metadata.namespace,
                        resource_name=pod.metadata.name,
                        details={"termination_grace_period_seconds": grace_period},
                        recommendation="Set termination grace period to allow graceful shutdown",
                        remediation="Set terminationGracePeriodSeconds to a reasonable value (e.g., 30)",
                        references=["https://kubernetes.io/docs/concepts/workloads/pods/pod-lifecycle/#pod-termination"],
                    )
                )
            elif grace_period and grace_period > 300:
                findings.append(
                    Finding(
                        check_id=check_id,
                        check_name=check_name,
                        category=self.get_category(),
                        severity=Severity.INFO,
                        message=f"Pod '{pod.metadata.name}' has very long termination grace period ({grace_period}s)",
                        resource_type="Pod",
                        resource_namespace=pod.metadata.namespace,
                        resource_name=pod.metadata.name,
                        details={"termination_grace_period_seconds": grace_period},
                        recommendation="Review if termination grace period is appropriate for application shutdown time",
                        remediation="Consider reducing terminationGracePeriodSeconds if application can shut down faster",
                        references=["https://kubernetes.io/docs/concepts/workloads/pods/pod-lifecycle/#pod-termination"],
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

    def check_prestop_hooks(self) -> CheckResult:
        """Check for preStop hooks on containers."""
        check_id = "POD-005"
        check_name = "PreStop Hooks"
        pods = self.client.list_pods()
        
        findings = []
        total_count = 0
        passed_count = 0

        for pod in pods:
            if self.should_exclude_namespace(pod.metadata.namespace):
                continue

            if not pod.spec.containers:
                continue

            for container in pod.spec.containers:
                total_count += 1
                lifecycle = container.lifecycle
                has_prestop = lifecycle and lifecycle.pre_stop is not None
                
                # PreStop hooks are recommended for graceful shutdown
                # Informational check - not critical
                if not has_prestop:
                    # Only flag if container has significant processing (has requests/limits)
                    resources = container.resources
                    has_resources = resources and (resources.requests or resources.limits)
                    
                    if has_resources:
                        findings.append(
                            Finding(
                                check_id=check_id,
                                check_name=check_name,
                                category=self.get_category(),
                                severity=Severity.INFO,
                                message=f"Container '{container.name}' in pod '{pod.metadata.name}' has no preStop hook",
                                resource_type="Pod",
                                resource_namespace=pod.metadata.namespace,
                                resource_name=pod.metadata.name,
                                details={"container": container.name},
                                recommendation="Consider adding preStop hook for graceful shutdown",
                                remediation="Add lifecycle.preStop to container spec",
                                references=["https://kubernetes.io/docs/concepts/containers/container-lifecycle-hooks/#hook-handler-implementations"],
                            )
                        )
                    else:
                        passed_count += 1
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

    def check_health_checks(self) -> CheckResult:
        """Check for health check probes."""
        check_id = "POD-002"
        check_name = "Health Checks"
        pods = self.client.list_pods()
        
        findings = []
        total_count = 0
        passed_count = 0

        for pod in pods:
            if self.should_exclude_namespace(pod.metadata.namespace):
                continue

            if not pod.spec.containers:
                continue

            for container in pod.spec.containers:
                total_count += 1
                
                has_liveness = container.liveness_probe is not None
                has_readiness = container.readiness_probe is not None
                
                if not has_liveness and not has_readiness:
                    findings.append(
                        Finding(
                            check_id=check_id,
                            check_name=check_name,
                            category=self.get_category(),
                            severity=Severity.WARNING,
                            message=f"Container '{container.name}' in pod '{pod.metadata.name}' has no health check probes",
                            resource_type="Pod",
                            resource_namespace=pod.metadata.namespace,
                            resource_name=pod.metadata.name,
                            details={
                                "container": container.name,
                                "has_liveness": has_liveness,
                                "has_readiness": has_readiness,
                            },
                            recommendation="Add liveness and readiness probes to detect and handle unhealthy containers",
                            remediation="Add livenessProbe and readinessProbe to container spec",
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
