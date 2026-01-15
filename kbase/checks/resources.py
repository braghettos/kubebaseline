"""Resource management checks."""

from typing import List
from kbase.checks.base import BaseCheck
from kbase.models import CheckResult, Finding, Severity
from kubernetes.client.models import V1Pod, V1Container


class ResourceManagementChecks(BaseCheck):
    """Resource management checks."""

    def get_category(self) -> str:
        return "Resource Management"

    def run_all_checks(self) -> List[CheckResult]:
        """Run all resource management checks."""
        return [
            self.check_cpu_requests(),
            self.check_memory_requests(),
            self.check_cpu_limits(),
            self.check_memory_limits(),
            self.check_resource_ratios(),
            self.check_resource_quotas(),
            self.check_limit_ranges(),
            self.check_init_container_resources(),
        ]

    def check_cpu_requests(self) -> CheckResult:
        """Check for missing CPU requests."""
        check_id = "RES-001"
        check_name = "CPU Requests"
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
                resources = container.resources
                
                if not resources or not resources.requests or "cpu" not in resources.requests:
                    findings.append(
                        Finding(
                            check_id=check_id,
                            check_name=check_name,
                            category=self.get_category(),
                            severity=Severity.CRITICAL,
                            message=f"Container '{container.name}' in pod '{pod.metadata.name}' has no CPU request",
                            resource_type="Pod",
                            resource_namespace=pod.metadata.namespace,
                            resource_name=pod.metadata.name,
                            details={"container": container.name},
                            recommendation="Set CPU requests for all containers to enable proper scheduling",
                            remediation="Add resources.requests.cpu to container spec",
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

    def check_memory_requests(self) -> CheckResult:
        """Check for missing memory requests."""
        check_id = "RES-002"
        check_name = "Memory Requests"
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
                resources = container.resources
                
                if not resources or not resources.requests or "memory" not in resources.requests:
                    findings.append(
                        Finding(
                            check_id=check_id,
                            check_name=check_name,
                            category=self.get_category(),
                            severity=Severity.CRITICAL,
                            message=f"Container '{container.name}' in pod '{pod.metadata.name}' has no memory request",
                            resource_type="Pod",
                            resource_namespace=pod.metadata.namespace,
                            resource_name=pod.metadata.name,
                            details={"container": container.name},
                            recommendation="Set memory requests for all containers to enable proper scheduling",
                            remediation="Add resources.requests.memory to container spec",
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

    def check_cpu_limits(self) -> CheckResult:
        """Check for missing CPU limits."""
        check_id = "RES-003"
        check_name = "CPU Limits"
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
                resources = container.resources
                
                if not resources or not resources.limits or "cpu" not in resources.limits:
                    findings.append(
                        Finding(
                            check_id=check_id,
                            check_name=check_name,
                            category=self.get_category(),
                            severity=Severity.WARNING,
                            message=f"Container '{container.name}' in pod '{pod.metadata.name}' has no CPU limit",
                            resource_type="Pod",
                            resource_namespace=pod.metadata.namespace,
                            resource_name=pod.metadata.name,
                            details={"container": container.name},
                            recommendation="Set CPU limits to prevent resource exhaustion",
                            remediation="Add resources.limits.cpu to container spec",
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

    def check_memory_limits(self) -> CheckResult:
        """Check for missing memory limits."""
        check_id = "RES-004"
        check_name = "Memory Limits"
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
                resources = container.resources
                
                if not resources or not resources.limits or "memory" not in resources.limits:
                    findings.append(
                        Finding(
                            check_id=check_id,
                            check_name=check_name,
                            category=self.get_category(),
                            severity=Severity.CRITICAL,
                            message=f"Container '{container.name}' in pod '{pod.metadata.name}' has no memory limit",
                            resource_type="Pod",
                            resource_namespace=pod.metadata.namespace,
                            resource_name=pod.metadata.name,
                            details={"container": container.name},
                            recommendation="Set memory limits to prevent OOM kills",
                            remediation="Add resources.limits.memory to container spec",
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

    def check_resource_ratios(self) -> CheckResult:
        """Check if limits exceed 2x requests (recommended ratio)."""
        check_id = "RES-005"
        check_name = "Resource Ratios"
        pods = self.client.list_pods()
        
        findings = []
        total_count = 0
        passed_count = 0

        def parse_quantity(qty_str: str) -> float:
            """Parse Kubernetes quantity to float (simplified)."""
            if not qty_str:
                return 0.0
            qty_str = qty_str.strip()
            if qty_str.endswith("m"):
                return float(qty_str[:-1]) / 1000.0
            elif qty_str.endswith("Gi"):
                return float(qty_str[:-2]) * 1024  # Convert to Mi
            elif qty_str.endswith("Mi"):
                return float(qty_str[:-2])
            elif qty_str.endswith("G"):
                return float(qty_str[:-1]) * 1000  # Convert to M
            elif qty_str.endswith("M"):
                return float(qty_str[:-1])
            try:
                return float(qty_str)
            except:
                return 0.0

        for pod in pods:
            if self.should_exclude_namespace(pod.metadata.namespace):
                continue

            if not pod.spec.containers:
                continue

            for container in pod.spec.containers:
                resources = container.resources
                
                if not resources:
                    continue
                
                # Check CPU ratio
                if resources.requests and "cpu" in resources.requests and \
                   resources.limits and "cpu" in resources.limits:
                    total_count += 1
                    cpu_request = parse_quantity(resources.requests["cpu"])
                    cpu_limit = parse_quantity(resources.limits["cpu"])
                    
                    if cpu_request > 0 and cpu_limit > cpu_request * 2:
                        findings.append(
                            Finding(
                                check_id=check_id,
                                check_name=check_name,
                                category=self.get_category(),
                                severity=Severity.INFO,
                                message=f"Container '{container.name}' has CPU limit ({cpu_limit}) > 2x request ({cpu_request})",
                                resource_type="Pod",
                                resource_namespace=pod.metadata.namespace,
                                resource_name=pod.metadata.name,
                                details={
                                    "container": container.name,
                                    "cpu_request": resources.requests["cpu"],
                                    "cpu_limit": resources.limits["cpu"],
                                    "ratio": cpu_limit / cpu_request if cpu_request > 0 else 0,
                                },
                                recommendation="Consider setting limits closer to requests for predictable performance",
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

    def check_resource_quotas(self) -> CheckResult:
        """Check for resource quotas in namespaces."""
        check_id = "RES-006"
        check_name = "Resource Quotas"
        namespaces = self.client.list_namespaces()
        resource_quotas = self.client.list_resource_quotas()
        
        # Create a set of namespaces that have resource quotas
        namespaces_with_quotas = set()
        for rq in resource_quotas:
            if rq.metadata.namespace:
                namespaces_with_quotas.add(rq.metadata.namespace)
        
        findings = []
        total_count = 0
        passed_count = 0

        for namespace in namespaces:
            namespace_name = namespace.metadata.name
            
            if self.should_exclude_namespace(namespace_name):
                continue
            
            # Skip system namespaces
            if namespace_name.startswith("kube-"):
                continue
            
            total_count += 1
            
            if namespace_name not in namespaces_with_quotas:
                findings.append(
                    Finding(
                        check_id=check_id,
                        check_name=check_name,
                        category=self.get_category(),
                        severity=Severity.WARNING,
                        message=f"Namespace '{namespace_name}' has no resource quotas",
                        resource_type="Namespace",
                        resource_namespace=None,
                        resource_name=namespace_name,
                        recommendation="Create ResourceQuota to limit resource consumption per namespace",
                        remediation="Create a ResourceQuota resource in the namespace",
                        references=["https://kubernetes.io/docs/concepts/policy/resource-quotas/"],
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

    def check_limit_ranges(self) -> CheckResult:
        """Check for limit ranges in namespaces."""
        check_id = "RES-007"
        check_name = "Limit Ranges"
        namespaces = self.client.list_namespaces()
        limit_ranges = self.client.list_limit_ranges()
        
        # Create a set of namespaces that have limit ranges
        namespaces_with_limits = set()
        for lr in limit_ranges:
            if lr.metadata.namespace:
                namespaces_with_limits.add(lr.metadata.namespace)
        
        findings = []
        total_count = 0
        passed_count = 0

        for namespace in namespaces:
            namespace_name = namespace.metadata.name
            
            if self.should_exclude_namespace(namespace_name):
                continue
            
            # Skip system namespaces
            if namespace_name.startswith("kube-"):
                continue
            
            total_count += 1
            
            if namespace_name not in namespaces_with_limits:
                findings.append(
                    Finding(
                        check_id=check_id,
                        check_name=check_name,
                        category=self.get_category(),
                        severity=Severity.INFO,
                        message=f"Namespace '{namespace_name}' has no limit ranges",
                        resource_type="Namespace",
                        resource_namespace=None,
                        resource_name=namespace_name,
                        recommendation="Create LimitRange to set default resource requests and limits",
                        remediation="Create a LimitRange resource in the namespace",
                        references=["https://kubernetes.io/docs/concepts/policy/limit-range/"],
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

    def check_init_container_resources(self) -> CheckResult:
        """Check for resource requests/limits on init containers."""
        check_id = "RES-008"
        check_name = "Init Container Resources"
        pods = self.client.list_pods()
        
        findings = []
        total_count = 0
        passed_count = 0

        for pod in pods:
            if self.should_exclude_namespace(pod.metadata.namespace):
                continue

            if not pod.spec.init_containers:
                continue

            for init_container in pod.spec.init_containers:
                total_count += 1
                resources = init_container.resources
                
                has_requests = resources and resources.requests and ("cpu" in resources.requests or "memory" in resources.requests)
                has_limits = resources and resources.limits and ("cpu" in resources.limits or "memory" in resources.limits)
                
                if not has_requests or not has_limits:
                    findings.append(
                        Finding(
                            check_id=check_id,
                            check_name=check_name,
                            category=self.get_category(),
                            severity=Severity.WARNING,
                            message=f"Init container '{init_container.name}' in pod '{pod.metadata.name}' is missing resource requests or limits",
                            resource_type="Pod",
                            resource_namespace=pod.metadata.namespace,
                            resource_name=pod.metadata.name,
                            details={
                                "init_container": init_container.name,
                                "has_requests": has_requests,
                                "has_limits": has_limits,
                            },
                            recommendation="Set resource requests and limits on init containers",
                            remediation="Add resources.requests and resources.limits to init container spec",
                            references=["https://kubernetes.io/docs/concepts/workloads/pods/init-containers/"],
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
