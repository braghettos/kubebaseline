"""Network security checks."""

from typing import List
from kbase.checks.base import BaseCheck
from kbase.models import CheckResult, Finding, Severity
from kubernetes.client.models import V1Namespace


class NetworkSecurityChecks(BaseCheck):
    """Network security checks."""

    def get_category(self) -> str:
        return "Network Security"

    def run_all_checks(self) -> List[CheckResult]:
        """Run all network security checks."""
        return [
            self.check_network_policies(),
            self.check_ingress_tls(),
            self.check_service_types(),
            self.check_ingress_security_annotations(),
        ]

    def check_network_policies(self) -> CheckResult:
        """Check for network policies in namespaces."""
        check_id = "NET-001"
        check_name = "Network Policies"
        namespaces = self.client.list_namespaces()
        network_policies = self.client.list_network_policies()
        
        # Create a set of namespaces that have network policies
        namespaces_with_policies = set()
        for np in network_policies:
            if np.metadata.namespace:
                namespaces_with_policies.add(np.metadata.namespace)
        
        findings = []
        total_count = 0
        passed_count = 0

        for namespace in namespaces:
            namespace_name = namespace.metadata.name
            
            if self.should_exclude_namespace(namespace_name):
                continue
            
            # Skip system namespaces that might not need network policies
            if namespace_name.startswith("kube-"):
                continue
            
            total_count += 1
            
            if namespace_name not in namespaces_with_policies:
                findings.append(
                    Finding(
                        check_id=check_id,
                        check_name=check_name,
                        category=self.get_category(),
                        severity=Severity.CRITICAL,
                        message=f"Namespace '{namespace_name}' has no network policies",
                        resource_type="Namespace",
                        resource_namespace=None,
                        resource_name=namespace_name,
                        recommendation="Implement NetworkPolicy resources with default deny-all and explicit allow rules",
                        remediation="Create NetworkPolicy resources to restrict pod-to-pod communication",
                        references=["https://kubernetes.io/docs/concepts/services-networking/network-policies/"],
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

    def check_ingress_tls(self) -> CheckResult:
        """Check for TLS configuration on Ingress resources."""
        check_id = "NET-002"
        check_name = "Ingress TLS Configuration"
        ingresses = self.client.list_ingresses()
        
        findings = []
        total_count = 0
        passed_count = 0

        for ingress in ingresses:
            if self.should_exclude_namespace(ingress.metadata.namespace):
                continue

            total_count += 1
            tls = ingress.spec.tls if ingress.spec else None
            
            if not tls or len(tls) == 0:
                findings.append(
                    Finding(
                        check_id=check_id,
                        check_name=check_name,
                        category=self.get_category(),
                        severity=Severity.CRITICAL,
                        message=f"Ingress '{ingress.metadata.name}' has no TLS configuration",
                        resource_type="Ingress",
                        resource_namespace=ingress.metadata.namespace,
                        resource_name=ingress.metadata.name,
                        recommendation="Enable TLS/HTTPS for all Ingress resources",
                        remediation="Add TLS section to Ingress spec with secret containing certificate",
                        references=["https://kubernetes.io/docs/concepts/services-networking/ingress/#tls"],
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

    def check_service_types(self) -> CheckResult:
        """Check for appropriate Service types."""
        check_id = "NET-003"
        check_name = "Service Types"
        services = self.client.list_services()
        
        findings = []
        total_count = 0
        passed_count = 0

        for service in services:
            if self.should_exclude_namespace(service.metadata.namespace):
                continue

            total_count += 1
            service_type = service.spec.type if service.spec else "ClusterIP"
            
            # Flag NodePort and LoadBalancer services as they expose services externally
            if service_type in ["NodePort", "LoadBalancer"]:
                findings.append(
                    Finding(
                        check_id=check_id,
                        check_name=check_name,
                        category=self.get_category(),
                        severity=Severity.WARNING,
                        message=f"Service '{service.metadata.name}' uses {service_type} type",
                        resource_type="Service",
                        resource_namespace=service.metadata.namespace,
                        resource_name=service.metadata.name,
                        details={"service_type": service_type},
                        recommendation="Use ClusterIP for internal services and Ingress for external access",
                        remediation="Change service type to ClusterIP and use Ingress for external access",
                        references=["https://kubernetes.io/docs/concepts/services-networking/service/#publishing-services-service-types"],
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

    def check_ingress_security_annotations(self) -> CheckResult:
        """Check for security-related annotations on Ingress resources."""
        check_id = "NET-004"
        check_name = "Ingress Security Annotations"
        ingresses = self.client.list_ingresses()
        
        findings = []
        total_count = 0
        passed_count = 0
        
        # Common security annotations to check for
        security_annotations = [
            "nginx.ingress.kubernetes.io/rate-limit",
            "nginx.ingress.kubernetes.io/ssl-redirect",
            "nginx.ingress.kubernetes.io/force-ssl-redirect",
            "cert-manager.io/cluster-issuer",
            "cert-manager.io/issuer",
        ]

        for ingress in ingresses:
            if self.should_exclude_namespace(ingress.metadata.namespace):
                continue

            total_count += 1
            annotations = ingress.metadata.annotations or {}
            
            # Check if any security annotations are present
            has_security_annotations = any(ann in annotations for ann in security_annotations)
            
            # Informational - recommend adding security annotations
            if not has_security_annotations:
                findings.append(
                    Finding(
                        check_id=check_id,
                        check_name=check_name,
                        category=self.get_category(),
                        severity=Severity.INFO,
                        message=f"Ingress '{ingress.metadata.name}' has no security annotations",
                        resource_type="Ingress",
                        resource_namespace=ingress.metadata.namespace,
                        resource_name=ingress.metadata.name,
                        recommendation="Consider adding security annotations (rate limiting, SSL redirect, cert-manager)",
                        remediation="Add security annotations based on your ingress controller (nginx, traefik, etc.)",
                        references=["https://kubernetes.github.io/ingress-nginx/user-guide/nginx-configuration/annotations/"],
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
