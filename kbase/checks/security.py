"""Security best practice checks."""

from typing import List
from kbase.checks.base import BaseCheck
from kbase.models import CheckResult, Finding, Severity
from kubernetes.client.models import V1Pod, V1Container


class SecurityChecks(BaseCheck):
    """Security best practice checks."""

    def get_category(self) -> str:
        return "Security Best Practices"

    def run_all_checks(self) -> List[CheckResult]:
        """Run all security checks."""
        return [
            self.check_privileged_containers(),
            self.check_root_users(),
            self.check_security_context(),
            self.check_readonly_rootfs(),
            self.check_capabilities(),
            self.check_host_namespace_sharing(),
            self.check_pod_security_standards(),
            self.check_secrets_in_configmaps(),
            self.check_image_pull_secrets(),
            self.check_image_tags(),
            self.check_service_account_token_automount(),
            self.check_seccomp_profile(),
        ]

    def check_privileged_containers(self) -> CheckResult:
        """Check for privileged containers."""
        check_id = "SEC-001"
        check_name = "Privileged Containers"
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
                security_context = container.security_context
                
                if security_context and security_context.privileged:
                    # Allow privileged in system namespaces
                    if pod.metadata.namespace in ["kube-system"]:
                        passed_count += 1
                        continue
                    
                    findings.append(
                        Finding(
                            check_id=check_id,
                            check_name=check_name,
                            category=self.get_category(),
                            severity=Severity.CRITICAL,
                            message=f"Container '{container.name}' in pod '{pod.metadata.name}' is running as privileged",
                            resource_type="Pod",
                            resource_namespace=pod.metadata.namespace,
                            resource_name=pod.metadata.name,
                            details={"container": container.name},
                            recommendation="Remove privileged flag from container security context",
                            remediation="Set securityContext.privileged: false",
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

    def check_root_users(self) -> CheckResult:
        """Check for containers running as root."""
        check_id = "SEC-002"
        check_name = "Root Users"
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
                
                # Check pod-level security context
                pod_sec_ctx = pod.spec.security_context
                container_sec_ctx = container.security_context
                
                run_as_user = None
                run_as_non_root = None
                
                if container_sec_ctx:
                    run_as_user = container_sec_ctx.run_as_user
                    run_as_non_root = container_sec_ctx.run_as_non_root
                
                if pod_sec_ctx and not container_sec_ctx:
                    run_as_user = pod_sec_ctx.run_as_user
                    run_as_non_root = pod_sec_ctx.run_as_non_root
                
                # Check if running as root (user 0 or not specified without runAsNonRoot)
                is_root = False
                if run_as_user == 0:
                    is_root = True
                elif run_as_user is None and run_as_non_root is not True:
                    # Default behavior is to run as root
                    is_root = True
                
                if is_root:
                    findings.append(
                        Finding(
                            check_id=check_id,
                            check_name=check_name,
                            category=self.get_category(),
                            severity=Severity.CRITICAL,
                            message=f"Container '{container.name}' in pod '{pod.metadata.name}' may be running as root",
                            resource_type="Pod",
                            resource_namespace=pod.metadata.namespace,
                            resource_name=pod.metadata.name,
                            details={
                                "container": container.name,
                                "run_as_user": run_as_user,
                                "run_as_non_root": run_as_non_root,
                            },
                            recommendation="Set runAsNonRoot: true and specify a non-zero runAsUser",
                            remediation="Set securityContext.runAsNonRoot: true and securityContext.runAsUser: <non-zero-uid>",
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

    def check_security_context(self) -> CheckResult:
        """Check for missing security context."""
        check_id = "SEC-003"
        check_name = "Missing Security Context"
        pods = self.client.list_pods()
        
        findings = []
        total_count = 0
        passed_count = 0

        for pod in pods:
            if self.should_exclude_namespace(pod.metadata.namespace):
                continue

            if not pod.spec.containers:
                continue

            total_count += 1
            
            # Check if pod or containers have security context
            has_pod_sec_ctx = pod.spec.security_context is not None
            has_container_sec_ctx = any(
                c.security_context is not None for c in pod.spec.containers
            )
            
            if not has_pod_sec_ctx and not has_container_sec_ctx:
                findings.append(
                    Finding(
                        check_id=check_id,
                        check_name=check_name,
                        category=self.get_category(),
                        severity=Severity.WARNING,
                        message=f"Pod '{pod.metadata.name}' has no security context defined",
                        resource_type="Pod",
                        resource_namespace=pod.metadata.namespace,
                        resource_name=pod.metadata.name,
                        recommendation="Define securityContext with appropriate security settings",
                        remediation="Add securityContext to pod or container spec",
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

    def check_readonly_rootfs(self) -> CheckResult:
        """Check for read-only root filesystems."""
        check_id = "SEC-004"
        check_name = "Read-Only Root Filesystem"
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
                security_context = container.security_context
                
                if not security_context or not security_context.read_only_root_filesystem:
                    findings.append(
                        Finding(
                            check_id=check_id,
                            check_name=check_name,
                            category=self.get_category(),
                            severity=Severity.INFO,
                            message=f"Container '{container.name}' in pod '{pod.metadata.name}' does not use read-only root filesystem",
                            resource_type="Pod",
                            resource_namespace=pod.metadata.namespace,
                            resource_name=pod.metadata.name,
                            details={"container": container.name},
                            recommendation="Enable readOnlyRootFilesystem where possible for improved security",
                            remediation="Set securityContext.readOnlyRootFilesystem: true",
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

    def check_capabilities(self) -> CheckResult:
        """Check for dangerous capabilities."""
        check_id = "SEC-005"
        check_name = "Dangerous Capabilities"
        pods = self.client.list_pods()
        
        dangerous_caps = ["NET_RAW", "SYS_ADMIN", "SYS_MODULE", "ALL"]
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
                security_context = container.security_context
                
                if security_context and security_context.capabilities:
                    add_caps = security_context.capabilities.add or []
                    dangerous_found = [cap for cap in add_caps if cap in dangerous_caps]
                    
                    if dangerous_found:
                        findings.append(
                            Finding(
                                check_id=check_id,
                                check_name=check_name,
                                category=self.get_category(),
                                severity=Severity.WARNING if "ALL" not in dangerous_found else Severity.CRITICAL,
                                message=f"Container '{container.name}' has dangerous capabilities: {', '.join(dangerous_found)}",
                                resource_type="Pod",
                                resource_namespace=pod.metadata.namespace,
                                resource_name=pod.metadata.name,
                                details={"container": container.name, "capabilities": dangerous_found},
                                recommendation="Drop ALL capabilities and add only those explicitly required",
                                remediation="Set securityContext.capabilities.drop: ['ALL'] and add minimal required capabilities",
                            )
                        )
                    else:
                        passed_count += 1
                else:
                    # No capabilities defined, which is acceptable
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

    def check_host_namespace_sharing(self) -> CheckResult:
        """Check for host namespace sharing."""
        check_id = "SEC-006"
        check_name = "Host Namespace Sharing"
        pods = self.client.list_pods()
        
        findings = []
        total_count = 0
        passed_count = 0

        for pod in pods:
            if self.should_exclude_namespace(pod.metadata.namespace):
                continue

            total_count += 1
            spec = pod.spec
            
            issues = []
            if spec.host_network:
                issues.append("hostNetwork")
            if spec.host_pid:
                issues.append("hostPID")
            if spec.host_ipc:
                issues.append("hostIPC")
            
            if issues:
                findings.append(
                    Finding(
                        check_id=check_id,
                        check_name=check_name,
                        category=self.get_category(),
                        severity=Severity.CRITICAL,
                        message=f"Pod '{pod.metadata.name}' shares host namespaces: {', '.join(issues)}",
                        resource_type="Pod",
                        resource_namespace=pod.metadata.namespace,
                        resource_name=pod.metadata.name,
                        details={"shared_namespaces": issues},
                        recommendation="Disable host namespace sharing unless absolutely necessary",
                        remediation="Remove hostNetwork, hostPID, or hostIPC from pod spec",
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

    def check_pod_security_standards(self) -> CheckResult:
        """Check for Pod Security Standards enforcement."""
        check_id = "SEC-007"
        check_name = "Pod Security Standards"
        namespaces = self.client.list_namespaces()
        
        findings = []
        total_count = 0
        passed_count = 0

        for namespace in namespaces:
            if self.should_exclude_namespace(namespace.metadata.name):
                continue

            total_count += 1
            annotations = namespace.metadata.annotations or {}
            enforce = annotations.get("pod-security.kubernetes.io/enforce")
            
            if not enforce:
                findings.append(
                    Finding(
                        check_id=check_id,
                        check_name=check_name,
                        category=self.get_category(),
                        severity=Severity.WARNING,
                        message=f"Namespace '{namespace.metadata.name}' has no Pod Security Standards enforcement",
                        resource_type="Namespace",
                        resource_namespace=None,
                        resource_name=namespace.metadata.name,
                        recommendation="Enable Pod Security Standards with enforce mode set to baseline or restricted",
                        remediation="Add annotation pod-security.kubernetes.io/enforce: baseline or restricted",
                        references=["https://kubernetes.io/docs/concepts/security/pod-security-standards/"],
                    )
                )
            elif enforce == "privileged":
                findings.append(
                    Finding(
                        check_id=check_id,
                        check_name=check_name,
                        category=self.get_category(),
                        severity=Severity.CRITICAL,
                        message=f"Namespace '{namespace.metadata.name}' allows privileged pods",
                        resource_type="Namespace",
                        resource_namespace=None,
                        resource_name=namespace.metadata.name,
                        recommendation="Change Pod Security Standards enforce mode to baseline or restricted",
                        remediation="Change annotation pod-security.kubernetes.io/enforce to baseline or restricted",
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

    def check_secrets_in_configmaps(self) -> CheckResult:
        """Check for secrets in ConfigMaps (heuristic check)."""
        check_id = "SEC-008"
        check_name = "Secrets in ConfigMaps"
        configmaps = self.client.list_configmaps()
        
        findings = []
        total_count = 0
        passed_count = 0
        
        # Patterns that might indicate secrets
        secret_patterns = ["pwd", "pass", "secret", "token", "key"]

        for cm in configmaps:
            if self.should_exclude_namespace(cm.metadata.namespace):
                continue

            if not cm.data:
                continue

            total_count += 1
            suspicious_keys = []
            
            for key, value in cm.data.items():
                key_lower = key.lower()
                # Check if key name suggests a secret
                if any(pattern in key_lower for pattern in secret_patterns):
                    suspicious_keys.append(key)
                # Check if value looks like a secret (long string without spaces, has alphanumeric)
                elif value and len(value) > 20 and " " not in value and (value.isalnum() or any(c in value for c in "!@#$%^&*")):
                    # Might be a secret, flag as suspicious
                    if key not in suspicious_keys:
                        suspicious_keys.append(key)
            
            if suspicious_keys:
                findings.append(
                    Finding(
                        check_id=check_id,
                        check_name=check_name,
                        category=self.get_category(),
                        severity=Severity.WARNING,
                        message=f"ConfigMap '{cm.metadata.name}' may contain secrets in keys: {', '.join(suspicious_keys[:5])}",
                        resource_type="ConfigMap",
                        resource_namespace=cm.metadata.namespace,
                        resource_name=cm.metadata.name,
                        details={"suspicious_keys": suspicious_keys},
                        recommendation="Move secrets to Kubernetes Secrets or external secret managers",
                        remediation="Create a Secret resource or use external secret management (Sealed Secrets, External Secrets Operator)",
                        references=["https://kubernetes.io/docs/concepts/configuration/secret/"],
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

    def check_image_pull_secrets(self) -> CheckResult:
        """Check for image pull secrets on pods using private registries."""
        check_id = "SEC-009"
        check_name = "Image Pull Secrets"
        pods = self.client.list_pods()
        
        findings = []
        total_count = 0
        passed_count = 0

        # Common private registry patterns
        private_registries = ["gcr.io", "docker.io", "quay.io", "azurecr.io", "amazonaws.com", "registry", "harbor"]

        for pod in pods:
            if self.should_exclude_namespace(pod.metadata.namespace):
                continue

            if not pod.spec.containers:
                continue

            for container in pod.spec.containers:
                if not container.image:
                    continue
                
                # Check if image might be from private registry
                image = container.image
                is_private_registry = any(registry in image for registry in private_registries)
                
                # Check if image has a tag/digest (more likely to need pull secret)
                has_tag_or_digest = ":" in image or "@" in image
                
                if is_private_registry and has_tag_or_digest:
                    total_count += 1
                    # Check for imagePullSecrets at pod level or service account
                    has_pull_secret = (
                        (pod.spec.image_pull_secrets and len(pod.spec.image_pull_secrets) > 0) or
                        (pod.spec.service_account_name and pod.spec.service_account_name != "default")
                    )
                    
                    if not has_pull_secret:
                        findings.append(
                            Finding(
                                check_id=check_id,
                                check_name=check_name,
                                category=self.get_category(),
                                severity=Severity.INFO,
                                message=f"Pod '{pod.metadata.name}' may need imagePullSecrets for private registry image",
                                resource_type="Pod",
                                resource_namespace=pod.metadata.namespace,
                                resource_name=pod.metadata.name,
                                details={"container": container.name, "image": image},
                                recommendation="Configure imagePullSecrets if image requires authentication",
                                remediation="Add imagePullSecrets to pod spec or configure service account with image pull secrets",
                                references=["https://kubernetes.io/docs/concepts/containers/images/#specifying-imagepullsecrets-on-a-pod"],
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

    def check_image_tags(self) -> CheckResult:
        """Check for use of :latest tag or missing tags."""
        check_id = "SEC-010"
        check_name = "Image Tags (Avoid Latest)"
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
                if not container.image:
                    continue
                
                total_count += 1
                image = container.image
                
                # Check for :latest tag or missing tag
                if ":latest" in image or (":" not in image and "@" not in image and "/" in image):
                    findings.append(
                        Finding(
                            check_id=check_id,
                            check_name=check_name,
                            category=self.get_category(),
                            severity=Severity.WARNING,
                            message=f"Container '{container.name}' uses 'latest' tag or no tag: {image}",
                            resource_type="Pod",
                            resource_namespace=pod.metadata.namespace,
                            resource_name=pod.metadata.name,
                            details={"container": container.name, "image": image},
                            recommendation="Use specific image tags or digests instead of 'latest'",
                            remediation="Update image to use specific version tag (e.g., myapp:v1.2.3) or digest (e.g., myapp@sha256:...)",
                            references=["https://kubernetes.io/docs/concepts/containers/images/#image-names"],
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

    def check_service_account_token_automount(self) -> CheckResult:
        """Check for service account token auto-mounting."""
        check_id = "SEC-011"
        check_name = "Service Account Token Auto-Mount"
        pods = self.client.list_pods()
        
        findings = []
        total_count = 0
        passed_count = 0

        for pod in pods:
            if self.should_exclude_namespace(pod.metadata.namespace):
                continue

            total_count += 1
            
            # Check automountServiceAccountToken
            automount = pod.spec.automount_service_account_token
            
            # Default is True if not specified, which is acceptable for most cases
            # Flag only if explicitly set to True when it might not be needed
            # This is informational - not critical
            if automount is True and pod.spec.service_account_name == "default":
                findings.append(
                    Finding(
                        check_id=check_id,
                        check_name=check_name,
                        category=self.get_category(),
                        severity=Severity.INFO,
                        message=f"Pod '{pod.metadata.name}' auto-mounts service account token from default service account",
                        resource_type="Pod",
                        resource_namespace=pod.metadata.namespace,
                        resource_name=pod.metadata.name,
                        recommendation="Disable automountServiceAccountToken if service account token is not needed",
                        remediation="Set automountServiceAccountToken: false if service account token access is not required",
                        references=["https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/#use-the-default-service-account-to-access-the-api-server"],
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

    def check_seccomp_profile(self) -> CheckResult:
        """Check for seccomp profile configuration."""
        check_id = "SEC-012"
        check_name = "Seccomp Profile"
        pods = self.client.list_pods()
        
        findings = []
        total_count = 0
        passed_count = 0

        for pod in pods:
            if self.should_exclude_namespace(pod.metadata.namespace):
                continue

            if not pod.spec.containers:
                continue

            total_count += 1
            sec_ctx = pod.spec.security_context
            annotations = pod.metadata.annotations or {}
            
            # Check for seccomp profile
            has_seccomp = False
            if sec_ctx and sec_ctx.seccomp_profile:
                has_seccomp = True
            elif "seccomp.security.alpha.kubernetes.io/pod" in annotations:
                has_seccomp = True
            
            if not has_seccomp:
                findings.append(
                    Finding(
                        check_id=check_id,
                        check_name=check_name,
                        category=self.get_category(),
                        severity=Severity.INFO,
                        message=f"Pod '{pod.metadata.name}' has no seccomp profile configured",
                        resource_type="Pod",
                        resource_namespace=pod.metadata.namespace,
                        resource_name=pod.metadata.name,
                        recommendation="Configure seccomp profile for additional security",
                        remediation="Set securityContext.seccompProfile.type to RuntimeDefault or create custom profile",
                        references=["https://kubernetes.io/docs/tutorials/security/seccomp/"],
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
