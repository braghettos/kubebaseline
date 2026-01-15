"""RBAC checks."""

from typing import List
from kbase.checks.base import BaseCheck
from kbase.models import CheckResult, Finding, Severity


class RBACChecks(BaseCheck):
    """RBAC checks."""

    def get_category(self) -> str:
        return "RBAC & Access Control"

    def run_all_checks(self) -> List[CheckResult]:
        """Run all RBAC checks."""
        return [
            self.check_service_accounts(),
            self.check_clusterrole_wildcards(),
            self.check_clusteradmin_bindings(),
            self.check_role_binding_best_practices(),
            self.check_service_account_permissions(),
        ]

    def check_service_accounts(self) -> CheckResult:
        """Check for use of default service accounts."""
        check_id = "RBAC-001"
        check_name = "Service Accounts"
        pods = self.client.list_pods()
        
        findings = []
        total_count = 0
        passed_count = 0

        for pod in pods:
            if self.should_exclude_namespace(pod.metadata.namespace):
                continue

            total_count += 1
            service_account = pod.spec.service_account_name or "default"
            
            if service_account == "default":
                findings.append(
                    Finding(
                        check_id=check_id,
                        check_name=check_name,
                        category=self.get_category(),
                        severity=Severity.WARNING,
                        message=f"Pod '{pod.metadata.name}' uses default service account",
                        resource_type="Pod",
                        resource_namespace=pod.metadata.namespace,
                        resource_name=pod.metadata.name,
                        recommendation="Use dedicated service accounts for each application",
                        remediation="Create a named service account and set spec.serviceAccountName",
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

    def check_clusterrole_wildcards(self) -> CheckResult:
        """Check for wildcard permissions in ClusterRoles."""
        check_id = "RBAC-002"
        check_name = "ClusterRole with Wildcards"
        cluster_roles = self.client.list_cluster_roles()
        
        findings = []
        total_count = 0
        passed_count = 0

        for cluster_role in cluster_roles:
            total_count += 1
            rules = cluster_role.rules or []
            
            has_wildcards = False
            for rule in rules:
                # Check for wildcards in verbs, resources, or apiGroups
                verbs = rule.verbs or []
                resources = rule.resources or []
                api_groups = rule.api_groups or []
                
                if "*" in verbs or "*" in resources or "*" in api_groups:
                    has_wildcards = True
                    break
            
            if has_wildcards:
                findings.append(
                    Finding(
                        check_id=check_id,
                        check_name=check_name,
                        category=self.get_category(),
                        severity=Severity.CRITICAL,
                        message=f"ClusterRole '{cluster_role.metadata.name}' uses wildcard permissions",
                        resource_type="ClusterRole",
                        resource_namespace=None,
                        resource_name=cluster_role.metadata.name,
                        recommendation="Replace wildcard permissions with specific verbs, resources, and apiGroups",
                        remediation="List specific permissions instead of using '*' wildcards",
                        references=["https://kubernetes.io/docs/reference/access-authn-authz/rbac/#role-and-clusterrole"],
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

    def check_clusteradmin_bindings(self) -> CheckResult:
        """Check for ClusterAdmin bindings."""
        check_id = "RBAC-003"
        check_name = "ClusterAdmin Bindings"
        cluster_role_bindings = self.client.list_cluster_role_bindings()
        
        findings = []
        total_count = 0
        passed_count = 0

        for crb in cluster_role_bindings:
            total_count += 1
            role_ref = crb.role_ref
            
            if role_ref and role_ref.name == "cluster-admin":
                # Get subjects
                subjects = crb.subjects or []
                subject_names = [f"{s.kind}/{s.name}" if hasattr(s, 'name') else str(s) for s in subjects]
                
                findings.append(
                    Finding(
                        check_id=check_id,
                        check_name=check_name,
                        category=self.get_category(),
                        severity=Severity.CRITICAL,
                        message=f"ClusterRoleBinding '{crb.metadata.name}' grants cluster-admin to: {', '.join(subject_names[:5])}",
                        resource_type="ClusterRoleBinding",
                        resource_namespace=None,
                        resource_name=crb.metadata.name,
                        details={"subjects": subject_names},
                        recommendation="Review and restrict cluster-admin bindings to absolute minimum",
                        remediation="Replace cluster-admin with more restrictive ClusterRole with least privilege",
                        references=["https://kubernetes.io/docs/reference/access-authn-authz/rbac/#default-roles-and-role-bindings"],
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

    def check_role_binding_best_practices(self) -> CheckResult:
        """Check for best practices in RoleBindings."""
        check_id = "RBAC-004"
        check_name = "Role Binding Best Practices"
        role_bindings = self.client.list_role_bindings()
        
        findings = []
        total_count = 0
        passed_count = 0

        for rb in role_bindings:
            total_count += 1
            subjects = rb.subjects or []
            
            # Check if any subject is a ServiceAccount without namespace specified
            issues = []
            for subject in subjects:
                if hasattr(subject, 'kind') and subject.kind == "ServiceAccount":
                    if not hasattr(subject, 'namespace') or not subject.namespace:
                        issues.append(f"ServiceAccount {subject.name} missing namespace")
            
            if issues:
                findings.append(
                    Finding(
                        check_id=check_id,
                        check_name=check_name,
                        category=self.get_category(),
                        severity=Severity.WARNING,
                        message=f"RoleBinding '{rb.metadata.name}' has subjects with missing namespace: {', '.join(issues[:3])}",
                        resource_type="RoleBinding",
                        resource_namespace=rb.metadata.namespace,
                        resource_name=rb.metadata.name,
                        details={"issues": issues},
                        recommendation="Always specify namespace for ServiceAccount subjects in RoleBindings",
                        remediation="Add namespace field to ServiceAccount subjects",
                        references=["https://kubernetes.io/docs/reference/access-authn-authz/rbac/#rolebinding-and-clusterrolebinding"],
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

    def check_service_account_permissions(self) -> CheckResult:
        """Check service account permissions."""
        check_id = "RBAC-005"
        check_name = "Service Account Permissions"
        service_accounts = self.client.list_service_accounts()
        cluster_role_bindings = self.client.list_cluster_role_bindings()
        role_bindings = self.client.list_role_bindings()
        
        # Build a map of service accounts and their bindings
        sa_bindings = {}
        for crb in cluster_role_bindings:
            for subject in crb.subjects or []:
                if hasattr(subject, 'kind') and subject.kind == "ServiceAccount":
                    sa_name = f"{subject.namespace}/{subject.name}" if hasattr(subject, 'namespace') and subject.namespace else subject.name
                    if sa_name not in sa_bindings:
                        sa_bindings[sa_name] = []
                    sa_bindings[sa_name].append(("ClusterRole", crb.role_ref.name))
        
        for rb in role_bindings:
            for subject in rb.subjects or []:
                if hasattr(subject, 'kind') and subject.kind == "ServiceAccount":
                    ns = subject.namespace if hasattr(subject, 'namespace') and subject.namespace else rb.metadata.namespace
                    sa_name = f"{ns}/{subject.name}"
                    if sa_name not in sa_bindings:
                        sa_bindings[sa_name] = []
                    sa_bindings[sa_name].append(("Role", rb.role_ref.name))
        
        findings = []
        total_count = 0
        passed_count = 0

        for sa in service_accounts:
            sa_name = f"{sa.metadata.namespace}/{sa.metadata.name}"
            if self.should_exclude_namespace(sa.metadata.namespace):
                continue
            
            # Only check non-default service accounts
            if sa.metadata.name == "default":
                continue
            
            total_count += 1
            bindings = sa_bindings.get(sa_name, [])
            
            # Check if service account has cluster-admin
            has_cluster_admin = any(role_type == "ClusterRole" and role_name == "cluster-admin" 
                                   for role_type, role_name in bindings)
            
            if has_cluster_admin:
                findings.append(
                    Finding(
                        check_id=check_id,
                        check_name=check_name,
                        category=self.get_category(),
                        severity=Severity.CRITICAL,
                        message=f"ServiceAccount '{sa_name}' has cluster-admin permissions",
                        resource_type="ServiceAccount",
                        resource_namespace=sa.metadata.namespace,
                        resource_name=sa.metadata.name,
                        details={"bindings": [f"{t}/{n}" for t, n in bindings]},
                        recommendation="Remove cluster-admin permissions and use least privilege",
                        remediation="Update ClusterRoleBinding to use a more restrictive ClusterRole",
                        references=["https://kubernetes.io/docs/reference/access-authn-authz/rbac/#default-roles-and-role-bindings"],
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
