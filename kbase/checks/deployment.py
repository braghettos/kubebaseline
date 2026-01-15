"""Deployment and availability checks."""

from typing import List
from kbase.checks.base import BaseCheck
from kbase.models import CheckResult, Finding, Severity


class DeploymentChecks(BaseCheck):
    """Deployment and availability checks."""

    def get_category(self) -> str:
        return "Deployment & Availability"

    def run_all_checks(self) -> List[CheckResult]:
        """Run all deployment checks."""
        return [
            self.check_replica_counts(),
            self.check_pod_disruption_budgets(),
            self.check_deployment_strategy(),
            self.check_statefulset_update_strategy(),
        ]

    def check_replica_counts(self) -> CheckResult:
        """Check for appropriate replica counts."""
        check_id = "DEP-001"
        check_name = "Replica Counts"
        deployments = self.client.list_deployments()
        statefulsets = self.client.list_statefulsets()
        
        findings = []
        total_count = 0
        passed_count = 0

        # Check deployments
        for dep in deployments:
            if self.should_exclude_namespace(dep.metadata.namespace):
                continue

            total_count += 1
            replicas = dep.spec.replicas if dep.spec.replicas is not None else 1
            
            if replicas < 2:
                findings.append(
                    Finding(
                        check_id=check_id,
                        check_name=check_name,
                        category=self.get_category(),
                        severity=Severity.WARNING,
                        message=f"Deployment '{dep.metadata.name}' has only {replicas} replica(s)",
                        resource_type="Deployment",
                        resource_namespace=dep.metadata.namespace,
                        resource_name=dep.metadata.name,
                        details={"replicas": replicas},
                        recommendation="Use at least 2 replicas for production workloads for high availability",
                        remediation="Set spec.replicas to at least 2",
                        references=["https://kubernetes.io/docs/concepts/workloads/controllers/deployment/"],
                    )
                )
            else:
                passed_count += 1

        # Check statefulsets
        for sts in statefulsets:
            if self.should_exclude_namespace(sts.metadata.namespace):
                continue

            total_count += 1
            replicas = sts.spec.replicas if sts.spec.replicas is not None else 1
            
            if replicas < 2:
                findings.append(
                    Finding(
                        check_id=check_id,
                        check_name=check_name,
                        category=self.get_category(),
                        severity=Severity.WARNING,
                        message=f"StatefulSet '{sts.metadata.name}' has only {replicas} replica(s)",
                        resource_type="StatefulSet",
                        resource_namespace=sts.metadata.namespace,
                        resource_name=sts.metadata.name,
                        details={"replicas": replicas},
                        recommendation="Use at least 2 replicas for production workloads for high availability",
                        remediation="Set spec.replicas to at least 2",
                        references=["https://kubernetes.io/docs/concepts/workloads/controllers/statefulset/"],
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

    def check_pod_disruption_budgets(self) -> CheckResult:
        """Check for Pod Disruption Budgets on deployments."""
        check_id = "DEP-002"
        check_name = "Pod Disruption Budgets"
        deployments = self.client.list_deployments()
        statefulsets = self.client.list_statefulsets()
        pdbs = self.client.list_pod_disruption_budgets()
        
        # Build a set of selectors from PDBs
        pdb_selectors = set()
        for pdb in pdbs:
            if pdb.spec and pdb.spec.selector:
                # Convert selector to a string representation for matching
                match_labels = pdb.spec.selector.match_labels or {}
                selector_str = ",".join(f"{k}={v}" for k, v in sorted(match_labels.items()))
                pdb_selectors.add((pdb.metadata.namespace, selector_str))
        
        findings = []
        total_count = 0
        passed_count = 0

        # Check deployments
        for dep in deployments:
            if self.should_exclude_namespace(dep.metadata.namespace):
                continue
            
            # Skip if only 1 replica
            if dep.spec.replicas and dep.spec.replicas < 2:
                continue

            total_count += 1
            match_labels = dep.spec.selector.match_labels or {}
            selector_str = ",".join(f"{k}={v}" for k, v in sorted(match_labels.items()))
            
            has_pdb = (dep.metadata.namespace, selector_str) in pdb_selectors
            
            if not has_pdb:
                findings.append(
                    Finding(
                        check_id=check_id,
                        check_name=check_name,
                        category=self.get_category(),
                        severity=Severity.WARNING,
                        message=f"Deployment '{dep.metadata.name}' has no Pod Disruption Budget",
                        resource_type="Deployment",
                        resource_namespace=dep.metadata.namespace,
                        resource_name=dep.metadata.name,
                        recommendation="Create PodDisruptionBudget to ensure availability during voluntary disruptions",
                        remediation="Create a PodDisruptionBudget resource matching the deployment's selector",
                        references=["https://kubernetes.io/docs/concepts/workloads/pods/disruptions/"],
                    )
                )
            else:
                passed_count += 1

        # Check statefulsets
        for sts in statefulsets:
            if self.should_exclude_namespace(sts.metadata.namespace):
                continue
            
            # Skip if only 1 replica
            if sts.spec.replicas and sts.spec.replicas < 2:
                continue

            total_count += 1
            match_labels = sts.spec.selector.match_labels or {}
            selector_str = ",".join(f"{k}={v}" for k, v in sorted(match_labels.items()))
            
            has_pdb = (sts.metadata.namespace, selector_str) in pdb_selectors
            
            if not has_pdb:
                findings.append(
                    Finding(
                        check_id=check_id,
                        check_name=check_name,
                        category=self.get_category(),
                        severity=Severity.WARNING,
                        message=f"StatefulSet '{sts.metadata.name}' has no Pod Disruption Budget",
                        resource_type="StatefulSet",
                        resource_namespace=sts.metadata.namespace,
                        resource_name=sts.metadata.name,
                        recommendation="Create PodDisruptionBudget to ensure availability during voluntary disruptions",
                        remediation="Create a PodDisruptionBudget resource matching the statefulset's selector",
                        references=["https://kubernetes.io/docs/concepts/workloads/pods/disruptions/"],
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

    def check_deployment_strategy(self) -> CheckResult:
        """Check deployment update strategy."""
        check_id = "DEP-003"
        check_name = "Deployment Strategy"
        deployments = self.client.list_deployments()
        
        findings = []
        total_count = 0
        passed_count = 0

        for dep in deployments:
            if self.should_exclude_namespace(dep.metadata.namespace):
                continue

            total_count += 1
            strategy = dep.spec.strategy
            strategy_type = strategy.type if strategy else "RollingUpdate"
            
            if strategy_type == "Recreate":
                findings.append(
                    Finding(
                        check_id=check_id,
                        check_name=check_name,
                        category=self.get_category(),
                        severity=Severity.WARNING,
                        message=f"Deployment '{dep.metadata.name}' uses Recreate strategy (causes downtime)",
                        resource_type="Deployment",
                        resource_namespace=dep.metadata.namespace,
                        resource_name=dep.metadata.name,
                        details={"strategy": strategy_type},
                        recommendation="Use RollingUpdate strategy to avoid downtime during updates",
                        remediation="Change spec.strategy.type to RollingUpdate",
                        references=["https://kubernetes.io/docs/concepts/workloads/controllers/deployment/#strategy"],
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

    def check_statefulset_update_strategy(self) -> CheckResult:
        """Check StatefulSet update strategy."""
        check_id = "DEP-004"
        check_name = "StatefulSet Update Strategy"
        statefulsets = self.client.list_statefulsets()
        
        findings = []
        total_count = 0
        passed_count = 0

        for sts in statefulsets:
            if self.should_exclude_namespace(sts.metadata.namespace):
                continue

            total_count += 1
            update_strategy = sts.spec.update_strategy
            strategy_type = update_strategy.type if update_strategy else "RollingUpdate"
            
            # OnDelete strategy can be used for manual control, but RollingUpdate is recommended
            if strategy_type == "OnDelete":
                findings.append(
                    Finding(
                        check_id=check_id,
                        check_name=check_name,
                        category=self.get_category(),
                        severity=Severity.INFO,
                        message=f"StatefulSet '{sts.metadata.name}' uses OnDelete update strategy",
                        resource_type="StatefulSet",
                        resource_namespace=sts.metadata.namespace,
                        resource_name=sts.metadata.name,
                        details={"strategy": strategy_type},
                        recommendation="Consider using RollingUpdate strategy for automatic updates",
                        remediation="Change spec.updateStrategy.type to RollingUpdate",
                        references=["https://kubernetes.io/docs/concepts/workloads/controllers/statefulset/#update-strategies"],
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