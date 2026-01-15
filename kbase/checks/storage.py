"""Storage checks."""

from typing import List
from kbase.checks.base import BaseCheck
from kbase.models import CheckResult, Finding, Severity


class StorageChecks(BaseCheck):
    """Storage checks."""

    def get_category(self) -> str:
        return "Storage"

    def run_all_checks(self) -> List[CheckResult]:
        """Run all storage checks."""
        return [
            self.check_persistent_volume_access_modes(),
            self.check_hostpath_volumes(),
        ]

    def check_persistent_volume_access_modes(self) -> CheckResult:
        """Check for appropriate PersistentVolume access modes."""
        check_id = "STOR-001"
        check_name = "Persistent Volume Access Modes"
        pvs = self.client.list_persistent_volumes()
        
        findings = []
        total_count = 0
        passed_count = 0

        for pv in pvs:
            if pv.status and pv.status.phase == "Available":
                # Only check bound PVs or check all
                total_count += 1
                access_modes = pv.spec.access_modes or []
                
                # ReadWriteMany allows multiple nodes to mount, which can cause issues
                if "ReadWriteMany" in access_modes:
                    findings.append(
                        Finding(
                            check_id=check_id,
                            check_name=check_name,
                            category=self.get_category(),
                            severity=Severity.INFO,
                            message=f"PersistentVolume '{pv.metadata.name}' uses ReadWriteMany access mode",
                            resource_type="PersistentVolume",
                            resource_namespace=None,
                            resource_name=pv.metadata.name,
                            details={"access_modes": access_modes},
                            recommendation="Review ReadWriteMany usage - ensure storage backend supports concurrent access",
                            remediation="Verify storage backend supports ReadWriteMany or use ReadWriteOnce with single pod",
                            references=["https://kubernetes.io/docs/concepts/storage/persistent-volumes/#access-modes"],
                        )
                    )
                elif not access_modes:
                    findings.append(
                        Finding(
                            check_id=check_id,
                            check_name=check_name,
                            category=self.get_category(),
                            severity=Severity.WARNING,
                            message=f"PersistentVolume '{pv.metadata.name}' has no access modes specified",
                            resource_type="PersistentVolume",
                            resource_namespace=None,
                            resource_name=pv.metadata.name,
                            recommendation="Specify appropriate access modes for the PersistentVolume",
                            remediation="Add accessModes to PersistentVolume spec",
                            references=["https://kubernetes.io/docs/concepts/storage/persistent-volumes/#access-modes"],
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

    def check_hostpath_volumes(self) -> CheckResult:
        """Check for hostPath volumes in pods."""
        check_id = "STOR-002"
        check_name = "HostPath Volumes"
        pods = self.client.list_pods()
        
        findings = []
        total_count = 0
        passed_count = 0

        for pod in pods:
            if self.should_exclude_namespace(pod.metadata.namespace):
                continue

            if not pod.spec.volumes:
                continue

            total_count += 1
            hostpath_volumes = []
            
            for volume in pod.spec.volumes:
                if volume.host_path:
                    hostpath_volumes.append(volume.name)
            
            if hostpath_volumes:
                findings.append(
                    Finding(
                        check_id=check_id,
                        check_name=check_name,
                        category=self.get_category(),
                        severity=Severity.CRITICAL,
                        message=f"Pod '{pod.metadata.name}' uses hostPath volumes: {', '.join(hostpath_volumes)}",
                        resource_type="Pod",
                        resource_namespace=pod.metadata.namespace,
                        resource_name=pod.metadata.name,
                        details={"hostpath_volumes": hostpath_volumes},
                        recommendation="Avoid hostPath volumes - use PersistentVolumes instead",
                        remediation="Replace hostPath volumes with PersistentVolumeClaims and PersistentVolumes",
                        references=["https://kubernetes.io/docs/concepts/storage/volumes/#hostpath"],
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