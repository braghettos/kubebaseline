"""Best practice checks."""

from kbase.checks.base import BaseCheck
from kbase.checks.security import SecurityChecks
from kbase.checks.resources import ResourceManagementChecks
from kbase.checks.pod_config import PodConfigurationChecks
from kbase.checks.network import NetworkSecurityChecks
from kbase.checks.rbac import RBACChecks
from kbase.checks.deployment import DeploymentChecks
from kbase.checks.storage import StorageChecks
from kbase.checks.admission import AdmissionChecks
from kbase.checks.namespace import NamespaceChecks

__all__ = [
    "BaseCheck",
    "SecurityChecks",
    "ResourceManagementChecks",
    "PodConfigurationChecks",
    "NetworkSecurityChecks",
    "RBACChecks",
    "DeploymentChecks",
    "StorageChecks",
    "AdmissionChecks",
    "NamespaceChecks",
]


def get_all_checks():
    """Get all check classes."""
    return [
        SecurityChecks,
        ResourceManagementChecks,
        PodConfigurationChecks,
        NetworkSecurityChecks,
        RBACChecks,
        DeploymentChecks,
        StorageChecks,
        AdmissionChecks,
        NamespaceChecks,
    ]
