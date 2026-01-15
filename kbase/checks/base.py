"""Base class for all checks."""

from abc import ABC, abstractmethod
from typing import List
from kbase.client import KubernetesClient
from kbase.models import CheckResult


class BaseCheck(ABC):
    """Base class for all compliance checks."""

    def __init__(self, client: KubernetesClient, excluded_namespaces: List[str] = None):
        """Initialize check.
        
        Args:
            client: Kubernetes API client
            excluded_namespaces: List of namespaces to exclude from checks
        """
        self.client = client
        self.excluded_namespaces = excluded_namespaces or [
            "kube-system",
            "kube-public",
            "kube-node-lease",
        ]

    def should_exclude_namespace(self, namespace: str) -> bool:
        """Check if namespace should be excluded."""
        return namespace in self.excluded_namespaces

    @abstractmethod
    def get_category(self) -> str:
        """Get the category name for this check."""
        pass

    @abstractmethod
    def run_all_checks(self) -> List[CheckResult]:
        """Run all checks in this category."""
        pass
