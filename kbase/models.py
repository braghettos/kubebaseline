"""Data models for checks and findings."""

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Dict, Any
from datetime import datetime


class Severity(Enum):
    """Severity levels for findings."""

    CRITICAL = "critical"
    WARNING = "warning"
    INFO = "info"
    PASS = "pass"


@dataclass
class Finding:
    """A single compliance finding."""

    check_id: str
    check_name: str
    category: str
    severity: Severity
    message: str
    resource_type: str
    resource_namespace: Optional[str]
    resource_name: str
    details: Dict[str, Any] = field(default_factory=dict)
    recommendation: Optional[str] = None
    remediation: Optional[str] = None
    references: List[str] = field(default_factory=list)

    def __post_init__(self):
        """Validate finding."""
        if self.severity not in Severity:
            raise ValueError(f"Invalid severity: {self.severity}")


@dataclass
class CheckResult:
    """Result of a single check."""

    check_id: str
    check_name: str
    category: str
    passed: bool
    findings: List[Finding] = field(default_factory=list)
    resource_count: int = 0
    passed_count: int = 0
    failed_count: int = 0

    @property
    def compliance_percentage(self) -> float:
        """Calculate compliance percentage."""
        if self.resource_count == 0:
            return 100.0
        return (self.passed_count / self.resource_count) * 100.0


@dataclass
class CategoryResult:
    """Results for a category of checks."""

    category: str
    checks: List[CheckResult] = field(default_factory=list)
    total_resources: int = 0
    total_passed: int = 0
    total_failed: int = 0
    total_warnings: int = 0
    total_critical: int = 0

    @property
    def compliance_percentage(self) -> float:
        """Calculate category compliance percentage."""
        total_checks = sum(c.resource_count for c in self.checks)
        if total_checks == 0:
            return 100.0
        passed_checks = sum(c.passed_count for c in self.checks)
        return (passed_checks / total_checks) * 100.0


@dataclass
class ScanResult:
    """Complete scan results."""

    cluster_info: Dict[str, Any]
    scan_date: datetime
    scan_duration: float
    categories: List[CategoryResult] = field(default_factory=list)
    all_findings: List[Finding] = field(default_factory=list)
    excluded_namespaces: List[str] = field(default_factory=list)

    @property
    def total_resources(self) -> int:
        """Total number of resources checked."""
        return sum(c.total_resources for c in self.categories)

    @property
    def total_passed(self) -> int:
        """Total number of passed checks."""
        return sum(c.total_passed for c in self.categories)

    @property
    def total_failed(self) -> int:
        """Total number of failed checks."""
        return sum(c.total_failed for c in self.categories)

    @property
    def total_warnings(self) -> int:
        """Total number of warning findings."""
        return sum(c.total_warnings for c in self.categories)

    @property
    def total_critical(self) -> int:
        """Total number of critical findings."""
        return sum(c.total_critical for c in self.categories)

    @property
    def overall_compliance(self) -> float:
        """Overall compliance percentage."""
        if self.total_resources == 0:
            return 100.0
        return (self.total_passed / self.total_resources) * 100.0

    def get_critical_findings(self) -> List[Finding]:
        """Get all critical findings."""
        return [f for f in self.all_findings if f.severity == Severity.CRITICAL]

    def get_warning_findings(self) -> List[Finding]:
        """Get all warning findings."""
        return [f for f in self.all_findings if f.severity == Severity.WARNING]

    def get_findings_by_category(self, category: str) -> List[Finding]:
        """Get findings for a specific category."""
        return [f for f in self.all_findings if f.category == category]
