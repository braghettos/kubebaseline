"""Admission controller checks."""

from typing import List
from kbase.checks.base import BaseCheck
from kbase.models import CheckResult, Finding, Severity


class AdmissionChecks(BaseCheck):
    """Admission controller checks."""

    def get_category(self) -> str:
        return "Admission Controllers & Policies"

    def run_all_checks(self) -> List[CheckResult]:
        """Run all admission checks."""
        return [
            self.check_validating_admission_webhooks(),
            self.check_mutating_admission_webhooks(),
        ]

    def check_validating_admission_webhooks(self) -> CheckResult:
        """Check for validating admission webhooks."""
        check_id = "ADM-001"
        check_name = "Validating Admission Webhooks"
        
        try:
            webhooks = self.client.admissionregistration_v1.list_validating_webhook_configuration().items
        except Exception:
            # API might not be available
            return CheckResult(
                check_id=check_id,
                check_name=check_name,
                category=self.get_category(),
                passed=True,
                findings=[],
                resource_count=0,
                passed_count=0,
                failed_count=0,
            )
        
        findings = []
        total_count = len(webhooks)
        passed_count = 0

        for webhook_config in webhooks:
            webhooks_list = webhook_config.webhooks or []
            
            for webhook in webhooks_list:
                # Check for failure policy
                failure_policy = webhook.failure_policy
                
                # Fail or Ignore are both valid, but Fail is recommended for security policies
                if failure_policy == "Ignore":
                    findings.append(
                        Finding(
                            check_id=check_id,
                            check_name=check_name,
                            category=self.get_category(),
                            severity=Severity.WARNING,
                            message=f"ValidatingWebhookConfiguration '{webhook_config.metadata.name}' has failurePolicy=Ignore",
                            resource_type="ValidatingWebhookConfiguration",
                            resource_namespace=None,
                            resource_name=webhook_config.metadata.name,
                            details={"webhook": webhook.name if hasattr(webhook, 'name') else "unknown", "failure_policy": failure_policy},
                            recommendation="Use failurePolicy=Fail for security-critical validating webhooks",
                            remediation="Set failurePolicy to Fail in ValidatingWebhookConfiguration",
                            references=["https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/#failure-policy"],
                        )
                    )
                else:
                    passed_count += 1

        if total_count == 0:
            # No webhooks found - this is informational
            findings.append(
                Finding(
                    check_id=check_id,
                    check_name=check_name,
                    category=self.get_category(),
                    severity=Severity.INFO,
                    message="No validating admission webhooks found",
                    resource_type="ValidatingWebhookConfiguration",
                    resource_namespace=None,
                    resource_name=None,
                    recommendation="Consider implementing validating admission webhooks for policy enforcement",
                    remediation="Create ValidatingWebhookConfiguration resources for policy validation",
                    references=["https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/"],
                )
            )
            total_count = 1

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

    def check_mutating_admission_webhooks(self) -> CheckResult:
        """Check for mutating admission webhooks."""
        check_id = "ADM-002"
        check_name = "Mutating Admission Webhooks"
        
        try:
            webhooks = self.client.admissionregistration_v1.list_mutating_webhook_configuration().items
        except Exception:
            # API might not be available
            return CheckResult(
                check_id=check_id,
                check_name=check_name,
                category=self.get_category(),
                passed=True,
                findings=[],
                resource_count=0,
                passed_count=0,
                failed_count=0,
            )
        
        findings = []
        total_count = len(webhooks)
        passed_count = 0

        for webhook_config in webhooks:
            webhooks_list = webhook_config.webhooks or []
            
            for webhook in webhooks_list:
                # Check for failure policy
                failure_policy = webhook.failure_policy
                
                # Fail or Ignore are both valid, but Fail is recommended for security policies
                if failure_policy == "Ignore":
                    findings.append(
                        Finding(
                            check_id=check_id,
                            check_name=check_name,
                            category=self.get_category(),
                            severity=Severity.INFO,
                            message=f"MutatingWebhookConfiguration '{webhook_config.metadata.name}' has failurePolicy=Ignore",
                            resource_type="MutatingWebhookConfiguration",
                            resource_namespace=None,
                            resource_name=webhook_config.metadata.name,
                            details={"webhook": webhook.name if hasattr(webhook, 'name') else "unknown", "failure_policy": failure_policy},
                            recommendation="Review failurePolicy - Ignore may allow requests to proceed if webhook fails",
                            remediation="Consider setting failurePolicy to Fail for security-critical mutating webhooks",
                            references=["https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/#failure-policy"],
                        )
                    )
                else:
                    passed_count += 1

        # No findings for missing webhooks - mutating webhooks are optional

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