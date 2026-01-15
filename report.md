# Kubernetes Best Practices Compliance Report

**Generated**: 2026-01-15 22:14:38 UTC
**Scan Duration**: 0.47 seconds

---

## Executive Summary

### Compliance Overview
- **Overall Compliance Score**: 81.0%
- **Total Resources Audited**: 174
- **Critical Issues Found**: 17
- **Warning Issues Found**: 7
- **Passing Checks**: 141

### Risk Assessment
- **Security Risk Level**: Low ✅
- **Overall Risk Level**: Low ✅

### Key Findings
- 1 critical issue(s) in Security Best Practices
- 3 critical issue(s) in Resource Management
- 2 critical issue(s) in Network Security
- 4 critical issue(s) in RBAC & Access Control

### Priority Actions Required
1. **[CRITICAL]** Root Users: Container 'local-path-provisioner' in pod 'local-path-provisioner-57c5987fd4-mfvmz' may be running a...
2. **[CRITICAL]** CPU Requests: Container 'local-path-provisioner' in pod 'local-path-provisioner-57c5987fd4-mfvmz' has no CPU reque...
3. **[CRITICAL]** Memory Requests: Container 'local-path-provisioner' in pod 'local-path-provisioner-57c5987fd4-mfvmz' has no memory re...
4. **[CRITICAL]** Memory Limits: Container 'local-path-provisioner' in pod 'local-path-provisioner-57c5987fd4-mfvmz' has no memory li...
5. **[CRITICAL]** Network Policies: Namespace 'default' has no network policies...

---

## Cluster Information

### Cluster Metadata
- **Kubernetes Version**: unknown
- **Node Count**: 0

### Cluster Resources
- **Namespaces**: 5
  - System: 3
  - Application: 2
- **Total Pods**: 9
- **Total Deployments**: 2
- **Total Services**: 2

---

## Overall Compliance Score

### Score Breakdown

Compliance Score: 81.0% ████████████████░░░░

By Severity:
  ✓ Pass:    141 checks (81.0%)
  ⚠ Warning: 7 checks (4.0%)
  ✗ Critical: 17 checks (9.8%)

---

## Compliance by Category

| Category | Compliance | Critical | Warning | Pass | Total | Status |
|----------|------------|----------|---------|------|-------|--------|
| Security Best Practices | 67% | 1 | 2 | 10 | 15 | ⚠️ Needs Attention |
| Resource Management | 0% | 3 | 3 | 0 | 8 | ❌ Critical |
| Pod Configuration | 80% | 0 | 1 | 4 | 5 | ✅ Good |
| Network Security | 33% | 2 | 0 | 1 | 3 | ❌ Critical |
| RBAC & Access Control | 92% | 11 | 0 | 124 | 135 | ✅ Excellent |
| Deployment & Availability | 50% | 0 | 1 | 1 | 2 | ❌ Critical |
| Storage | 100% | 0 | 0 | 1 | 1 | ✅ Excellent |
| Admission Controllers & Policies | 0% | 0 | 0 | 0 | 1 | ❌ Critical |
| Namespace Management | 0% | 0 | 0 | 0 | 4 | ❌ Critical |

---

## Critical Findings

### Severity Definitions
- **CRITICAL**: Security vulnerabilities, compliance violations, or issues that pose immediate risk
- **WARNING**: Best practice violations that should be addressed but don't pose immediate risk
- **INFO**: Informational findings or recommendations for improvement

### Top Critical Issues

#### 1. [CRITICAL] Root Users
**Category**: Security Best Practices
**Severity**: CRITICAL
**Affected Resources**: 1 resource(s)
**Impact**: Container 'local-path-provisioner' in pod 'local-path-provisioner-57c5987fd4-mfvmz' may be running as root

**Affected Resources**:
- `local-path-storage/local-path-provisioner-57c5987fd4-mfvmz`

**Recommendation**: Set runAsNonRoot: true and specify a non-zero runAsUser

**Remediation**: Set securityContext.runAsNonRoot: true and securityContext.runAsUser: <non-zero-uid>

---

#### 2. [CRITICAL] CPU Requests
**Category**: Resource Management
**Severity**: CRITICAL
**Affected Resources**: 1 resource(s)
**Impact**: Container 'local-path-provisioner' in pod 'local-path-provisioner-57c5987fd4-mfvmz' has no CPU request

**Affected Resources**:
- `local-path-storage/local-path-provisioner-57c5987fd4-mfvmz`

**Recommendation**: Set CPU requests for all containers to enable proper scheduling

**Remediation**: Add resources.requests.cpu to container spec

---

#### 3. [CRITICAL] Memory Requests
**Category**: Resource Management
**Severity**: CRITICAL
**Affected Resources**: 1 resource(s)
**Impact**: Container 'local-path-provisioner' in pod 'local-path-provisioner-57c5987fd4-mfvmz' has no memory request

**Affected Resources**:
- `local-path-storage/local-path-provisioner-57c5987fd4-mfvmz`

**Recommendation**: Set memory requests for all containers to enable proper scheduling

**Remediation**: Add resources.requests.memory to container spec

---

#### 4. [CRITICAL] Memory Limits
**Category**: Resource Management
**Severity**: CRITICAL
**Affected Resources**: 1 resource(s)
**Impact**: Container 'local-path-provisioner' in pod 'local-path-provisioner-57c5987fd4-mfvmz' has no memory limit

**Affected Resources**:
- `local-path-storage/local-path-provisioner-57c5987fd4-mfvmz`

**Recommendation**: Set memory limits to prevent OOM kills

**Remediation**: Add resources.limits.memory to container spec

---

#### 5. [CRITICAL] Network Policies
**Category**: Network Security
**Severity**: CRITICAL
**Affected Resources**: 2 resource(s)
**Impact**: Namespace 'default' has no network policies

**Affected Resources**:
- `default/default`
- `default/local-path-storage`

**Recommendation**: Implement NetworkPolicy resources with default deny-all and explicit allow rules

**Remediation**: Create NetworkPolicy resources to restrict pod-to-pod communication

---

#### 6. [CRITICAL] ClusterRole with Wildcards
**Category**: RBAC & Access Control
**Severity**: CRITICAL
**Affected Resources**: 9 resource(s)
**Impact**: ClusterRole 'cluster-admin' uses wildcard permissions

**Affected Resources**:
- `default/cluster-admin`
- `default/local-path-provisioner-role`
- `default/system:controller:disruption-controller`
- `default/system:controller:generic-garbage-collector`
- `default/system:controller:horizontal-pod-autoscaler`
- `default/system:controller:namespace-controller`
- `default/system:controller:resourcequota-controller`
- `default/system:kube-controller-manager`
- `default/system:kubelet-api-admin`

**Recommendation**: Replace wildcard permissions with specific verbs, resources, and apiGroups

**Remediation**: List specific permissions instead of using '*' wildcards

---

#### 7. [CRITICAL] ClusterAdmin Bindings
**Category**: RBAC & Access Control
**Severity**: CRITICAL
**Affected Resources**: 2 resource(s)
**Impact**: ClusterRoleBinding 'cluster-admin' grants cluster-admin to: Group/system:masters

**Affected Resources**:
- `default/cluster-admin`
- `default/kubeadm:cluster-admins`

**Recommendation**: Review and restrict cluster-admin bindings to absolute minimum

**Remediation**: Replace cluster-admin with more restrictive ClusterRole with least privilege

---

## Findings by Category

### Security Best Practices

**Overall Compliance**: 66.7% (10/15 checks passed)

#### Root Users
**Status**: ❌ 1 issue(s) found
**Compliance**: 0.0% (0/1)

- **CRITICAL**: `local-path-storage/local-path-provisioner-57c5987fd4-mfvmz` - Container 'local-path-provisioner' in pod 'local-path-provisioner-57c5987fd4-mfvmz' may be running as root

#### Read-Only Root Filesystem
**Status**: ⚠️ 1 issue(s) found
**Compliance**: 0.0% (0/1)

- **INFO**: `local-path-storage/local-path-provisioner-57c5987fd4-mfvmz` - Container 'local-path-provisioner' in pod 'local-path-provisioner-57c5987fd4-mfvmz' does not use read-only root filesystem

#### Pod Security Standards
**Status**: ⚠️ 2 issue(s) found
**Compliance**: 0.0% (0/2)

- **WARNING**: `default/default` - Namespace 'default' has no Pod Security Standards enforcement
- **WARNING**: `default/local-path-storage` - Namespace 'local-path-storage' has no Pod Security Standards enforcement

#### Seccomp Profile
**Status**: ⚠️ 1 issue(s) found
**Compliance**: 0.0% (0/1)

- **INFO**: `local-path-storage/local-path-provisioner-57c5987fd4-mfvmz` - Pod 'local-path-provisioner-57c5987fd4-mfvmz' has no seccomp profile configured

---

### Resource Management

**Overall Compliance**: 0.0% (0/8 checks passed)

#### CPU Requests
**Status**: ❌ 1 issue(s) found
**Compliance**: 0.0% (0/1)

- **CRITICAL**: `local-path-storage/local-path-provisioner-57c5987fd4-mfvmz` - Container 'local-path-provisioner' in pod 'local-path-provisioner-57c5987fd4-mfvmz' has no CPU request

#### Memory Requests
**Status**: ❌ 1 issue(s) found
**Compliance**: 0.0% (0/1)

- **CRITICAL**: `local-path-storage/local-path-provisioner-57c5987fd4-mfvmz` - Container 'local-path-provisioner' in pod 'local-path-provisioner-57c5987fd4-mfvmz' has no memory request

#### CPU Limits
**Status**: ⚠️ 1 issue(s) found
**Compliance**: 0.0% (0/1)

- **WARNING**: `local-path-storage/local-path-provisioner-57c5987fd4-mfvmz` - Container 'local-path-provisioner' in pod 'local-path-provisioner-57c5987fd4-mfvmz' has no CPU limit

#### Memory Limits
**Status**: ❌ 1 issue(s) found
**Compliance**: 0.0% (0/1)

- **CRITICAL**: `local-path-storage/local-path-provisioner-57c5987fd4-mfvmz` - Container 'local-path-provisioner' in pod 'local-path-provisioner-57c5987fd4-mfvmz' has no memory limit

#### Resource Quotas
**Status**: ⚠️ 2 issue(s) found
**Compliance**: 0.0% (0/2)

- **WARNING**: `default/default` - Namespace 'default' has no resource quotas
- **WARNING**: `default/local-path-storage` - Namespace 'local-path-storage' has no resource quotas

#### Limit Ranges
**Status**: ⚠️ 2 issue(s) found
**Compliance**: 0.0% (0/2)

- **INFO**: `default/default` - Namespace 'default' has no limit ranges
- **INFO**: `default/local-path-storage` - Namespace 'local-path-storage' has no limit ranges

---

### Pod Configuration

**Overall Compliance**: 80.0% (4/5 checks passed)

#### Health Checks
**Status**: ⚠️ 1 issue(s) found
**Compliance**: 0.0% (0/1)

- **WARNING**: `local-path-storage/local-path-provisioner-57c5987fd4-mfvmz` - Container 'local-path-provisioner' in pod 'local-path-provisioner-57c5987fd4-mfvmz' has no health check probes

---

### Network Security

**Overall Compliance**: 33.3% (1/3 checks passed)

#### Network Policies
**Status**: ❌ 2 issue(s) found
**Compliance**: 0.0% (0/2)

- **CRITICAL**: `default/default` - Namespace 'default' has no network policies
- **CRITICAL**: `default/local-path-storage` - Namespace 'local-path-storage' has no network policies

---

### RBAC & Access Control

**Overall Compliance**: 91.9% (124/135 checks passed)

#### ClusterRole with Wildcards
**Status**: ❌ 9 issue(s) found
**Compliance**: 86.8% (59/68)

- **CRITICAL**: `default/cluster-admin` - ClusterRole 'cluster-admin' uses wildcard permissions
- **CRITICAL**: `default/local-path-provisioner-role` - ClusterRole 'local-path-provisioner-role' uses wildcard permissions
- **CRITICAL**: `default/system:controller:disruption-controller` - ClusterRole 'system:controller:disruption-controller' uses wildcard permissions
- **CRITICAL**: `default/system:controller:generic-garbage-collector` - ClusterRole 'system:controller:generic-garbage-collector' uses wildcard permissions
- **CRITICAL**: `default/system:controller:horizontal-pod-autoscaler` - ClusterRole 'system:controller:horizontal-pod-autoscaler' uses wildcard permissions
- ... (4 more)

#### ClusterAdmin Bindings
**Status**: ❌ 2 issue(s) found
**Compliance**: 96.3% (52/54)

- **CRITICAL**: `default/cluster-admin` - ClusterRoleBinding 'cluster-admin' grants cluster-admin to: Group/system:masters
- **CRITICAL**: `default/kubeadm:cluster-admins` - ClusterRoleBinding 'kubeadm:cluster-admins' grants cluster-admin to: Group/kubeadm:cluster-admins

---

### Deployment & Availability

**Overall Compliance**: 50.0% (1/2 checks passed)

#### Replica Counts
**Status**: ⚠️ 1 issue(s) found
**Compliance**: 0.0% (0/1)

- **WARNING**: `local-path-storage/local-path-provisioner` - Deployment 'local-path-provisioner' has only 1 replica(s)

---

### Storage

**Overall Compliance**: 100.0% (1/1 checks passed)

---

### Admission Controllers & Policies

**Overall Compliance**: 0.0% (0/1 checks passed)

#### Validating Admission Webhooks
**Status**: ⚠️ 1 issue(s) found
**Compliance**: 0.0% (0/1)

- **INFO**: `default/None` - No validating admission webhooks found

---

### Namespace Management

**Overall Compliance**: 0.0% (0/4 checks passed)

#### Namespace Labels
**Status**: ⚠️ 2 issue(s) found
**Compliance**: 0.0% (0/2)

- **INFO**: `default/default` - Namespace 'default' is missing recommended labels
- **INFO**: `default/local-path-storage` - Namespace 'local-path-storage' is missing recommended labels

#### Namespace Annotations
**Status**: ⚠️ 2 issue(s) found
**Compliance**: 0.0% (0/2)

- **INFO**: `default/default` - Namespace 'default' has no Pod Security Standards annotations
- **INFO**: `default/local-path-storage` - Namespace 'local-path-storage' has no Pod Security Standards annotations

---

## Recommendations

### Priority 1: Critical Security Issues (Fix within 1 week)

#### 1. Root Users
**Priority**: P1 - Critical
**Effort**: Medium
**Impact**: High
**Category**: Security Best Practices

**Action Items**:
1. Fix 1 affected resource(s)
2. Set runAsNonRoot: true and specify a non-zero runAsUser

**Remediation**: Set securityContext.runAsNonRoot: true and securityContext.runAsUser: <non-zero-uid>

#### 2. CPU Requests
**Priority**: P1 - Critical
**Effort**: Medium
**Impact**: High
**Category**: Resource Management

**Action Items**:
1. Fix 1 affected resource(s)
2. Set CPU requests for all containers to enable proper scheduling

**Remediation**: Add resources.requests.cpu to container spec

#### 3. Memory Requests
**Priority**: P1 - Critical
**Effort**: Medium
**Impact**: High
**Category**: Resource Management

**Action Items**:
1. Fix 1 affected resource(s)
2. Set memory requests for all containers to enable proper scheduling

**Remediation**: Add resources.requests.memory to container spec

#### 4. Memory Limits
**Priority**: P1 - Critical
**Effort**: Medium
**Impact**: High
**Category**: Resource Management

**Action Items**:
1. Fix 1 affected resource(s)
2. Set memory limits to prevent OOM kills

**Remediation**: Add resources.limits.memory to container spec

#### 5. Network Policies
**Priority**: P1 - Critical
**Effort**: Medium
**Impact**: High
**Category**: Network Security

**Action Items**:
1. Fix 2 affected resource(s)
2. Implement NetworkPolicy resources with default deny-all and explicit allow rules

**Remediation**: Create NetworkPolicy resources to restrict pod-to-pod communication

### Priority 2: Important Best Practices (Fix within 1 month)

#### 1. Pod Security Standards
**Priority**: P2 - Important
**Affected Resources**: 2
**Recommendation**: Enable Pod Security Standards with enforce mode set to baseline or restricted

#### 2. CPU Limits
**Priority**: P2 - Important
**Affected Resources**: 1
**Recommendation**: Set CPU limits to prevent resource exhaustion

#### 3. Resource Quotas
**Priority**: P2 - Important
**Affected Resources**: 2
**Recommendation**: Create ResourceQuota to limit resource consumption per namespace

#### 4. Health Checks
**Priority**: P2 - Important
**Affected Resources**: 1
**Recommendation**: Add liveness and readiness probes to detect and handle unhealthy containers

#### 5. Replica Counts
**Priority**: P2 - Important
**Affected Resources**: 1
**Recommendation**: Use at least 2 replicas for production workloads for high availability

---

## Appendix

### Report Metadata
- **Generated By**: kubebaseline v1.0.0
- **Report Version**: 1.0
- **Generation Time**: 0.47 seconds
- **Kubernetes Version**: unknown
- **Report Format**: Markdown

### Excluded Namespaces
- `kube-public`
- `kube-node-lease`
- `kube-system`

### References
- [Kubernetes Documentation](https://kubernetes.io/docs/)
- [Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [Network Policies](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
