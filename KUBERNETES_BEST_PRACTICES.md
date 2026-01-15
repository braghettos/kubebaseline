# Kubernetes Best Practices - CLI Checks

This document describes the best practice checks implemented in the `kbase` CLI tool. All checks are performed using Kubernetes APIs and query cluster resources to verify compliance with best practices.

## Overview

The `kbase` CLI tool scans your Kubernetes cluster and checks resources against a set of best practices. All checks use only Kubernetes API resources—no external tools or file system access is required.

**Current Implementation:** The tool currently implements **42 checks** across 9 categories. All implemented checks are documented in detail below with their check IDs, severity levels, remediation steps, and API resources used.

## Check Categories

The tool currently implements checks across nine categories (42 total checks):

1. **Security Best Practices** (12 checks) - SEC-001 through SEC-012
2. **Resource Management** (8 checks) - RES-001 through RES-008
3. **Pod Configuration** (5 checks) - POD-001 through POD-005
4. **Network Security** (4 checks) - NET-001 through NET-004
5. **RBAC & Access Control** (5 checks) - RBAC-001 through RBAC-005
6. **Deployment & Availability** (4 checks) - DEP-001 through DEP-004
7. **Storage** (2 checks) - STOR-001 through STOR-002
8. **Admission Controllers & Policies** (2 checks) - ADM-001 through ADM-002
9. **Namespace Management** (2 checks) - NS-001 through NS-002

All checks are fully implemented and can be verified using only Kubernetes APIs.

---

## Security Best Practices

### SEC-001: Privileged Containers

**Check ID:** `SEC-001`  
**Severity:** Critical  
**What it checks:** Verifies that containers are not running with `privileged: true` in their security context.

**How it works:**
- Queries all pods using Kubernetes API (`client.list_pods()`)
- Examines each container's `securityContext.privileged` field
- Allows privileged containers only in `kube-system` namespace
- Flags all other privileged containers as violations

**Remediation:**
```yaml
securityContext:
  privileged: false
```

**Kubernetes API Resources Used:**
- `CoreV1Api.list_pod_for_all_namespaces()` or `list_namespaced_pod()`
- Inspects `Pod.spec.containers[].securityContext.privileged`

**Best Practice Reference:**
- [Kubernetes Pod Security Standards - Restricted Profile](https://kubernetes.io/docs/concepts/security/pod-security-standards/#restricted)
- [CIS Kubernetes Benchmark - 5.2.1](https://www.cisecurity.org/benchmark/kubernetes)

---

### SEC-002: Root Users

**Check ID:** `SEC-002`  
**Severity:** Critical  
**What it checks:** Verifies that containers are not running as root user (UID 0).

**How it works:**
- Queries all pods using Kubernetes API
- Checks `securityContext.runAsUser` and `securityContext.runAsNonRoot` at both pod and container levels
- Flags containers where:
  - `runAsUser` is explicitly set to 0, OR
  - `runAsUser` is not set AND `runAsNonRoot` is not `true` (default behavior runs as root)

**Remediation:**
```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 1000  # Non-zero UID
```

**Kubernetes API Resources Used:**
- `CoreV1Api.list_pod_for_all_namespaces()`
- Inspects `Pod.spec.securityContext` and `Pod.spec.containers[].securityContext`

**Best Practice Reference:**
- [Kubernetes Pod Security Standards - Restricted Profile](https://kubernetes.io/docs/concepts/security/pod-security-standards/#restricted)
- [Configure a Security Context for a Pod or Container](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)

---

### SEC-003: Missing Security Context

**Check ID:** `SEC-003`  
**Severity:** Warning  
**What it checks:** Verifies that pods or containers have security context defined.

**How it works:**
- Queries all pods using Kubernetes API
- Checks if either pod-level or container-level security context exists
- Flags pods where neither is defined

**Remediation:**
```yaml
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
  containers:
    - name: app
      securityContext:
        allowPrivilegeEscalation: false
        capabilities:
          drop:
            - ALL
```

**Kubernetes API Resources Used:**
- `CoreV1Api.list_pod_for_all_namespaces()`
- Inspects `Pod.spec.securityContext` and presence of `Pod.spec.containers[].securityContext`

**Best Practice Reference:**
- [Kubernetes Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [Configure a Security Context for a Pod or Container](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)

---

### SEC-004: Read-Only Root Filesystem

**Check ID:** `SEC-004`  
**Severity:** Info  
**What it checks:** Verifies that containers use read-only root filesystem where possible.

**How it works:**
- Queries all pods using Kubernetes API
- Checks `securityContext.readOnlyRootFilesystem` for each container
- Flags containers where this is not enabled (informational only)

**Remediation:**
```yaml
securityContext:
  readOnlyRootFilesystem: true
  volumes:
    - name: tmp
      emptyDir: {}
    - name: cache
      emptyDir: {}
```

**Kubernetes API Resources Used:**
- `CoreV1Api.list_pod_for_all_namespaces()`
- Inspects `Pod.spec.containers[].securityContext.readOnlyRootFilesystem`

**Best Practice Reference:**
- [Kubernetes Pod Security Standards - Restricted Profile](https://kubernetes.io/docs/concepts/security/pod-security-standards/#restricted)
- [Configure a Security Context for a Pod or Container](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)

---

### SEC-005: Dangerous Capabilities

**Check ID:** `SEC-005`  
**Severity:** Warning (Critical if `ALL` capability is added)  
**What it checks:** Verifies that containers don't add dangerous Linux capabilities.

**How it works:**
- Queries all pods using Kubernetes API
- Checks `securityContext.capabilities.add` for dangerous capabilities:
  - `NET_RAW`
  - `SYS_ADMIN`
  - `SYS_MODULE`
  - `ALL` (critical)
- Flags containers with these capabilities

**Remediation:**
```yaml
securityContext:
  capabilities:
    drop:
      - ALL
    add:
      - NET_BIND_SERVICE  # Only add minimal required capabilities
```

**Kubernetes API Resources Used:**
- `CoreV1Api.list_pod_for_all_namespaces()`
- Inspects `Pod.spec.containers[].securityContext.capabilities.add`

**Best Practice Reference:**
- [Kubernetes Pod Security Standards - Restricted Profile](https://kubernetes.io/docs/concepts/security/pod-security-standards/#restricted)
- [Linux Capabilities](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [CIS Kubernetes Benchmark - 5.2.6](https://www.cisecurity.org/benchmark/kubernetes)

---

### SEC-006: Host Namespace Sharing

**Check ID:** `SEC-006`  
**Severity:** Critical  
**What it checks:** Verifies that pods don't share host network, PID, or IPC namespaces.

**How it works:**
- Queries all pods using Kubernetes API
- Checks pod spec for:
  - `spec.hostNetwork`
  - `spec.hostPID`
  - `spec.hostIPC`
- Flags pods where any of these are enabled

**Remediation:**
```yaml
spec:
  hostNetwork: false
  hostPID: false
  hostIPC: false
```

**Kubernetes API Resources Used:**
- `CoreV1Api.list_pod_for_all_namespaces()`
- Inspects `Pod.spec.hostNetwork`, `Pod.spec.hostPID`, `Pod.spec.hostIPC`

**Best Practice Reference:**
- [Kubernetes Pod Security Standards - Restricted Profile](https://kubernetes.io/docs/concepts/security/pod-security-standards/#restricted)
- [CIS Kubernetes Benchmark - 5.2.2, 5.2.3, 5.2.4](https://www.cisecurity.org/benchmark/kubernetes)

---

## Resource Management

### RES-001: CPU Requests

**Check ID:** `RES-001`  
**Severity:** Critical  
**What it checks:** Verifies that all containers have CPU requests defined.

**How it works:**
- Queries all pods using Kubernetes API
- Checks `resources.requests.cpu` for each container
- Flags containers missing CPU requests

**Remediation:**
```yaml
resources:
  requests:
    cpu: "100m"
  limits:
    cpu: "200m"
```

**Kubernetes API Resources Used:**
- `CoreV1Api.list_pod_for_all_namespaces()`
- Inspects `Pod.spec.containers[].resources.requests["cpu"]`

**Best Practice Reference:**
- [Assign CPU Resources to Containers and Pods](https://kubernetes.io/docs/tasks/configure-pod-container/assign-cpu-resource/)
- [Manage Resources for Containers](https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/)
- [CIS Kubernetes Benchmark - 5.7.1](https://www.cisecurity.org/benchmark/kubernetes)

---

### RES-002: Memory Requests

**Check ID:** `RES-002`  
**Severity:** Critical  
**What it checks:** Verifies that all containers have memory requests defined.

**How it works:**
- Queries all pods using Kubernetes API
- Checks `resources.requests.memory` for each container
- Flags containers missing memory requests

**Remediation:**
```yaml
resources:
  requests:
    memory: "128Mi"
  limits:
    memory: "256Mi"
```

**Kubernetes API Resources Used:**
- `CoreV1Api.list_pod_for_all_namespaces()`
- Inspects `Pod.spec.containers[].resources.requests["memory"]`

**Best Practice Reference:**
- [Assign Memory Resources to Containers and Pods](https://kubernetes.io/docs/tasks/configure-pod-container/assign-memory-resource/)
- [Manage Resources for Containers](https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/)

---

### RES-003: CPU Limits

**Check ID:** `RES-003`  
**Severity:** Warning  
**What it checks:** Verifies that containers have CPU limits defined.

**How it works:**
- Queries all pods using Kubernetes API
- Checks `resources.limits.cpu` for each container
- Flags containers missing CPU limits

**Remediation:**
```yaml
resources:
  limits:
    cpu: "200m"
```

**Kubernetes API Resources Used:**
- `CoreV1Api.list_pod_for_all_namespaces()`
- Inspects `Pod.spec.containers[].resources.limits["cpu"]`

**Best Practice Reference:**
- [Manage Resources for Containers](https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/)
- [Resource Management](https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/)

---

### RES-004: Memory Limits

**Check ID:** `RES-004`  
**Severity:** Critical  
**What it checks:** Verifies that all containers have memory limits defined.

**How it works:**
- Queries all pods using Kubernetes API
- Checks `resources.limits.memory` for each container
- Flags containers missing memory limits (prevents OOM kills)

**Remediation:**
```yaml
resources:
  limits:
    memory: "256Mi"
```

**Kubernetes API Resources Used:**
- `CoreV1Api.list_pod_for_all_namespaces()`
- Inspects `Pod.spec.containers[].resources.limits["memory"]`

**Best Practice Reference:**
- [Assign Memory Resources to Containers and Pods](https://kubernetes.io/docs/tasks/configure-pod-container/assign-memory-resource/)
- [Manage Resources for Containers](https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/)
- [CIS Kubernetes Benchmark - 5.7.2](https://www.cisecurity.org/benchmark/kubernetes)

---

### RES-005: Resource Ratios

**Check ID:** `RES-005`  
**Severity:** Info  
**What it checks:** Verifies that resource limits don't exceed 2x requests (recommended ratio).

**How it works:**
- Queries all pods using Kubernetes API
- Parses CPU quantities and compares limits vs requests
- Flags containers where `limit > 2 * request` for CPU

**Remediation:**
```yaml
resources:
  requests:
    cpu: "100m"
    memory: "128Mi"
  limits:
    cpu: "200m"      # Keep within 2x request
    memory: "256Mi"  # Keep within 2x request
```

**Kubernetes API Resources Used:**
- `CoreV1Api.list_pod_for_all_namespaces()`
- Inspects `Pod.spec.containers[].resources.requests` and `limits`
- Parses Kubernetes quantity strings (e.g., "100m", "1Gi", "512Mi")

**Best Practice Reference:**
- [Resource Management Best Practices](https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/#resource-requests-and-limits-of-pod-and-container)
- [Setting Requests and Limits](https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/#requests-and-limits)

---

## Pod Configuration

### POD-001: Required Labels

**Check ID:** `POD-001`  
**Severity:** Warning  
**What it checks:** Verifies that pods have required labels for identification.

**How it works:**
- Queries all pods using Kubernetes API
- Checks pod metadata labels for presence of:
  - `app.kubernetes.io/name` OR
  - `app`
- Flags pods missing both labels

**Remediation:**
```yaml
metadata:
  labels:
    app.kubernetes.io/name: my-app
    app.kubernetes.io/version: "1.0.0"
    app.kubernetes.io/component: backend
```

**Kubernetes API Resources Used:**
- `CoreV1Api.list_pod_for_all_namespaces()`
- Inspects `Pod.metadata.labels`

**Best Practice Reference:**
- [Kubernetes Recommended Labels](https://kubernetes.io/docs/concepts/overview/working-with-objects/common-labels/)
- [Labels and Selectors](https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/)

---

### POD-002: Health Checks

**Check ID:** `POD-002`  
**Severity:** Warning  
**What it checks:** Verifies that containers have health check probes defined.

**How it works:**
- Queries all pods using Kubernetes API
- Checks each container for presence of:
  - `livenessProbe` OR
  - `readinessProbe`
- Flags containers with neither probe defined

**Remediation:**
```yaml
containers:
  - name: app
    livenessProbe:
      httpGet:
        path: /health
        port: 8080
      initialDelaySeconds: 30
      periodSeconds: 10
    readinessProbe:
      httpGet:
        path: /ready
        port: 8080
      initialDelaySeconds: 5
      periodSeconds: 5
```

**Kubernetes API Resources Used:**
- `CoreV1Api.list_pod_for_all_namespaces()`
- Inspects `Pod.spec.containers[].livenessProbe` and `readinessProbe`

**Best Practice Reference:**
- [Configure Liveness, Readiness and Startup Probes](https://kubernetes.io/docs/tasks/configure-pod-container/configure-liveness-readiness-startup-probes/)
- [Container Probes](https://kubernetes.io/docs/concepts/workloads/pods/pod-lifecycle/#container-probes)

---

## Network Security

### NET-001: Network Policies

**Check ID:** `NET-001`  
**Severity:** Critical  
**What it checks:** Verifies that namespaces have NetworkPolicy resources defined.

**How it works:**
- Queries all namespaces using Kubernetes API
- Queries all NetworkPolicy resources using Kubernetes API
- Creates a set of namespaces that have NetworkPolicy resources
- Flags namespaces (excluding system namespaces) without NetworkPolicies

**Remediation:**
```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: my-namespace
spec:
  podSelector: {}
  policyTypes:
    - Ingress
    - Egress
```

**Kubernetes API Resources Used:**
- `CoreV1Api.list_namespace()` or `list_namespace()`
- `NetworkingV1Api.list_network_policy_for_all_namespaces()` or `list_namespaced_network_policy()`
- Inspects `Namespace.metadata.name` and `NetworkPolicy.metadata.namespace`

**Best Practice Reference:**
- [Network Policies](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
- [Declare Network Policy](https://kubernetes.io/docs/tasks/administer-cluster/declare-network-policy/)
- [CIS Kubernetes Benchmark - 5.3.1](https://www.cisecurity.org/benchmark/kubernetes)

---

## RBAC & Access Control

### RBAC-001: Service Accounts

**Check ID:** `RBAC-001`  
**Severity:** Warning  
**What it checks:** Verifies that pods use named service accounts instead of default.

**How it works:**
- Queries all pods using Kubernetes API
- Checks `spec.serviceAccountName` (or defaults to "default" if not set)
- Flags pods using the "default" service account

**Remediation:**
```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: my-app-sa
  namespace: my-namespace
---
spec:
  serviceAccountName: my-app-sa
```

**Kubernetes API Resources Used:**
- `CoreV1Api.list_pod_for_all_namespaces()`
- Inspects `Pod.spec.serviceAccountName`

**Best Practice Reference:**
- [Configure Service Accounts for Pods](https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/)
- [Service Accounts](https://kubernetes.io/docs/concepts/security/service-accounts/)
- [CIS Kubernetes Benchmark - 5.1.5](https://www.cisecurity.org/benchmark/kubernetes)

---

## Security Best Practices (Continued)

### SEC-007: Pod Security Standards

**Check ID:** `SEC-007`  
**Severity:** Warning (Critical if privileged)  
**What it checks:** Verifies that namespaces have Pod Security Standards enforcement enabled.

**How it works:**
- Queries all namespaces using Kubernetes API
- Checks namespace annotations for `pod-security.kubernetes.io/enforce`
- Flags namespaces without PSA enforcement or with `privileged` mode

**Remediation:**
```yaml
apiVersion: v1
kind: Namespace
metadata:
  annotations:
    pod-security.kubernetes.io/enforce: baseline
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted
```

**Kubernetes API Resources Used:**
- `CoreV1Api.list_namespace()`
- Inspects `Namespace.metadata.annotations["pod-security.kubernetes.io/enforce"]`

**Best Practice Reference:**
- [Kubernetes Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [Enforce Pod Security Standards with Namespace Labels](https://kubernetes.io/docs/tasks/configure-pod-container/enforce-standards-namespace-labels/)

---

### SEC-008: Secrets in ConfigMaps

**Check ID:** `SEC-008`  
**Severity:** Warning  
**What it checks:** Heuristically detects potential secrets stored in ConfigMaps.

**How it works:**
- Queries all ConfigMaps using Kubernetes API
- Scans ConfigMap data keys and values for secret-like patterns
- Flags ConfigMaps that might contain secrets

**Remediation:**
- Move secrets to Kubernetes Secrets or external secret management systems
- Use tools like Sealed Secrets or External Secrets Operator

**Kubernetes API Resources Used:**
- `CoreV1Api.list_config_map_for_all_namespaces()`
- Inspects `ConfigMap.data` for suspicious patterns

**Best Practice Reference:**
- [Kubernetes Secrets](https://kubernetes.io/docs/concepts/configuration/secret/)
- [Configure a Pod to Use a ConfigMap](https://kubernetes.io/docs/tasks/configure-pod-container/configure-pod-configmap/)
- [CIS Kubernetes Benchmark - 5.4.1](https://www.cisecurity.org/benchmark/kubernetes)

---

### SEC-009: Image Pull Secrets

**Check ID:** `SEC-009`  
**Severity:** Info  
**What it checks:** Verifies that pods using private registries have image pull secrets configured.

**How it works:**
- Queries all pods using Kubernetes API
- Detects private registry patterns in container images
- Flags pods without `imagePullSecrets` or custom service accounts

**Remediation:**
```yaml
spec:
  imagePullSecrets:
    - name: my-registry-secret
```

**Kubernetes API Resources Used:**
- `CoreV1Api.list_pod_for_all_namespaces()`
- Inspects `Pod.spec.imagePullSecrets` and `Pod.spec.serviceAccountName`

**Best Practice Reference:**
- [Pull an Image from a Private Registry](https://kubernetes.io/docs/tasks/configure-pod-container/pull-image-private-registry/)
- [Specifying imagePullSecrets on a Pod](https://kubernetes.io/docs/concepts/containers/images/#specifying-imagepullsecrets-on-a-pod)

---

### SEC-010: Image Tags (Avoid Latest)

**Check ID:** `SEC-010`  
**Severity:** Warning  
**What it checks:** Verifies that container images use specific tags or digests instead of `:latest`.

**How it works:**
- Queries all pods using Kubernetes API
- Checks container image strings for `:latest` tag or missing tags
- Flags images without specific version tags

**Remediation:**
```yaml
containers:
  - name: app
    image: myapp:v1.2.3  # Specific version tag
    # OR
    image: myapp@sha256:abc123...  # Digest
```

**Kubernetes API Resources Used:**
- `CoreV1Api.list_pod_for_all_namespaces()`
- Inspects `Pod.spec.containers[].image`

**Best Practice Reference:**
- [Container Images](https://kubernetes.io/docs/concepts/containers/images/)
- [Image Names](https://kubernetes.io/docs/concepts/containers/images/#image-names)
- [CIS Kubernetes Benchmark - 5.3.1](https://www.cisecurity.org/benchmark/kubernetes)

---

### SEC-011: Service Account Token Auto-Mount

**Check ID:** `SEC-011`  
**Severity:** Info  
**What it checks:** Verifies that service account token auto-mounting is configured appropriately.

**How it works:**
- Queries all pods using Kubernetes API
- Checks `automountServiceAccountToken` field
- Flags pods that auto-mount tokens from default service account when not needed

**Remediation:**
```yaml
spec:
  automountServiceAccountToken: false  # If token not needed
```

**Kubernetes API Resources Used:**
- `CoreV1Api.list_pod_for_all_namespaces()`
- Inspects `Pod.spec.automountServiceAccountToken` and `Pod.spec.serviceAccountName`

**Best Practice Reference:**
- [Configure Service Accounts for Pods](https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/)
- [Use the Default Service Account to Access the API Server](https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/#use-the-default-service-account-to-access-the-api-server)

---

### SEC-012: Seccomp Profile

**Check ID:** `SEC-012`  
**Severity:** Info  
**What it checks:** Verifies that pods have seccomp profiles configured for additional security.

**How it works:**
- Queries all pods using Kubernetes API
- Checks `securityContext.seccompProfile` or seccomp annotations
- Flags pods without seccomp profiles

**Remediation:**
```yaml
spec:
  securityContext:
    seccompProfile:
      type: RuntimeDefault
```

**Kubernetes API Resources Used:**
- `CoreV1Api.list_pod_for_all_namespaces()`
- Inspects `Pod.spec.securityContext.seccompProfile` and `Pod.metadata.annotations`

**Best Practice Reference:**
- [Restrict a Container's Syscalls with seccomp](https://kubernetes.io/docs/tutorials/security/seccomp/)
- [Seccomp](https://man7.org/linux/man-pages/man2/seccomp.2.html)
- [CIS Kubernetes Benchmark - 5.7.2](https://www.cisecurity.org/benchmark/kubernetes)

---

## Resource Management (Continued)

### RES-006: Resource Quotas

**Check ID:** `RES-006`  
**Severity:** Warning  
**What it checks:** Verifies that namespaces have ResourceQuota objects defined.

**How it works:**
- Queries all namespaces using Kubernetes API
- Queries all ResourceQuota resources
- Flags namespaces (excluding system namespaces) without resource quotas

**Remediation:**
```yaml
apiVersion: v1
kind: ResourceQuota
metadata:
  name: compute-quota
  namespace: my-namespace
spec:
  hard:
    requests.cpu: "2"
    requests.memory: 4Gi
    limits.cpu: "4"
    limits.memory: 8Gi
```

**Kubernetes API Resources Used:**
- `CoreV1Api.list_namespace()` and `list_resource_quota_for_all_namespaces()`
- Inspects `ResourceQuota.metadata.namespace`

**Best Practice Reference:**
- [Resource Quotas](https://kubernetes.io/docs/concepts/policy/resource-quotas/)
- [Apply Resource Quota to a Namespace](https://kubernetes.io/docs/tasks/administer-cluster/manage-resources/quota-memory-cpu-namespace/)
- [CIS Kubernetes Benchmark - 5.10.1](https://www.cisecurity.org/benchmark/kubernetes)

---

#### SEC-008: Secrets in ConfigMaps
**API Resources:** `CoreV1Api.list_configmap_for_all_namespaces()`
**What to check:**
- Scan ConfigMap data for common secret patterns (passwords, API keys, tokens)
- Flag ConfigMaps that might contain secrets (heuristic check)
- Recommend using Secrets instead

**Kubernetes API:**
```python
configmaps = client.list_configmaps()
for cm in configmaps:
    if cm.data:
        for key, value in cm.data.items():
            # Pattern matching for secrets
```

---

#### SEC-009: Image Pull Secrets
**API Resources:** `CoreV1Api.list_pod_for_all_namespaces()`, `AppsV1Api.list_deployment_for_all_namespaces()`
**What to check:**
- Verify pods/deployments using private registries have `imagePullSecrets` configured

**Kubernetes API:**
```python
pods = client.list_pods()
for pod in pods:
    if pod.spec.image_pull_secrets is None or len(pod.spec.image_pull_secrets) == 0:
        # Check if image requires pull secret (private registry)
```

---

#### SEC-010: Image Tags (Avoid Latest)
**API Resources:** `CoreV1Api.list_pod_for_all_namespaces()`, `AppsV1Api.list_deployment_for_all_namespaces()`
**What to check:**
- Check container images for use of `:latest` tag
- Flag images without specific tags or digests

**Kubernetes API:**
```python
pods = client.list_pods()
for pod in pods:
    for container in pod.spec.containers:
        image = container.image
        if ":latest" in image or ":" not in image:
            # Flag as warning
```

---

#### SEC-011: Service Account Token Auto-Mount
**API Resources:** `CoreV1Api.list_pod_for_all_namespaces()`
**What to check:**
- Check `automountServiceAccountToken` field
- Flag pods that auto-mount service account tokens when not needed

**Kubernetes API:**
```python
pods = client.list_pods()
for pod in pods:
    if pod.spec.automount_service_account_token is True:
        # Check if it's necessary
```

---

#### SEC-012: Seccomp Profile
**API Resources:** `CoreV1Api.list_pod_for_all_namespaces()`
**What to check:**
- Verify pods have seccomp profiles configured
- Check for `securityContext.seccompProfile` or annotations

**Kubernetes API:**
```python
pods = client.list_pods()
for pod in pods:
    sec_ctx = pod.spec.security_context
    if not sec_ctx or not sec_ctx.seccomp_profile:
        annotations = pod.metadata.annotations or {}
        if "seccomp.security.alpha.kubernetes.io/pod" not in annotations:
            # Flag as warning
```

---

### Resource Management

#### RES-006: Resource Quotas
**API Resources:** `CoreV1Api.list_resource_quota_for_all_namespaces()`, `CoreV1Api.list_namespace()`
**What to check:**
- Verify namespaces have ResourceQuota objects defined
- Flag namespaces without quotas

**Kubernetes API:**
```python
namespaces = client.list_namespaces()
quotas = client.list_resource_quotas()
namespaces_with_quotas = {q.metadata.namespace for q in quotas}
for ns in namespaces:
    if ns.metadata.name not in namespaces_with_quotas:
        # Flag namespace without quota
```

---

#### RES-007: Limit Ranges
**API Resources:** `CoreV1Api.list_limit_range_for_all_namespaces()`, `CoreV1Api.list_namespace()`
**What to check:**
- Verify namespaces have LimitRange objects
- Flag namespaces without limit ranges

**Kubernetes API:**
```python
namespaces = client.list_namespaces()
limit_ranges = client.list_limit_ranges()
namespaces_with_limits = {lr.metadata.namespace for lr in limit_ranges}
for ns in namespaces:
    if ns.metadata.name not in namespaces_with_limits:
        # Flag namespace without limit range
```

**Best Practice Reference:**
- [Limit Ranges](https://kubernetes.io/docs/concepts/policy/limit-range/)
- [Configure Memory and CPU Quotas for a Namespace](https://kubernetes.io/docs/tasks/administer-cluster/manage-resources/quota-memory-cpu-namespace/)

---

#### RES-008: Init Container Resources
**API Resources:** `CoreV1Api.list_pod_for_all_namespaces()`
**What to check:**
- Verify init containers have resource requests and limits
- Same checks as regular containers

**Kubernetes API:**
```python
pods = client.list_pods()
for pod in pods:
    if pod.spec.init_containers:
        for init_container in pod.spec.init_containers:
            # Check resources same as regular containers
```

**Best Practice Reference:**
- [Init Containers](https://kubernetes.io/docs/concepts/workloads/pods/init-containers/)
- [Manage Resources for Containers](https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/)

---

### Pod Configuration

#### POD-003: Startup Probes
**API Resources:** `CoreV1Api.list_pod_for_all_namespaces()`
**What to check:**
- Verify containers have startup probes for slow-starting applications

**Kubernetes API:**
```python
pods = client.list_pods()
for pod in pods:
    for container in pod.spec.containers:
        if container.startup_probe is None:
            # Check if liveness/readiness exist (might need startup probe)
```

**Best Practice Reference:**
- [Configure Liveness, Readiness and Startup Probes](https://kubernetes.io/docs/tasks/configure-pod-container/configure-liveness-readiness-startup-probes/)
- [Define Startup Probes](https://kubernetes.io/docs/tasks/configure-pod-container/configure-liveness-readiness-startup-probes/#define-startup-probes)

---

#### POD-004: Termination Grace Period
**API Resources:** `CoreV1Api.list_pod_for_all_namespaces()`
**What to check:**
- Verify `terminationGracePeriodSeconds` is set appropriately
- Flag very short or very long grace periods

**Kubernetes API:**
```python
pods = client.list_pods()
for pod in pods:
    grace_period = pod.spec.termination_grace_period_seconds
    if grace_period is None or grace_period < 10 or grace_period > 300:
        # Flag as warning
```

**Best Practice Reference:**
- [Pod Lifecycle](https://kubernetes.io/docs/concepts/workloads/pods/pod-lifecycle/#pod-termination)
- [Termination of Pods](https://kubernetes.io/docs/concepts/workloads/pods/pod-lifecycle/#pod-termination)

---

#### POD-005: PreStop Hooks
**API Resources:** `CoreV1Api.list_pod_for_all_namespaces()`
**What to check:**
- Check for `lifecycle.preStop` hooks for graceful shutdown

**Kubernetes API:**
```python
pods = client.list_pods()
for pod in pods:
    for container in pod.spec.containers:
        if not container.lifecycle or not container.lifecycle.pre_stop:
            # Flag as info/recommendation
```

**Best Practice Reference:**
- [Container Lifecycle Hooks](https://kubernetes.io/docs/concepts/containers/container-lifecycle-hooks/)
- [Hook Handler Implementations](https://kubernetes.io/docs/concepts/containers/container-lifecycle-hooks/#hook-handler-implementations)

---

### Network Security

#### NET-002: Ingress TLS Configuration
**API Resources:** `NetworkingV1Api.list_ingress_for_all_namespaces()`
**What to check:**
- Verify Ingress resources have TLS configured
- Flag Ingress without TLS

**Kubernetes API:**
```python
ingresses = client.list_ingresses()
for ingress in ingresses:
    if not ingress.spec.tls or len(ingress.spec.tls) == 0:
        # Flag as critical
```

**Best Practice Reference:**
- [Ingress TLS](https://kubernetes.io/docs/concepts/services-networking/ingress/#tls)
- [TLS Ingress](https://kubernetes.io/docs/concepts/services-networking/ingress/#tls)
- [CIS Kubernetes Benchmark - 5.6.1](https://www.cisecurity.org/benchmark/kubernetes)

---

#### NET-003: Service Types
**API Resources:** `CoreV1Api.list_service_for_all_namespaces()`
**What to check:**
- Flag unnecessary use of NodePort or LoadBalancer services
- Recommend ClusterIP for internal services

**Kubernetes API:**
```python
services = client.list_services()
for svc in services:
    if svc.spec.type in ["NodePort", "LoadBalancer"]:
        # Check if external access is necessary
```

**Best Practice Reference:**
- [Service Types](https://kubernetes.io/docs/concepts/services-networking/service/#publishing-services-service-types)
- [Services](https://kubernetes.io/docs/concepts/services-networking/service/)

---

#### NET-004: Ingress Security Annotations
**API Resources:** `NetworkingV1Api.list_ingress_for_all_namespaces()`
**What to check:**
- Check for security-related annotations (rate limiting, WAF, etc.)

**Kubernetes API:**
```python
ingresses = client.list_ingresses()
for ingress in ingresses:
    annotations = ingress.metadata.annotations or {}
    # Check for security annotations
```

**Best Practice Reference:**
- [NGINX Ingress Controller Annotations](https://kubernetes.github.io/ingress-nginx/user-guide/nginx-configuration/annotations/)
- [Ingress](https://kubernetes.io/docs/concepts/services-networking/ingress/)

---

### RBAC & Access Control

#### RBAC-002: ClusterRole with Wildcards
**API Resources:** `RbacAuthorizationV1Api.list_cluster_role()`, `RbacAuthorizationV1Api.list_role()`
**What to check:**
- Check for wildcard verbs (`*`) in Roles/ClusterRoles
- Check for wildcard resources (`*`) in rules
- Flag overly permissive roles

**Kubernetes API:**
```python
cluster_roles = client.rbac_v1.list_cluster_role()
for cr in cluster_roles.items:
    for rule in cr.rules:
        if "*" in rule.verbs or "*" in rule.resources:
            # Flag as critical
```

**Best Practice Reference:**
- [Using RBAC Authorization](https://kubernetes.io/docs/reference/access-authn-authz/rbac/)
- [Role and ClusterRole](https://kubernetes.io/docs/reference/access-authn-authz/rbac/#role-and-clusterrole)
- [CIS Kubernetes Benchmark - 5.1.3](https://www.cisecurity.org/benchmark/kubernetes)

---

#### RBAC-003: ClusterAdmin Bindings
**API Resources:** `RbacAuthorizationV1Api.list_cluster_role_binding()`
**What to check:**
- Check for ClusterRoleBindings to `cluster-admin`
- Flag bindings to service accounts (especially in production)
- Check for bindings to `system:anonymous` or `system:unauthenticated`

**Kubernetes API:**
```python
bindings = client.rbac_v1.list_cluster_role_binding()
for binding in bindings.items:
    if binding.role_ref.name == "cluster-admin":
        for subject in binding.subjects:
            if subject.kind == "ServiceAccount":
                # Flag as critical
```

**Best Practice Reference:**
- [Using RBAC Authorization](https://kubernetes.io/docs/reference/access-authn-authz/rbac/)
- [Default Roles and Role Bindings](https://kubernetes.io/docs/reference/access-authn-authz/rbac/#default-roles-and-role-bindings)
- [CIS Kubernetes Benchmark - 5.1.5](https://www.cisecurity.org/benchmark/kubernetes)

---

#### RBAC-004: Role Binding Best Practices
**API Resources:** `RbacAuthorizationV1Api.list_role_binding()`, `RbacAuthorizationV1Api.list_cluster_role_binding()`
**What to check:**
- Verify RoleBindings use Role (not ClusterRole) when namespace-scoped

**Kubernetes API:**
```python
role_bindings = client.rbac_v1.list_role_binding_for_all_namespaces()
for rb in role_bindings.items:
    if rb.role_ref.kind == "ClusterRole":
        # Check if namespace-scoped Role would suffice
```

**Best Practice Reference:**
- [RoleBinding and ClusterRoleBinding](https://kubernetes.io/docs/reference/access-authn-authz/rbac/#rolebinding-and-clusterrolebinding)
- [Using RBAC Authorization](https://kubernetes.io/docs/reference/access-authn-authz/rbac/)

---

#### RBAC-005: Service Account Permissions
**API Resources:** `RbacAuthorizationV1Api.list_role_binding()`, `CoreV1Api.list_service_account()`
**What to check:**
- Check service accounts have minimal required permissions
- Verify service accounts are not bound to cluster-admin

**Kubernetes API:**
```python
service_accounts = client.list_service_accounts()
bindings = client.rbac_v1.list_role_binding_for_all_namespaces()
# Cross-reference to find over-privileged SAs
```

**Best Practice Reference:**
- [Service Accounts](https://kubernetes.io/docs/concepts/security/service-accounts/)
- [Default Roles and Role Bindings](https://kubernetes.io/docs/reference/access-authn-authz/rbac/#default-roles-and-role-bindings)
- [CIS Kubernetes Benchmark - 5.1.6](https://www.cisecurity.org/benchmark/kubernetes)

---

### Deployment & Availability

#### DEP-001: Replica Counts
**API Resources:** `AppsV1Api.list_deployment_for_all_namespaces()`, `AppsV1Api.list_stateful_set_for_all_namespaces()`
**What to check:**
- Verify deployments have at least 2 replicas for production
- Flag single-replica deployments in production namespaces

**Kubernetes API:**
```python
deployments = client.list_deployments()
for dep in deployments:
    replicas = dep.spec.replicas or 1
    if replicas < 2:
        # Flag as warning (unless it's a system component)
```

**Best Practice Reference:**
- [Deployments](https://kubernetes.io/docs/concepts/workloads/controllers/deployment/)
- [StatefulSets](https://kubernetes.io/docs/concepts/workloads/controllers/statefulset/)
- [High Availability](https://kubernetes.io/docs/setup/best-practices/cluster-large/)

---

#### DEP-002: Pod Disruption Budgets
**API Resources:** `PolicyV1Api.list_pod_disruption_budget_for_all_namespaces()` (if available)
**What to check:**
- Verify critical deployments have PodDisruptionBudgets
- Flag deployments without PDBs

**Kubernetes API:**
```python
# Requires PolicyV1Api
try:
    pdbs = client.policy_v1.list_pod_disruption_budget_for_all_namespaces()
    # Check deployments against PDBs
except:
    # Policy API might not be available
```

**Best Practice Reference:**
- [Pod Disruption Budgets](https://kubernetes.io/docs/concepts/workloads/pods/disruptions/)
- [Specifying a Disruption Budget for your Application](https://kubernetes.io/docs/tasks/run-application/configure-pdb/)

---

#### DEP-003: Deployment Strategy
**API Resources:** `AppsV1Api.list_deployment_for_all_namespaces()`
**What to check:**
- Verify deployments use RollingUpdate strategy (not Recreate)
- Flag Recreate strategy (causes downtime)

**Kubernetes API:**
```python
deployments = client.list_deployments()
for dep in deployments:
    strategy = dep.spec.strategy
    if strategy and strategy.type == "Recreate":
        # Flag as warning
```

**Best Practice Reference:**
- [Deployment Strategies](https://kubernetes.io/docs/concepts/workloads/controllers/deployment/#strategy)
- [Performing a Rolling Update](https://kubernetes.io/docs/tutorials/kubernetes-basics/update/update-intro/)

---

#### DEP-004: Update Strategy for StatefulSets
**API Resources:** `AppsV1Api.list_stateful_set_for_all_namespaces()`
**What to check:**
- Verify StatefulSets have appropriate update strategy

**Kubernetes API:**
```python
statefulsets = client.list_statefulsets()
for sts in statefulsets:
    update_strategy = sts.spec.update_strategy
    if update_strategy.type == "OnDelete":
        # Flag as info (might be intentional)
```

**Best Practice Reference:**
- [StatefulSet Update Strategies](https://kubernetes.io/docs/concepts/workloads/controllers/statefulset/#update-strategies)
- [StatefulSets](https://kubernetes.io/docs/concepts/workloads/controllers/statefulset/)

---

### Storage

#### STOR-001: Persistent Volume Access Modes
**API Resources:** `CoreV1Api.list_persistent_volume_claim_for_all_namespaces()`
**What to check:**
- Verify PVCs use appropriate access modes (RWO, ROX, RWX)
- Flag RWX unless necessary (security concern)

**Kubernetes API:**
```python
pvcs = client.core_v1.list_persistent_volume_claim_for_all_namespaces()
for pvc in pvc.items:
    access_modes = pvc.spec.access_modes
    if "ReadWriteMany" in access_modes:
        # Flag as warning (security concern)
```

**Best Practice Reference:**
- [Access Modes](https://kubernetes.io/docs/concepts/storage/persistent-volumes/#access-modes)
- [Persistent Volumes](https://kubernetes.io/docs/concepts/storage/persistent-volumes/)

---

#### STOR-002: HostPath Volumes
**API Resources:** `CoreV1Api.list_pod_for_all_namespaces()`
**What to check:**
- Flag use of hostPath volumes (security risk)
- Verify path restrictions if hostPath is used

**Kubernetes API:**
```python
pods = client.list_pods()
for pod in pods:
    if pod.spec.volumes:
        for volume in pod.spec.volumes:
            if volume.host_path:
                # Flag as critical (unless in system namespace)
```

**Best Practice Reference:**
- [hostPath](https://kubernetes.io/docs/concepts/storage/volumes/#hostpath)
- [Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [CIS Kubernetes Benchmark - 5.2.7](https://www.cisecurity.org/benchmark/kubernetes)

---

### Admission Controllers & Policies

#### ADM-001: Validating Admission Webhooks
**API Resources:** `AdmissionregistrationV1Api.list_validating_webhook_configuration()`
**What to check:**
- Verify webhooks are configured for policy enforcement
- Check webhook failure policy and rules

**Kubernetes API:**
```python
webhooks = client.admissionregistration_v1.list_validating_webhook_configuration()
for wh in webhooks.items:
    for webhook in wh.webhooks:
        # Check failurePolicy, rules, etc.
```

**Best Practice Reference:**
- [Dynamic Admission Control](https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/)
- [Validating Admission Webhooks](https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/#what-are-admission-webhooks)

---

#### ADM-002: Mutating Admission Webhooks
**API Resources:** `AdmissionregistrationV1Api.list_mutating_webhook_configuration()`
**What to check:**
- Verify mutating webhooks are used appropriately
- Check webhook ordering and side effects

**Kubernetes API:**
```python
webhooks = client.admissionregistration_v1.list_mutating_webhook_configuration()
for wh in webhooks.items:
    # Check webhook configuration
```

**Best Practice Reference:**
- [Dynamic Admission Control](https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/)
- [Mutating Admission Webhooks](https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/#what-are-admission-webhooks)
- [Webhook Configuration](https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/#failure-policy)

---

### Namespace Management

#### NS-001: Namespace Labels and Annotations
**API Resources:** `CoreV1Api.list_namespace()`
**What to check:**
- Verify namespaces have proper labels (environment, team, etc.)
- Check for required annotations

**Kubernetes API:**
```python
namespaces = client.list_namespaces()
for ns in namespaces:
    labels = ns.metadata.labels or {}
    # Check for required labels
```

**Best Practice Reference:**
- [Kubernetes Recommended Labels](https://kubernetes.io/docs/concepts/overview/working-with-objects/common-labels/)
- [Labels and Selectors](https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/)
- [Enforce Pod Security Standards with Namespace Labels](https://kubernetes.io/docs/tasks/configure-pod-container/enforce-standards-namespace-labels/)

---

#### NS-002: Default Namespace Usage
**API Resources:** `CoreV1Api.list_pod_for_all_namespaces()`
**What to check:**
- Flag resources in `default` namespace
- Recommend using named namespaces

**Kubernetes API:**
```python
pods = client.list_pods()
for pod in pods:
    if pod.metadata.namespace == "default":
        # Flag as warning
```

**Best Practice Reference:**
- [Namespaces](https://kubernetes.io/docs/concepts/overview/working-with-objects/namespaces/)
- [Namespaces Walkthrough](https://kubernetes.io/docs/tasks/administer-cluster/namespaces-walkthrough/)
- [CIS Kubernetes Benchmark - 5.7.3](https://www.cisecurity.org/benchmark/kubernetes)

---

## Summary of Best Practices

### Currently Implemented: 42 checks ✅

All of the following checks are **fully implemented** and actively run by the `kbase` CLI tool:

1. **Security Best Practices (12 checks):** SEC-001 through SEC-012
2. **Resource Management (8 checks):** RES-001 through RES-008
3. **Pod Configuration (5 checks):** POD-001 through POD-005
4. **Network Security (4 checks):** NET-001 through NET-004
5. **RBAC & Access Control (5 checks):** RBAC-001 through RBAC-005
6. **Deployment & Availability (4 checks):** DEP-001 through DEP-004
7. **Storage (2 checks):** STOR-001 through STOR-002
8. **Admission Controllers & Policies (2 checks):** ADM-001 through ADM-002
9. **Namespace Management (2 checks):** NS-001 through NS-002

**Total Implemented Checks: 42**

All checks are fully implemented and verified using only Kubernetes APIs. The complete list of implemented checks is documented in detail above.

---

## Excluded Namespaces

By default, the following namespaces are excluded from most checks:

- `kube-system`
- `kube-public`
- `kube-node-lease`

Additional namespaces can be excluded using the `--exclude-namespaces` CLI flag.

## Kubernetes API Resources Used

All checks use only standard Kubernetes API clients:

- **CoreV1Api**: For pods, namespaces, ConfigMaps, Secrets, ServiceAccounts, PersistentVolumes, PersistentVolumeClaims, ResourceQuotas, LimitRanges
- **AppsV1Api**: For Deployments, StatefulSets, DaemonSets
- **NetworkingV1Api**: For NetworkPolicies, Ingresses, Services
- **RbacAuthorizationV1Api**: For Roles, RoleBindings, ClusterRoles, ClusterRoleBindings
- **AdmissionregistrationV1Api**: For ValidatingWebhookConfigurations, MutatingWebhookConfigurations
- **PolicyV1Api**: For PodDisruptionBudgets (if available)

No checks require:
- File system access to cluster nodes
- Access to API server configuration files
- External tools or binaries (kubectl, etc.)
- Network access beyond the Kubernetes API

All checks are performed using read-only API queries and inspection of resource specifications.

---

## Usage

```bash
# Generate a compliance report
kbase report

# Save report to file
kbase report --output report.md

# Exclude specific namespaces
kbase report --exclude-namespaces kube-system,monitoring

# Use a specific kubeconfig and context
kbase report --kubeconfig ~/.kube/config --context my-cluster

# JSON output format
kbase report --format json --output report.json
```

---

## References

- [Kubernetes Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [Kubernetes Resource Management](https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/)
- [Kubernetes Network Policies](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
- [Kubernetes RBAC](https://kubernetes.io/docs/reference/access-authn-authz/rbac/)
- [Kubernetes Audit Logging](https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/)
- [Kubernetes API Reference](https://kubernetes.io/docs/reference/kubernetes-api/)
