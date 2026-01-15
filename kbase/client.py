"""Kubernetes API client wrapper."""

from typing import Optional, Dict, List, Any
from kubernetes import client, config
from kubernetes.client import (
    V1Pod,
    V1Namespace,
    V1Deployment,
    V1StatefulSet,
    V1DaemonSet,
    V1Service,
    V1ConfigMap,
    V1Secret,
    V1NetworkPolicy,
    V1ResourceQuota,
    V1LimitRange,
    V1Node,
    V1Ingress,
    V1ClusterRole,
    V1ClusterRoleBinding,
    V1Role,
    V1RoleBinding,
    V1PodDisruptionBudget,
    V1PersistentVolume,
    V1PersistentVolumeClaim,
    RbacAuthorizationV1Api,
    CoreV1Api,
    AppsV1Api,
    NetworkingV1Api,
    StorageV1Api,
    AdmissionregistrationV1Api,
)

try:
    from kubernetes.client import PolicyV1Api
except ImportError:
    # PolicyV1Api might not be available in older kubernetes-client versions
    PolicyV1Api = None
from kubernetes.config.config_exception import ConfigException
import logging

logger = logging.getLogger(__name__)


class KubernetesClient:
    """Wrapper for Kubernetes API client with error handling."""

    def __init__(self, kubeconfig: Optional[str] = None, context: Optional[str] = None):
        """Initialize Kubernetes client.
        
        Args:
            kubeconfig: Path to kubeconfig file (defaults to ~/.kube/config)
            context: Kubernetes context to use
        """
        try:
            if kubeconfig:
                config.load_kube_config(config_file=kubeconfig, context=context)
            else:
                config.load_kube_config(context=context)
            logger.info("Successfully loaded kubeconfig")
        except ConfigException as e:
            raise RuntimeError(f"Failed to load kubeconfig: {e}")

        self.core_v1 = CoreV1Api()
        self.apps_v1 = AppsV1Api()
        self.networking_v1 = NetworkingV1Api()
        self.rbac_v1 = RbacAuthorizationV1Api()
        self.storage_v1 = StorageV1Api()
        self.admissionregistration_v1 = AdmissionregistrationV1Api()
        if PolicyV1Api is not None:
            try:
                self.policy_v1 = PolicyV1Api()
            except Exception:
                # PolicyV1Api might not be available in older clusters
                self.policy_v1 = None
        else:
            self.policy_v1 = None

        # Cache cluster info
        self._cluster_info: Optional[Dict[str, Any]] = None

    def get_cluster_info(self) -> Dict[str, Any]:
        """Get cluster information."""
        if self._cluster_info is None:
            try:
                version = self.core_v1.get_code()
                nodes = self.core_v1.list_node()
                
                self._cluster_info = {
                    "version": version.git_version if hasattr(version, 'git_version') else "unknown",
                    "platform": version.platform if hasattr(version, 'platform') else "unknown",
                    "node_count": len(nodes.items),
                    "nodes": [
                        {
                            "name": node.metadata.name,
                            "kubelet_version": node.status.node_info.kubelet_version,
                            "os": node.status.node_info.operating_system,
                            "cpu_capacity": node.status.capacity.get("cpu", "0"),
                            "memory_capacity": node.status.capacity.get("memory", "0"),
                        }
                        for node in nodes.items
                    ]
                }
            except Exception as e:
                logger.warning(f"Failed to get cluster info: {e}")
                self._cluster_info = {
                    "version": "unknown",
                    "platform": "unknown",
                    "node_count": 0,
                    "nodes": []
                }
        return self._cluster_info

    def list_namespaces(self) -> List[V1Namespace]:
        """List all namespaces."""
        try:
            return self.core_v1.list_namespace().items
        except Exception as e:
            logger.error(f"Failed to list namespaces: {e}")
            return []

    def list_pods(self, namespace: Optional[str] = None) -> List[V1Pod]:
        """List all pods, optionally filtered by namespace."""
        try:
            if namespace:
                return self.core_v1.list_namespaced_pod(namespace).items
            else:
                return self.core_v1.list_pod_for_all_namespaces().items
        except Exception as e:
            logger.error(f"Failed to list pods: {e}")
            return []

    def list_deployments(self, namespace: Optional[str] = None) -> List[V1Deployment]:
        """List all deployments, optionally filtered by namespace."""
        try:
            if namespace:
                return self.apps_v1.list_namespaced_deployment(namespace).items
            else:
                return self.apps_v1.list_deployment_for_all_namespaces().items
        except Exception as e:
            logger.error(f"Failed to list deployments: {e}")
            return []

    def list_statefulsets(self, namespace: Optional[str] = None) -> List[V1StatefulSet]:
        """List all statefulsets, optionally filtered by namespace."""
        try:
            if namespace:
                return self.apps_v1.list_namespaced_stateful_set(namespace).items
            else:
                return self.apps_v1.list_stateful_set_for_all_namespaces().items
        except Exception as e:
            logger.error(f"Failed to list statefulsets: {e}")
            return []

    def list_daemonsets(self, namespace: Optional[str] = None) -> List[V1DaemonSet]:
        """List all daemonsets, optionally filtered by namespace."""
        try:
            if namespace:
                return self.apps_v1.list_namespaced_daemon_set(namespace).items
            else:
                return self.apps_v1.list_daemon_set_for_all_namespaces().items
        except Exception as e:
            logger.error(f"Failed to list daemonsets: {e}")
            return []

    def list_services(self, namespace: Optional[str] = None) -> List[V1Service]:
        """List all services, optionally filtered by namespace."""
        try:
            if namespace:
                return self.core_v1.list_namespaced_service(namespace).items
            else:
                return self.core_v1.list_service_for_all_namespaces().items
        except Exception as e:
            logger.error(f"Failed to list services: {e}")
            return []

    def list_configmaps(self, namespace: Optional[str] = None) -> List[V1ConfigMap]:
        """List all configmaps, optionally filtered by namespace."""
        try:
            if namespace:
                return self.core_v1.list_namespaced_config_map(namespace).items
            else:
                return self.core_v1.list_config_map_for_all_namespaces().items
        except Exception as e:
            logger.error(f"Failed to list configmaps: {e}")
            return []

    def list_secrets(self, namespace: Optional[str] = None) -> List[V1Secret]:
        """List all secrets, optionally filtered by namespace."""
        try:
            if namespace:
                return self.core_v1.list_namespaced_secret(namespace).items
            else:
                return self.core_v1.list_secret_for_all_namespaces().items
        except Exception as e:
            logger.error(f"Failed to list secrets: {e}")
            return []

    def list_network_policies(self, namespace: Optional[str] = None) -> List[V1NetworkPolicy]:
        """List all network policies, optionally filtered by namespace."""
        try:
            if namespace:
                return self.networking_v1.list_namespaced_network_policy(namespace).items
            else:
                return self.networking_v1.list_network_policy_for_all_namespaces().items
        except Exception as e:
            logger.error(f"Failed to list network policies: {e}")
            return []

    def list_resource_quotas(self, namespace: Optional[str] = None) -> List[V1ResourceQuota]:
        """List all resource quotas, optionally filtered by namespace."""
        try:
            if namespace:
                return self.core_v1.list_namespaced_resource_quota(namespace).items
            else:
                return self.core_v1.list_resource_quota_for_all_namespaces().items
        except Exception as e:
            logger.error(f"Failed to list resource quotas: {e}")
            return []

    def list_limit_ranges(self, namespace: Optional[str] = None) -> List[V1LimitRange]:
        """List all limit ranges, optionally filtered by namespace."""
        try:
            if namespace:
                return self.core_v1.list_namespaced_limit_range(namespace).items
            else:
                return self.core_v1.list_limit_range_for_all_namespaces().items
        except Exception as e:
            logger.error(f"Failed to list limit ranges: {e}")
            return []

    def list_ingresses(self, namespace: Optional[str] = None) -> List[V1Ingress]:
        """List all ingresses, optionally filtered by namespace."""
        try:
            if namespace:
                return self.networking_v1.list_namespaced_ingress(namespace).items
            else:
                return self.networking_v1.list_ingress_for_all_namespaces().items
        except Exception as e:
            logger.error(f"Failed to list ingresses: {e}")
            return []

    def list_nodes(self) -> List[V1Node]:
        """List all nodes."""
        try:
            return self.core_v1.list_node().items
        except Exception as e:
            logger.error(f"Failed to list nodes: {e}")
            return []

    def list_cluster_roles(self) -> List[V1ClusterRole]:
        """List all cluster roles."""
        try:
            return self.rbac_v1.list_cluster_role().items
        except Exception as e:
            logger.error(f"Failed to list cluster roles: {e}")
            return []

    def list_cluster_role_bindings(self) -> List[V1ClusterRoleBinding]:
        """List all cluster role bindings."""
        try:
            return self.rbac_v1.list_cluster_role_binding().items
        except Exception as e:
            logger.error(f"Failed to list cluster role bindings: {e}")
            return []

    def list_role_bindings(self, namespace: Optional[str] = None) -> List[V1RoleBinding]:
        """List all role bindings, optionally filtered by namespace."""
        try:
            if namespace:
                return self.rbac_v1.list_namespaced_role_binding(namespace).items
            else:
                return self.rbac_v1.list_role_binding_for_all_namespaces().items
        except Exception as e:
            logger.error(f"Failed to list role bindings: {e}")
            return []

    def list_service_accounts(self, namespace: Optional[str] = None) -> List:
        """List all service accounts, optionally filtered by namespace."""
        try:
            if namespace:
                return self.core_v1.list_namespaced_service_account(namespace).items
            else:
                return self.core_v1.list_service_account_for_all_namespaces().items
        except Exception as e:
            logger.error(f"Failed to list service accounts: {e}")
            return []

    def list_pod_disruption_budgets(self, namespace: Optional[str] = None) -> List[V1PodDisruptionBudget]:
        """List all pod disruption budgets, optionally filtered by namespace."""
        if not self.policy_v1:
            return []
        try:
            if namespace:
                return self.policy_v1.list_namespaced_pod_disruption_budget(namespace).items
            else:
                return self.policy_v1.list_pod_disruption_budget_for_all_namespaces().items
        except Exception as e:
            logger.error(f"Failed to list pod disruption budgets: {e}")
            return []

    def list_persistent_volumes(self) -> List[V1PersistentVolume]:
        """List all persistent volumes."""
        try:
            return self.core_v1.list_persistent_volume().items
        except Exception as e:
            logger.error(f"Failed to list persistent volumes: {e}")
            return []

    def list_persistent_volume_claims(self, namespace: Optional[str] = None) -> List[V1PersistentVolumeClaim]:
        """List all persistent volume claims, optionally filtered by namespace."""
        try:
            if namespace:
                return self.core_v1.list_namespaced_persistent_volume_claim(namespace).items
            else:
                return self.core_v1.list_persistent_volume_claim_for_all_namespaces().items
        except Exception as e:
            logger.error(f"Failed to list persistent volume claims: {e}")
            return []
