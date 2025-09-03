# NRI Policy Validator Kustomize Deployment

This directory contains Kustomize manifests for deploying the NRI Policy Validator plugin to Kubernetes clusters.

## Overview

The NRI Policy Validator enforces validation policies for container adjustments made by other NRI plugins. It provides:

- **RBAC-style access control**: Control who can use which plugins in which namespaces
- **Technical restrictions**: Block dangerous mutations like namespace modifications and seccomp changes
- **Fine-grained control**: Allowlist/denylist support for pods and mutation capabilities

## Deployment Options

### 1. Stable Release (Production)

Deploy the latest stable release:

```bash
kubectl apply -k github.com/containerd/nri/contrib/kustomize/policy-validator
```

### 2. Unstable Release (Testing)

Deploy the latest unstable/development version:

```bash
kubectl apply -k github.com/containerd/nri/contrib/kustomize/policy-validator/unstable
```

### 3. Development Environment

Deploy with more permissive settings for development:

```bash
kubectl apply -k github.com/containerd/nri/contrib/kustomize/policy-validator/dev
```

## Configuration

### Default Configuration

The base deployment includes a comprehensive policy configuration that:

- **Enables opt-in model**: `defaultDeny: true` requires explicit permission
- **Blocks dangerous mutations**: Prevents namespace, seccomp, and OCI hook modifications
- **Provides RBAC examples**: Sample rules for different user types and namespaces

### Custom Configuration

To customize the policy configuration:

1. **Copy the base ConfigMap**:
   ```bash
   kubectl get configmap nri-policy-validator-config -o yaml > my-policy.yaml
   ```

2. **Edit the configuration** in `my-policy.yaml`

3. **Apply the custom configuration**:
   ```bash
   kubectl apply -f my-policy.yaml
   ```

4. **Restart the DaemonSet** to pick up changes:
   ```bash
   kubectl rollout restart daemonset/nri-plugin-policy-validator
   ```

### Configuration Examples

#### Permissive Development Setup
```yaml
policy:
  defaultDeny: false  # Allow by default
restrictions:
  globalRestrictions:
    - action: deny
      capabilities: ["hooks"]  # Only block hook injection
```

#### Strict Production Setup
```yaml
policy:
  defaultDeny: true  # Explicit permission required
restrictions:
  globalRestrictions:
    - action: deny
      capabilities: ["namespaces", "seccomp", "hooks", "devices"]
```

## Subject Identification

The plugin identifies subjects through pod annotations. You'll need to set these annotations on your pods:

```yaml
metadata:
  annotations:
    nri.io/user: "developer-team"
    # or
    nri.io/group: "platform-team"  
    # or
    nri.io/service-account: "my-service-account"
```

These annotations are typically set by:
- Kubernetes admission controllers
- Service mesh systems
- CI/CD pipelines
- Manual pod specifications

## Monitoring

### Check Plugin Status

```bash
# Check DaemonSet status
kubectl get daemonset nri-plugin-policy-validator

# Check pod logs
kubectl logs -l app.kubernetes.io/name=nri-plugin-policy-validator

# Check specific pod
kubectl logs nri-plugin-policy-validator-<pod-id>
```

### Validation Logs

The plugin logs all validation decisions:

```
Policy validator configured for runtime containerd 1.7.0
Validation DENIED for container default/test-pod/app: policy validation failed: access denied
Validation ALLOWED for container dev-test/app/frontend
```

Use `-verbose` flag in the DaemonSet args for detailed logging.

## Security Considerations

### Plugin Index

The plugin runs with index `99` to validate **after** all mutating plugins have made their changes.

### Security Context

The DaemonSet runs with:
- `runAsNonRoot: true`
- `readOnlyRootFilesystem: true`
- `allowPrivilegeEscalation: false`
- Minimal capabilities (drops ALL)

### Network Security

The plugin only communicates via the local NRI socket (`/var/run/nri/nri.sock`).

## Troubleshooting

### Common Issues

1. **Plugin not starting**: Check if NRI is enabled in containerd/CRI-O
2. **Permission denied**: Ensure the NRI socket permissions are correct
3. **Config not loading**: Verify the ConfigMap is mounted correctly
4. **Validation failures**: Check pod annotations and policy rules

### Debug Steps

1. **Check NRI socket**:
   ```bash
   kubectl exec -it nri-plugin-policy-validator-<pod> -- ls -la /var/run/nri/
   ```

2. **Validate configuration**:
   ```bash
   kubectl get configmap nri-policy-validator-config -o yaml
   ```

3. **Test validation**:
   ```bash
   kubectl logs nri-plugin-policy-validator-<pod> -f
   # Then create a test pod to see validation logs
   ```

## Integration Examples

### With Admission Controllers

```yaml
apiVersion: admissionregistration.k8s.io/v1
kind: MutatingAdmissionWebhook
metadata:
  name: nri-subject-injector
webhooks:
- name: inject-nri-subject.example.com
  clientConfig:
    service:
      name: subject-injector
      namespace: default
      path: "/mutate"
  rules:
  - operations: ["CREATE"]
    apiGroups: [""]
    apiVersions: ["v1"]
    resources: ["pods"]
  admissionReviewVersions: ["v1", "v1beta1"]
```

### With Service Mesh

For Istio integration:
```yaml
metadata:
  annotations:
    nri.io/user: "{{ .Values.user | default "default-user" }}"
    sidecar.istio.io/inject: "true"
```

## Migration from Manual Deployment

If migrating from manual deployment:

1. **Stop manual plugin**:
   ```bash
   sudo systemctl stop nri-policy-validator
   ```

2. **Deploy via Kustomize**:
   ```bash
   kubectl apply -k github.com/containerd/nri/contrib/kustomize/policy-validator
   ```

3. **Verify deployment**:
   ```bash
   kubectl get pods -l app.kubernetes.io/name=nri-plugin-policy-validator
   ```

## Contributing

To contribute improvements to these manifests:

1. Test changes in a development environment
2. Ensure compatibility with different Kubernetes versions
3. Update documentation for any new configuration options
4. Follow the existing naming and labeling conventions