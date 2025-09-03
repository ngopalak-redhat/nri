# NRI Validation Policy Examples

This directory contains examples of the NRI validation policy system that implements the restrictions mechanism described in [issue #137](https://github.com/containerd/nri/issues/137).

## Overview

The validation policy system provides two levels of control:

1. **Technical Restrictions**: Control what types of mutations plugins can make (e.g., block namespace modifications, seccomp changes)
2. **RBAC-style Policies**: Control who can use which plugins in which namespaces

## Files

### Configuration Examples

- **`validation-policy.yaml`**: Complete example configuration showing both policy rules and technical restrictions

### Plugin Implementation

The policy validator plugin is available in the main plugins directory:
- **`plugins/policy-validator/`**: Complete implementation of the policy validator plugin

### Key Features

#### Technical Restrictions (Fine-grained mutation control)

```yaml
restrictions:
  globalRestrictions:
    - action: deny
      capabilities:
        - namespaces    # Block all namespace modifications
        - seccomp      # Block seccomp policy changes
        - hooks        # Block OCI hook injection
```

#### RBAC-style Policies (Access control)

```yaml
policy:
  defaultDeny: true
  rules:
    - namespaces: ["dev-*"]
      plugins: ["*"]
      subjects:
        - kind: User
          name: "developer-team"
        - kind: ServiceAccount  
          name: "dev-runner"
```

## Usage

### 1. Basic Policy Validation

Create a validation configuration file:

```yaml
# /etc/nri/validation.yaml
enableDefaultValidator: true
policy:
  defaultDeny: true
  rules:
    - namespaces: ["dev-*"]
      plugins: ["*"]
      subjects:
        - kind: User
          name: "developer-team"
restrictions:
  globalRestrictions:
    - action: deny
      capabilities: ["namespaces", "seccomp"]
```

### 2. Deploy the Validator Plugin

```bash
# Build the plugin
cd plugins/policy-validator
go build -o policy-validator policy-validator.go

# Run the plugin
./policy-validator -config /etc/nri/validation.yaml
```

### 3. Annotate Pods for Subject Identification

Pods need to be annotated to identify the subject making the request:

```yaml
apiVersion: v1
kind: Pod
metadata:
  annotations:
    nri.io/user: "developer-team"
    # or
    nri.io/group: "platform-team"
    # or  
    nri.io/service-account: "dev-runner"
spec:
  # ... pod spec
```

## Configuration Reference

### Policy Rules

Each rule defines:
- **namespaces**: List of namespace patterns (supports glob like "dev-*")
- **plugins**: List of allowed plugin patterns
- **subjects**: List of users/groups/service accounts that can use these plugins

### Restriction Capabilities

Available mutation capabilities to control:

- `annotations` - Container annotations
- `mounts` - Filesystem mounts  
- `args` - Command line arguments
- `env` - Environment variables
- `hooks` - OCI hooks
- `rlimits` - Resource limits
- `devices` - Device access
- `resources` - Resource allocations
- `seccomp` - Seccomp policies
- `namespaces` - Linux namespaces
- `memory` - Memory-specific resources
- `cpu` - CPU-specific resources
- `blockio` - Block I/O resources
- `rdt` - Intel RDT resources
- `unified` - Unified cgroup resources

### Action Types

- `allow` - Allowlist mode (only listed items are permitted)
- `deny` - Denylist mode (listed items are blocked)

## Use Cases

### 1. Development Environment

Allow developers broad access in dev namespaces but restrict production:

```yaml
policy:
  rules:
    - namespaces: ["dev-*", "staging-*"]
      plugins: ["*"]
      subjects:
        - kind: Group
          name: "developers"
```

### 2. Security Hardening

Block dangerous mutations globally:

```yaml
restrictions:
  globalRestrictions:
    - action: deny
      capabilities: ["namespaces", "seccomp", "hooks"]
```

### 3. Multi-tenant Isolation

Restrict untrusted plugins to safe operations:

```yaml
restrictions:
  pluginRestrictions:
    - pluginPattern: "tenant-*"
      mutationRestrictions:
        - action: allow
          capabilities: ["env", "annotations"]
      podRestrictions:
        - action: allow
          selector:
            namespaces: ["tenant-*"]
```

## Integration with Existing NRI

This system extends NRI's existing validation framework and is designed to work alongside:

- Default validator plugin
- Custom validator plugins
- Existing NRI plugins (they remain unchanged)

The policy validator runs as a separate NRI plugin and validates the combined mutations from all other plugins.

## Implementation Notes

### Subject Identification

The current implementation uses pod annotations to identify subjects. In production, you might integrate with:

- Kubernetes admission controllers
- Service mesh identity systems  
- External authentication/authorization systems

### Policy Storage

The examples use YAML files for policies. In production, you might use:

- Kubernetes ConfigMaps/Secrets
- External policy management systems
- Database storage with API access

### Performance Considerations

- The validator plugin should run with a high index (e.g., "99") to validate after all mutations
- Policy evaluation is designed to be fast with O(n) complexity for most operations
- Consider caching for frequently accessed policies in high-load environments