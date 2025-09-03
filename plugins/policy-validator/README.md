# NRI Policy Validator Plugin

The NRI Policy Validator plugin enforces validation policies for container adjustments made by other NRI plugins. It implements the restrictions mechanism described in [issue #137](https://github.com/containerd/nri/issues/137).

## Overview

This plugin provides two levels of validation:

1. **Technical Restrictions**: Control what types of mutations plugins can make (e.g., block namespace modifications, seccomp changes)
2. **RBAC-style Policies**: Control who can use which plugins in which namespaces

## Features

- **Fine-grained mutation control**: Block or allow specific types of container modifications
- **Namespace-based rules**: Apply different policies to different namespace patterns
- **Subject-based access control**: Control access based on users, groups, and service accounts
- **Allowlist/denylist support**: Support both inclusive and exclusive policy models
- **Pod selection**: Target policies to specific pods based on labels and names
- **Integration with existing validation**: Works alongside NRI's built-in validation

## Configuration

The plugin is configured via a YAML file (default: `/etc/nri/validation.yaml`):

```yaml
# Enable existing default validator
enableDefaultValidator: true

# RBAC-style access control
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

    - namespaces: ["production"]
      plugins: ["cpu-manager", "memory-manager"]
      subjects:
        - kind: Group
          name: "platform-team"

# Technical mutation restrictions
restrictions:
  defaultAction: allow
  
  globalRestrictions:
    - action: deny
      capabilities: ["namespaces", "seccomp", "hooks"]
  
  pluginRestrictions:
    - pluginPattern: "untrusted-*"
      mutationRestrictions:
        - action: allow
          capabilities: ["annotations", "env"]
      podRestrictions:
        - action: allow
          selector:
            namespaces: ["sandbox-*"]
```

## Usage

### Command Line Options

```bash
./policy-validator [options]

Options:
  -config string
        Path to validation configuration file (default "/etc/nri/validation.yaml")
  -verbose
        Enable verbose logging (default false)
```

### Installation

1. **Build the plugin:**
   ```bash
   cd plugins/policy-validator
   go build -o policy-validator policy-validator.go
   ```

2. **Create configuration:**
   ```bash
   sudo mkdir -p /etc/nri
   sudo cp validation-policy.yaml /etc/nri/validation.yaml
   ```

3. **Run the plugin:**
   ```bash
   sudo ./policy-validator
   ```

### System Installation

Install as a system service:

```bash
# Install the plugin
sudo cp policy-validator /usr/local/bin/

# Install configuration
sudo mkdir -p /etc/nri
sudo cp validation-policy.yaml /etc/nri/validation.yaml

# Create systemd service (optional)
sudo systemctl enable nri-policy-validator
sudo systemctl start nri-policy-validator
```

## Subject Identification

The plugin identifies subjects through pod annotations:

- **User**: `nri.io/user: "username"`
- **Group**: `nri.io/group: "groupname"`  
- **Service Account**: `nri.io/service-account: "sa-name"` (or uses "default")

These annotations should be set by admission controllers or other pod modification mechanisms.

## Policy Rules

### Namespace Patterns

Support glob patterns:
- `dev-*` - matches "dev-test", "dev-staging", etc.
- `*-prod` - matches "app-prod", "web-prod", etc.
- `production` - exact match

### Plugin Patterns

Control which plugins can be used:
- `*` - all plugins allowed
- `cpu-manager` - specific plugin
- `trusted-*` - pattern matching

### Subjects

Support three types:
- `User` - human users
- `Group` - user groups  
- `ServiceAccount` - Kubernetes service accounts

### Mutation Capabilities

Available capabilities to control:

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

## Use Cases

### 1. Development Environment

Allow developers broad access in dev namespaces:

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

Restrict tenant plugins to safe operations:

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

## Validation Flow

1. **Container adjustment requested** by mutating plugins
2. **Default validation** (if enabled) runs first
3. **Technical restrictions** validate mutation types
4. **Policy rules** validate subject access
5. **Result**: Allow or deny the adjustment

## Logging

The plugin provides detailed logging:

- **Startup**: Configuration loading and validation
- **Runtime**: Validation decisions and policy matches
- **Verbose mode**: Detailed request/response logging

Example log output:
```
2023/09/03 Policy validator configured for runtime containerd 1.7.0
2023/09/03 Validation DENIED for container default/test-pod/app: policy validation failed: access denied: no matching rule allows this subject/plugin combination
2023/09/03 Validation ALLOWED for container dev-test/app/frontend
```

## Security Considerations

- **Plugin Index**: Set to "99" to run after all mutating plugins
- **Fail-safe**: Any validation error results in request denial
- **Defense in Depth**: Multiple validation layers provide comprehensive security
- **Audit Trail**: All decisions are logged for security monitoring

## Configuration Examples

See the `examples/` directory for complete configuration examples:

- Basic policy validation
- Security hardening
- Multi-tenant isolation
- Development vs production environments

## Integration

This plugin integrates with:

- **Existing NRI plugins**: Validates their mutations without modification
- **Default validator**: Can run alongside existing validation
- **Kubernetes admission controllers**: Uses annotations set by admission webhooks
- **External policy systems**: Can be extended to integrate with OPA, etc.

## Troubleshooting

### Common Issues

1. **Configuration not found**: Ensure `/etc/nri/validation.yaml` exists and is readable
2. **Permission denied**: Run with appropriate privileges to access NRI socket
3. **Policy violations**: Check logs for specific policy rule failures
4. **Missing annotations**: Ensure pods have required subject annotations

### Debug Mode

Enable verbose logging:
```bash
./policy-validator -verbose
```

### Configuration Validation

Test configuration before deployment:
```bash
./policy-validator -config test-config.yaml
# Check logs for validation errors
```