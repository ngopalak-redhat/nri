# NRI Validation Policy System Design Document

## Overview

This document describes the implementation of the NRI Validation Policy system, which addresses [issue #137](https://github.com/containerd/nri/issues/137) by providing fine-grained control over NRI plugin capabilities and access controls.

## Background and Motivation

### Problem Statement

As noted in issue #137, NRI plugins currently operate with broad privileges that can potentially:
- Escape to the host through mount or device adjustments
- Modify security-sensitive settings like seccomp policies, namespaces, and OCI hooks
- Override policies set by cluster orchestrators

### Goals

1. **Fine-grained mutation control**: Allow administrators to control what types of mutations plugins can make
2. **Access control**: Provide RBAC-style controls over who can use which plugins in which namespaces
3. **Incremental security**: Improve security without breaking existing functionality
4. **Flexible configuration**: Support both allowlist and denylist approaches

## Architecture

The validation policy system consists of three main components:

```
┌─────────────────────────────────────────────────────────────┐
│                  Validation Policy System                  │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────┐ │
│  │   Technical     │  │   RBAC-Style    │  │ Integration │ │
│  │  Restrictions   │  │    Policies     │  │   Manager   │ │
│  │                 │  │                 │  │             │ │
│  │ • Mutation      │  │ • User/Group    │  │ • Config    │ │
│  │   Capabilities  │  │   Access        │  │   Loading   │ │
│  │ • Pod Selectors │  │ • Plugin        │  │ • Validation│ │
│  │ • Allow/Deny    │  │   Authorization │  │ • Management│ │
│  └─────────────────┘  └─────────────────┘  └─────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

## Implementation Details

### 1. Technical Restrictions (`pkg/api/restrictions.go`)

#### Core Types

```go
type MutationCapability string
const (
    MutationAnnotations   MutationCapability = "annotations"
    MutationMounts        MutationCapability = "mounts"
    MutationArgs          MutationCapability = "args"
    MutationEnv           MutationCapability = "env"
    MutationHooks         MutationCapability = "hooks"
    MutationRlimits       MutationCapability = "rlimits"
    MutationDevices       MutationCapability = "devices"
    MutationResources     MutationCapability = "resources"
    MutationSeccomp       MutationCapability = "seccomp"
    MutationNamespaces    MutationCapability = "namespaces"
    // ... more capabilities
)
```

#### Key Features

- **Mutation Capability Detection**: Automatically analyzes `ContainerAdjustment` to determine what mutations are being attempted
- **Global and Plugin-specific Restrictions**: Apply restrictions across all plugins or target specific plugin patterns
- **Pod Selection**: Control which pods can be modified based on namespace patterns, labels, and names
- **Allow/Deny Lists**: Support both allowlist (only specified items allowed) and denylist (specified items blocked) modes

#### Example Usage

```yaml
restrictions:
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

### 2. RBAC-Style Policies (`pkg/api/policy_validator.go`)

#### Core Types

```go
type NRIValidationPolicySpec struct {
    DefaultDeny bool         `yaml:"defaultDeny"`
    Rules       []PolicyRule `yaml:"rules"`
}

type PolicyRule struct {
    Namespaces []string        `yaml:"namespaces"`
    Plugins    []string        `yaml:"plugins"`
    Subjects   []PolicySubject `yaml:"subjects"`
}

type PolicySubject struct {
    Kind string `yaml:"kind"` // User, Group, ServiceAccount
    Name string `yaml:"name"`
}
```

#### Key Features

- **Namespace-based Rules**: Apply different rules to different namespace patterns
- **Plugin Authorization**: Control which plugins can be used by which subjects
- **Subject Types**: Support for Users, Groups, and ServiceAccounts
- **Default Deny**: Opt-in security model where access must be explicitly granted

#### Example Usage

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
    
    - namespaces: ["production"]
      plugins: ["cpu-manager", "memory-manager"]
      subjects:
        - kind: Group
          name: "platform-team"
```

### 3. Integration Management (`pkg/api/integration.go`)

#### Key Features

- **Configuration Loading**: Load policies from YAML files or directories
- **Configuration Validation**: Validate policy structure and consistency
- **Multi-layer Validation**: Combine default, technical, and policy validation
- **Runtime Management**: Dynamic policy updates and management

#### ValidationManager

```go
type ValidationManager struct {
    extendedValidator *ExtendedValidator
    config           ValidationConfig
}
```

The `ValidationManager` orchestrates all validation layers:

1. **Default Validation**: Existing NRI validation logic
2. **Technical Restrictions**: Mutation capability controls
3. **Policy Validation**: RBAC-style access controls

## File Structure

```
pkg/api/
├── restrictions.go           # Technical mutation restrictions
├── policy_validator.go       # RBAC-style policy validation
├── integration.go           # Configuration management and integration
└── validate.go             # Existing validation (enhanced)

examples/
├── validation-policy.yaml   # Complete configuration examples
├── policy-validator-plugin/ # Example validator plugin implementation
│   └── main.go
└── README.md               # Usage documentation and examples
```

## Configuration Format

### Complete Example

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

## Usage Patterns

### 1. Development Environment Security

**Scenario**: Allow developers broad access in development namespaces while restricting production access.

```yaml
policy:
  defaultDeny: true
  rules:
    - namespaces: ["dev-*", "staging-*"]
      plugins: ["*"]
      subjects:
        - kind: Group
          name: "developers"
    
    - namespaces: ["production", "prod-*"]
      plugins: ["approved-plugins-*"]
      subjects:
        - kind: Group
          name: "platform-team"
```

### 2. Security Hardening

**Scenario**: Block dangerous mutations globally while allowing safe operations.

```yaml
restrictions:
  globalRestrictions:
    - action: deny
      capabilities: ["namespaces", "seccomp", "hooks"]
  
  defaultAction: allow  # Allow other mutations
```

### 3. Multi-tenant Isolation

**Scenario**: Restrict tenant plugins to only affect their own namespaces and limit mutation types.

```yaml
restrictions:
  pluginRestrictions:
    - pluginPattern: "tenant-*"
      mutationRestrictions:
        - action: allow
          capabilities: ["env", "annotations", "resources"]
      podRestrictions:
        - action: allow
          selector:
            namespaces: ["tenant-*"]
        - action: deny
          selector:
            labels:
              "security.level": "high"
```

## Validation Flow

```
Container Adjustment Request
            │
            ▼
    ┌─────────────────┐
    │ Default         │
    │ Validation      │
    │ (existing NRI)  │
    └─────────┬───────┘
              │
              ▼
    ┌─────────────────┐
    │ Technical       │
    │ Restrictions    │
    │ Validation      │
    └─────────┬───────┘
              │
              ▼
    ┌─────────────────┐
    │ Policy          │
    │ (RBAC)          │
    │ Validation      │
    └─────────┬───────┘
              │
              ▼
        Allow/Deny
```

## Security Considerations

### 1. Defense in Depth

The system provides multiple layers of security:

- **Technical Restrictions**: Prevent dangerous mutations regardless of who requests them
- **Policy Controls**: Ensure only authorized subjects can use specific plugins
- **Namespace Isolation**: Limit plugin scope to appropriate namespaces

### 2. Fail-Safe Defaults

- **Default Deny**: When `defaultDeny: true`, access must be explicitly granted
- **Validation Failure**: Any validation failure results in request denial
- **Unknown Capabilities**: New mutation types are blocked until explicitly allowed

### 3. Audit and Monitoring

The system provides comprehensive logging:
- All validation decisions are logged
- Policy violations are clearly identified
- Subject identification is tracked for audit purposes

## Migration and Compatibility

### Backward Compatibility

- **Existing Plugins**: Continue to work unchanged
- **Existing Validation**: Default validator remains functional
- **Gradual Adoption**: Policies can be introduced incrementally

### Migration Strategy

1. **Phase 1**: Deploy with `defaultDeny: false` to monitor current usage
2. **Phase 2**: Add technical restrictions for dangerous mutations
3. **Phase 3**: Implement RBAC policies with `defaultDeny: true`
4. **Phase 4**: Fine-tune based on operational experience

## Performance Considerations

### Optimization Strategies

- **Policy Caching**: Frequently accessed policies are cached in memory
- **Early Termination**: Validation stops at first failure
- **Efficient Matching**: Glob patterns use optimized string matching
- **Minimal Overhead**: O(n) complexity for most operations

### Resource Usage

- **Memory**: Policies stored in memory for fast access
- **CPU**: Minimal per-request processing overhead
- **I/O**: Configuration loaded once at startup

## Future Extensions

### Planned Enhancements

1. **Mutation-Specific Rules**: Enable/disable specific mutation types per rule
2. **Advanced Selectors**: More sophisticated pod selection criteria
3. **Dynamic Updates**: Runtime policy updates without restart
4. **External Integration**: Integration with external policy systems (OPA, etc.)

### API Evolution

The system is designed for extensibility:

```go
// Future: Mutation-specific rules
type PolicyRule struct {
    Namespaces []string        `yaml:"namespaces"`
    Plugins    []string        `yaml:"plugins"`
    Subjects   []PolicySubject `yaml:"subjects"`
    Mutations  []string        `yaml:"mutations,omitempty"` // Future
}
```

## Testing Strategy

### Unit Tests

- **Policy Matching**: Test namespace, plugin, and subject matching logic
- **Restriction Validation**: Test mutation capability detection and validation
- **Configuration Parsing**: Test YAML parsing and validation

### Integration Tests

- **End-to-End Validation**: Test complete validation flow
- **Plugin Integration**: Test with actual NRI plugins
- **Error Scenarios**: Test various failure modes

### Example Test Cases

```go
func TestPolicyValidation(t *testing.T) {
    tests := []struct {
        name        string
        policy      NRIValidationPolicySpec
        request     *ValidateContainerAdjustmentRequest
        subject     *PolicySubject
        expectAllow bool
    }{
        {
            name: "developer in dev namespace allowed",
            policy: NRIValidationPolicySpec{
                DefaultDeny: true,
                Rules: []PolicyRule{{
                    Namespaces: []string{"dev-*"},
                    Plugins:    []string{"*"},
                    Subjects:   []PolicySubject{{Kind: "User", Name: "dev-user"}},
                }},
            },
            // ... test setup
            expectAllow: true,
        },
        // ... more test cases
    }
}
```

## Conclusion

The NRI Validation Policy system provides a comprehensive solution for controlling NRI plugin capabilities and access. It addresses the security concerns raised in issue #137 while maintaining backward compatibility and providing a path for gradual adoption.

The system's layered approach ensures defense in depth, while its flexible configuration format allows for a wide range of deployment scenarios from development environments to production multi-tenant clusters.

## References

- [NRI Issue #137](https://github.com/containerd/nri/issues/137) - Original feature request
- [NRI Documentation](https://github.com/containerd/nri/blob/main/README.md) - General NRI overview
- [Container Validation](https://github.com/containerd/nri/blob/main/README.md#container-adjustment-validation) - Existing validation framework