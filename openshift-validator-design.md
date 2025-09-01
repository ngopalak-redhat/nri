# OpenShift Validating NRI Plugin Design

Based on the transcript and codebase analysis, here's a design for the OpenShift-aware validating NRI plugin:

## Core Design: OpenShift Validating NRI Plugin

### Architecture Overview

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Mutating      │───▶│   Validating     │───▶│   Container     │
│   Plugins       │    │   Plugin         │    │   Creation      │
│   (ulimit, etc) │    │   (OpenShift)    │    │   Success/Fail  │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                               │
                               ▼
                       ┌──────────────────┐
                       │   Policy Store   │
                       │   (ConfigMaps/   │
                       │    CRDs/API)     │
                       └──────────────────┘
```

### 1. Plugin Structure

```go
// pkg/openshift/validator/plugin.go
type OpenShiftValidator struct {
    policyStore PolicyStore
    rbacClient  RBACInterface
    logger      log.Logger
}

type ValidationPolicy struct {
    // Namespace-level permissions
    NamespaceRules map[string]NamespacePolicy `yaml:"namespaceRules"`
    
    // Global rules (apply to all namespaces unless overridden)
    GlobalRules GlobalPolicy `yaml:"globalRules"`
    
    // Plugin-specific restrictions
    PluginRestrictions map[string]PluginPolicy `yaml:"pluginRestrictions"`
}

type NamespacePolicy struct {
    // Allowed mutations for this namespace
    AllowedMutations []MutationType `yaml:"allowedMutations"`
    
    // Allowed plugins for this namespace
    AllowedPlugins []string `yaml:"allowedPlugins"`
    
    // User/ServiceAccount restrictions
    UserRestrictions []UserPolicy `yaml:"userRestrictions"`
}
```

### 2. Key Components

#### A. Policy Store Interface
```go
type PolicyStore interface {
    GetPolicy(ctx context.Context) (*ValidationPolicy, error)
    WatchPolicy(ctx context.Context) (<-chan *ValidationPolicy, error)
}

// Implementations:
// - ConfigMapPolicyStore (for simple cases)
// - CRDPolicyStore (for complex cases) 
// - APIPolicyStore (for external policy systems)
```

#### B. RBAC Integration
```go
type RBACInterface interface {
    GetPodUser(ctx context.Context, pod *api.PodSandbox) (*UserContext, error)
    CanUserModify(ctx context.Context, user *UserContext, mutation MutationType, namespace string) (bool, error)
}

type UserContext struct {
    Username       string
    ServiceAccount string
    Groups         []string
    Namespace      string
}
```

#### C. Mutation Analysis
```go
type MutationType string

const (
    MutationTypeOCIHooks      MutationType = "oci-hooks"
    MutationTypeSeccomp       MutationType = "seccomp"
    MutationTypeNamespace     MutationType = "namespace"
    MutationTypeUlimit        MutationType = "ulimit"
    MutationTypeDevices       MutationType = "devices"
    MutationTypeResources     MutationType = "resources"
    MutationTypeMounts        MutationType = "mounts"
    MutationTypeEnvironment   MutationType = "environment"
    // ... more as needed
)

func (v *OpenShiftValidator) analyzeMutations(req *api.ValidateContainerAdjustmentRequest) ([]DetectedMutation, error) {
    var mutations []DetectedMutation
    
    // Analyze what each plugin changed
    for pluginName, changes := range req.Owners {
        mutations = append(mutations, DetectedMutation{
            Plugin:      pluginName,
            Type:        inferMutationType(changes),
            FieldPath:   changes.FieldPath,
            OldValue:    changes.OldValue,
            NewValue:    changes.NewValue,
        })
    }
    
    return mutations, nil
}
```

### 3. Validation Logic Flow

```go
func (v *OpenShiftValidator) ValidateContainerAdjustment(ctx context.Context, req *api.ValidateContainerAdjustmentRequest) error {
    // 1. Get user context from pod
    userCtx, err := v.rbacClient.GetPodUser(ctx, req.GetPod())
    if err != nil {
        return fmt.Errorf("failed to get user context: %w", err)
    }
    
    // 2. Load current policy
    policy, err := v.policyStore.GetPolicy(ctx)
    if err != nil {
        return fmt.Errorf("failed to load policy: %w", err)
    }
    
    // 3. Analyze what mutations were made
    mutations, err := v.analyzeMutations(req)
    if err != nil {
        return fmt.Errorf("failed to analyze mutations: %w", err)
    }
    
    // 4. Check each mutation against policy
    namespace := req.GetPod().GetNamespace()
    for _, mutation := range mutations {
        if !v.isMutationAllowed(policy, userCtx, namespace, mutation) {
            return fmt.Errorf("mutation %s by plugin %s denied for namespace %s, user %s", 
                mutation.Type, mutation.Plugin, namespace, userCtx.Username)
        }
    }
    
    return nil
}
```

### 4. Configuration Examples

#### Simple Namespace-based Config (ConfigMap)
```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: nri-validation-policy
  namespace: openshift-nri
data:
  policy.yaml: |
    globalRules:
      allowedMutations: []  # Deny all by default
      
    namespaceRules:
      "dev-team-a":
        allowedMutations: ["ulimit", "resources"]
        allowedPlugins: ["ulimit-adjuster", "cpu-pinning"]
        
      "prod-workloads":
        allowedMutations: ["resources"]
        allowedPlugins: ["cpu-pinning"]
        userRestrictions:
          - users: ["system:serviceaccount:prod-workloads:app-runner"]
            allowedMutations: ["resources"]
```

#### Advanced CRD-based Config
```yaml
apiVersion: nri.openshift.io/v1
kind: NRIValidationPolicy
metadata:
  name: cluster-policy
spec:
  defaultDeny: true  # Opt-in model
  
  rules:
    - namespaces: ["dev-*"]
      mutations: ["ulimit", "resources", "environment"]
      plugins: ["*"]
      subjects:
        - kind: User
          name: "developer-team"
        - kind: ServiceAccount
          name: "dev-runner"
          
    - namespaces: ["production"]
      mutations: ["resources"]
      plugins: ["cpu-manager", "memory-manager"]
      subjects:
        - kind: Group
          name: "platform-team"
```

### 5. Integration Points

#### A. Registration with NRI Runtime
```go
// cmd/openshift-nri-validator/main.go
func main() {
    config := loadConfig()
    
    validator := &OpenShiftValidator{
        policyStore: newConfigMapPolicyStore(config.PolicyConfigMap),
        rbacClient:  newKubernetesRBACClient(config.KubeConfig),
    }
    
    plugin := &builtin.BuiltinPlugin{
        Base:  "openshift-validator",
        Index: "99",  // Run last
        Handlers: builtin.BuiltinHandlers{
            ValidateContainerAdjustment: validator.ValidateContainerAdjustment,
        },
    }
    
    // Register with NRI runtime
    runtime.RegisterBuiltinPlugin(plugin)
}
```

#### B. OpenShift Integration
```go
// Integration with OpenShift RBAC
func (r *KubernetesRBACClient) GetPodUser(ctx context.Context, pod *api.PodSandbox) (*UserContext, error) {
    // Extract user info from pod annotations/labels set by OpenShift
    if sa := pod.GetLabels()["serviceaccount"]; sa != "" {
        return &UserContext{
            ServiceAccount: sa,
            Namespace:      pod.GetNamespace(),
            Username:       fmt.Sprintf("system:serviceaccount:%s:%s", pod.GetNamespace(), sa),
        }, nil
    }
    
    // Fallback to pod creator annotations
    if creator := pod.GetAnnotations()["openshift.io/scc"]; creator != "" {
        // Parse creator context
    }
    
    return nil, fmt.Errorf("unable to determine pod user context")
}
```

### 6. Deployment Strategy

1. **Built-in Plugin**: Ships with OpenShift, enabled via MachineConfig
2. **Policy Configuration**: ConfigMap in `openshift-nri` namespace  
3. **RBAC Integration**: Uses existing OpenShift user/SA context
4. **Monitoring**: Metrics on denied/allowed mutations
5. **Audit**: Log all validation decisions for compliance

This design provides:
- ✅ **Namespace awareness** via policy rules
- ✅ **RBAC integration** via OpenShift user context  
- ✅ **Plugin-specific controls** via mutation analysis
- ✅ **Opt-in security model** (deny by default)
- ✅ **Extensible policy store** for different config sources
- ✅ **OpenShift-specific** but with generic components

## Next Steps

1. **Short-term**: Contribute to NRI upstream to understand validation framework
2. **Medium-term**: Implement prototype OpenShift validator plugin
3. **Long-term**: Integrate with OpenShift console for policy management