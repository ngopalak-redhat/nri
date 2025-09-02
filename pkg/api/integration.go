/*
   Copyright The containerd Authors.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

package api

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// ValidationConfig holds the complete validation configuration
type ValidationConfig struct {
	// Policy defines RBAC-style access control
	Policy *NRIValidationPolicySpec `yaml:"policy,omitempty" json:"policy,omitempty"`
	
	// Restrictions define technical mutation controls
	Restrictions *RestrictionsConfig `yaml:"restrictions,omitempty" json:"restrictions,omitempty"`
	
	// EnableDefaultValidator enables the existing default validator
	EnableDefaultValidator bool `yaml:"enableDefaultValidator" json:"enableDefaultValidator"`
	
	// DefaultValidatorConfig configures the default validator if enabled
	DefaultValidatorConfig map[string]interface{} `yaml:"defaultValidatorConfig,omitempty" json:"defaultValidatorConfig,omitempty"`
}

// ValidationManager manages all validation components
type ValidationManager struct {
	extendedValidator *ExtendedValidator
	config           ValidationConfig
}

// NewValidationManager creates a new validation manager
func NewValidationManager(config ValidationConfig) (*ValidationManager, error) {
	var defaultValidator interface {
		ValidateContainerAdjustment(context.Context, *ValidateContainerAdjustmentRequest) error
	}
	
	// Create default validator if enabled
	if config.EnableDefaultValidator {
		// This would integrate with the existing default validator
		// For now, we'll leave it nil and focus on the new validation
		defaultValidator = nil
	}
	
	// Create extended validator
	var policy NRIValidationPolicySpec
	if config.Policy != nil {
		policy = *config.Policy
	}
	
	extendedValidator := NewExtendedValidator(policy, config.Restrictions, defaultValidator)
	
	return &ValidationManager{
		extendedValidator: extendedValidator,
		config:           config,
	}, nil
}

// ValidateContainerAdjustment validates a container adjustment using all configured validators
func (vm *ValidationManager) ValidateContainerAdjustment(ctx context.Context, req *ValidateContainerAdjustmentRequest, subject *PolicySubject) error {
	validationCtx := &ValidationContext{
		Subject: subject,
	}
	
	if pod := req.GetPod(); pod != nil {
		validationCtx.PodNamespace = pod.GetNamespace()
		validationCtx.PodName = pod.GetName()
	}
	
	return vm.extendedValidator.ValidateContainerAdjustment(ctx, req, validationCtx)
}

// LoadConfigFromFile loads validation configuration from a YAML file
func LoadConfigFromFile(path string) (*ValidationConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file %s: %w", path, err)
	}
	
	var config ValidationConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config file %s: %w", path, err)
	}
	
	return &config, nil
}

// LoadConfigFromDir loads multiple config files from a directory
func LoadConfigFromDir(dir string) (*ValidationConfig, error) {
	files, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
	if err != nil {
		return nil, fmt.Errorf("failed to list config files in %s: %w", dir, err)
	}
	
	if len(files) == 0 {
		files, err = filepath.Glob(filepath.Join(dir, "*.yml"))
		if err != nil {
			return nil, fmt.Errorf("failed to list config files in %s: %w", dir, err)
		}
	}
	
	if len(files) == 0 {
		return nil, fmt.Errorf("no config files found in %s", dir)
	}
	
	var mergedConfig ValidationConfig
	
	for _, file := range files {
		config, err := LoadConfigFromFile(file)
		if err != nil {
			return nil, fmt.Errorf("failed to load config from %s: %w", file, err)
		}
		
		// Simple merge strategy - last file wins for conflicts
		if config.Policy != nil {
			mergedConfig.Policy = config.Policy
		}
		if config.Restrictions != nil {
			mergedConfig.Restrictions = config.Restrictions
		}
		if config.EnableDefaultValidator {
			mergedConfig.EnableDefaultValidator = config.EnableDefaultValidator
		}
		if config.DefaultValidatorConfig != nil {
			mergedConfig.DefaultValidatorConfig = config.DefaultValidatorConfig
		}
	}
	
	return &mergedConfig, nil
}

// ValidateConfig validates the configuration for consistency
func ValidateConfig(config *ValidationConfig) error {
	if config == nil {
		return fmt.Errorf("config cannot be nil")
	}
	
	// Validate policy structure
	if config.Policy != nil {
		if err := validatePolicy(*config.Policy); err != nil {
			return fmt.Errorf("invalid policy: %w", err)
		}
	}
	
	// Validate restrictions structure  
	if config.Restrictions != nil {
		if err := validateRestrictions(*config.Restrictions); err != nil {
			return fmt.Errorf("invalid restrictions: %w", err)
		}
	}
	
	return nil
}

// validatePolicy validates policy configuration
func validatePolicy(policy NRIValidationPolicySpec) error {
	for i, rule := range policy.Rules {
		if len(rule.Namespaces) == 0 {
			return fmt.Errorf("rule %d: namespaces cannot be empty", i)
		}
		
		if len(rule.Plugins) == 0 {
			return fmt.Errorf("rule %d: plugins cannot be empty", i)
		}
		
		if len(rule.Subjects) == 0 {
			return fmt.Errorf("rule %d: subjects cannot be empty", i)
		}
		
		for j, subject := range rule.Subjects {
			if subject.Kind == "" {
				return fmt.Errorf("rule %d, subject %d: kind cannot be empty", i, j)
			}
			if subject.Name == "" {
				return fmt.Errorf("rule %d, subject %d: name cannot be empty", i, j)
			}
			
			// Validate known subject kinds
			validKinds := []string{"User", "Group", "ServiceAccount"}
			found := false
			for _, kind := range validKinds {
				if subject.Kind == kind {
					found = true
					break
				}
			}
			if !found {
				return fmt.Errorf("rule %d, subject %d: invalid kind %s, must be one of: %v", i, j, subject.Kind, validKinds)
			}
		}
	}
	
	return nil
}

// validateRestrictions validates restrictions configuration
func validateRestrictions(restrictions RestrictionsConfig) error {
	// Validate default action
	if restrictions.DefaultAction != "" {
		if restrictions.DefaultAction != RestrictionAllow && restrictions.DefaultAction != RestrictionDeny {
			return fmt.Errorf("invalid defaultAction: must be 'allow' or 'deny'")
		}
	}
	
	// Validate global restrictions
	for i, restriction := range restrictions.GlobalRestrictions {
		if err := validateMutationRestriction(restriction); err != nil {
			return fmt.Errorf("global restriction %d: %w", i, err)
		}
	}
	
	// Validate plugin restrictions
	for i, pluginRestriction := range restrictions.PluginRestrictions {
		if pluginRestriction.PluginPattern == "" {
			return fmt.Errorf("plugin restriction %d: pluginPattern cannot be empty", i)
		}
		
		for j, mutationRestriction := range pluginRestriction.MutationRestrictions {
			if err := validateMutationRestriction(mutationRestriction); err != nil {
				return fmt.Errorf("plugin restriction %d, mutation restriction %d: %w", i, j, err)
			}
		}
	}
	
	return nil
}

// validateMutationRestriction validates a single mutation restriction
func validateMutationRestriction(restriction MutationRestriction) error {
	if restriction.Action != RestrictionAllow && restriction.Action != RestrictionDeny {
		return fmt.Errorf("invalid action: must be 'allow' or 'deny'")
	}
	
	if len(restriction.Capabilities) == 0 {
		return fmt.Errorf("capabilities cannot be empty")
	}
	
	// Validate capability names
	validCapabilities := []MutationCapability{
		MutationAnnotations, MutationMounts, MutationArgs, MutationEnv,
		MutationHooks, MutationRlimits, MutationDevices, MutationResources,
		MutationSeccomp, MutationNamespaces, MutationMemory, MutationCPU,
		MutationBlockIO, MutationRDT, MutationUnified,
	}
	
	for _, cap := range restriction.Capabilities {
		found := false
		for _, valid := range validCapabilities {
			if cap == valid {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("invalid capability: %s", cap)
		}
	}
	
	return nil
}

// CreateExampleConfig creates an example configuration file
func CreateExampleConfig(path string) error {
	config := ValidationConfig{
		EnableDefaultValidator: true,
		Policy: &NRIValidationPolicySpec{
			DefaultDeny: true,
			Rules: []PolicyRule{
				{
					Namespaces: []string{"dev-*"},
					Plugins:    []string{"*"},
					Subjects: []PolicySubject{
						{Kind: "User", Name: "developer-team"},
						{Kind: "ServiceAccount", Name: "dev-runner"},
					},
				},
				{
					Namespaces: []string{"production"},
					Plugins:    []string{"cpu-manager", "memory-manager"},
					Subjects: []PolicySubject{
						{Kind: "Group", Name: "platform-team"},
					},
				},
			},
		},
		Restrictions: &RestrictionsConfig{
			DefaultAction: RestrictionAllow,
			GlobalRestrictions: []MutationRestriction{
				{
					Action:       RestrictionDeny,
					Capabilities: []MutationCapability{MutationNamespaces, MutationSeccomp, MutationHooks},
				},
			},
		},
	}
	
	data, err := yaml.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}
	
	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}
	
	return nil
}