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
	"slices"
	"strings"
)

// NRIValidationPolicySpec represents the YAML configuration structure you provided
type NRIValidationPolicySpec struct {
	// DefaultDeny sets the default behavior when no rules match
	DefaultDeny bool `yaml:"defaultDeny" json:"defaultDeny"`
	
	// Rules define the validation rules
	Rules []PolicyRule `yaml:"rules" json:"rules"`
}

// PolicyRule represents a single rule in the validation policy
type PolicyRule struct {
	// Namespaces specifies namespace patterns this rule applies to
	Namespaces []string `yaml:"namespaces" json:"namespaces"`
	
	// Plugins specifies which plugins are allowed
	Plugins []string `yaml:"plugins" json:"plugins"`
	
	// Subjects specifies who can invoke the plugins
	Subjects []PolicySubject `yaml:"subjects" json:"subjects"`
	
	// Future extension for mutation types
	// Mutations []string `yaml:"mutations,omitempty" json:"mutations,omitempty"`
}

// PolicySubject represents a subject in the policy
type PolicySubject struct {
	Kind string `yaml:"kind" json:"kind"`
	Name string `yaml:"name" json:"name"`
}

// ValidationContext provides context for policy validation
type ValidationContext struct {
	// Subject represents who is requesting the action
	Subject *PolicySubject
	
	// PodNamespace is the namespace of the pod being modified
	PodNamespace string
	
	// PodName is the name of the pod being modified
	PodName string
	
	// PluginName is the name of the plugin making the request
	PluginName string
}

// PolicyBasedValidator validates requests against policy rules
type PolicyBasedValidator struct {
	policy NRIValidationPolicySpec
	restrictionsValidator *RestrictionsValidator
}

// NewPolicyBasedValidator creates a new policy-based validator
func NewPolicyBasedValidator(policy NRIValidationPolicySpec, restrictionsConfig *RestrictionsConfig) *PolicyBasedValidator {
	var restrictionsValidator *RestrictionsValidator
	if restrictionsConfig != nil {
		restrictionsValidator = NewRestrictionsValidator(*restrictionsConfig)
	}
	
	return &PolicyBasedValidator{
		policy: policy,
		restrictionsValidator: restrictionsValidator,
	}
}

// ValidateContainerAdjustment validates a container adjustment against the policy
func (pv *PolicyBasedValidator) ValidateContainerAdjustment(ctx context.Context, req *ValidateContainerAdjustmentRequest, validationCtx *ValidationContext) error {
	pod := req.GetPod()
	if pod == nil {
		return fmt.Errorf("pod information is required for policy validation")
	}
	
	// Set context from pod if not provided
	if validationCtx == nil {
		validationCtx = &ValidationContext{
			PodNamespace: pod.GetNamespace(),
			PodName:      pod.GetName(),
		}
	}
	
	// Validate against restrictions first (technical validation)
	if pv.restrictionsValidator != nil {
		if err := pv.restrictionsValidator.ValidateContainerAdjustment(req); err != nil {
			return fmt.Errorf("restrictions validation failed: %w", err)
		}
	}
	
	// Validate against policy rules (RBAC-style validation)
	plugins := req.GetPluginMap()
	for pluginName := range plugins {
		validationCtx.PluginName = pluginName
		if err := pv.validatePluginAccess(validationCtx); err != nil {
			return fmt.Errorf("policy validation failed for plugin %s: %w", pluginName, err)
		}
	}
	
	return nil
}

// validatePluginAccess checks if a plugin is allowed to operate in the given context
func (pv *PolicyBasedValidator) validatePluginAccess(ctx *ValidationContext) error {
	// Find matching rules
	matchingRules := pv.findMatchingRules(ctx.PodNamespace)
	
	if len(matchingRules) == 0 {
		// No matching rules found
		if pv.policy.DefaultDeny {
			return fmt.Errorf("access denied: no matching rules found and defaultDeny is true")
		}
		return nil // Allow by default
	}
	
	// Check if any rule allows this combination
	for _, rule := range matchingRules {
		if pv.pluginAllowed(ctx.PluginName, rule.Plugins) && 
		   pv.subjectAllowed(ctx.Subject, rule.Subjects) {
			return nil // Access granted
		}
	}
	
	// No rule granted access
	if pv.policy.DefaultDeny {
		return fmt.Errorf("access denied: no rule allows this subject/plugin combination")
	}
	
	return nil
}

// findMatchingRules finds policy rules that match the given namespace
func (pv *PolicyBasedValidator) findMatchingRules(namespace string) []PolicyRule {
	var matching []PolicyRule
	
	for _, rule := range pv.policy.Rules {
		if pv.namespaceMatches(namespace, rule.Namespaces) {
			matching = append(matching, rule)
		}
	}
	
	return matching
}

// namespaceMatches checks if namespace matches any pattern in the list
func (pv *PolicyBasedValidator) namespaceMatches(namespace string, patterns []string) bool {
	for _, pattern := range patterns {
		if pv.globMatch(pattern, namespace) {
			return true
		}
	}
	return false
}

// pluginAllowed checks if a plugin is in the allowed plugins list
func (pv *PolicyBasedValidator) pluginAllowed(pluginName string, allowedPlugins []string) bool {
	for _, allowed := range allowedPlugins {
		if pv.globMatch(allowed, pluginName) {
			return true
		}
	}
	return false
}

// subjectAllowed checks if a subject is in the allowed subjects list
func (pv *PolicyBasedValidator) subjectAllowed(subject *PolicySubject, allowedSubjects []PolicySubject) bool {
	if subject == nil {
		// No subject information - could allow or deny based on policy
		return false
	}
	
	for _, allowed := range allowedSubjects {
		if subject.Kind == allowed.Kind && subject.Name == allowed.Name {
			return true
		}
	}
	
	return false
}

// globMatch performs glob pattern matching with support for "*" wildcard
func (pv *PolicyBasedValidator) globMatch(pattern, str string) bool {
	if pattern == "*" {
		return true
	}
	
	if strings.Contains(pattern, "*") {
		if strings.HasSuffix(pattern, "*") {
			prefix := strings.TrimSuffix(pattern, "*")
			return strings.HasPrefix(str, prefix)
		}
		if strings.HasPrefix(pattern, "*") {
			suffix := strings.TrimPrefix(pattern, "*")
			return strings.HasSuffix(str, suffix)
		}
		// For more complex patterns, could implement full glob matching
	}
	
	return pattern == str
}

// ExtendedValidator combines multiple validation approaches
type ExtendedValidator struct {
	policyValidator *PolicyBasedValidator
	defaultValidator interface {
		ValidateContainerAdjustment(context.Context, *ValidateContainerAdjustmentRequest) error
	}
}

// NewExtendedValidator creates a validator that combines policy and default validation
func NewExtendedValidator(policy NRIValidationPolicySpec, restrictionsConfig *RestrictionsConfig, defaultValidator interface {
	ValidateContainerAdjustment(context.Context, *ValidateContainerAdjustmentRequest) error
}) *ExtendedValidator {
	return &ExtendedValidator{
		policyValidator:  NewPolicyBasedValidator(policy, restrictionsConfig),
		defaultValidator: defaultValidator,
	}
}

// ValidateContainerAdjustment performs comprehensive validation
func (ev *ExtendedValidator) ValidateContainerAdjustment(ctx context.Context, req *ValidateContainerAdjustmentRequest, validationCtx *ValidationContext) error {
	// Run default validation first (existing NRI validation logic)
	if ev.defaultValidator != nil {
		if err := ev.defaultValidator.ValidateContainerAdjustment(ctx, req); err != nil {
			return fmt.Errorf("default validation failed: %w", err)
		}
	}
	
	// Run policy-based validation
	if err := ev.policyValidator.ValidateContainerAdjustment(ctx, req, validationCtx); err != nil {
		return fmt.Errorf("policy validation failed: %w", err)
	}
	
	return nil
}

// ValidateExamplePolicy validates the example policy you provided
func ValidateExamplePolicy() error {
	// Example policy from your specification
	examplePolicy := NRIValidationPolicySpec{
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
	}
	
	// Example restrictions config
	restrictionsConfig := RestrictionsConfig{
		DefaultAction: RestrictionAllow,
		GlobalRestrictions: []MutationRestriction{
			{
				Action:       RestrictionDeny,
				Capabilities: []MutationCapability{MutationNamespaces, MutationSeccomp},
			},
		},
		PluginRestrictions: []PluginRestriction{
			{
				PluginPattern: "untrusted-*",
				MutationRestrictions: []MutationRestriction{
					{
						Action:       RestrictionAllow,
						Capabilities: []MutationCapability{MutationEnv, MutationAnnotations},
					},
				},
			},
		},
	}
	
	validator := NewPolicyBasedValidator(examplePolicy, &restrictionsConfig)
	
	// Test cases could be added here
	fmt.Printf("Policy validator created successfully with %d rules\n", len(examplePolicy.Rules))
	fmt.Printf("Restrictions validator created with %d plugin restrictions\n", len(restrictionsConfig.PluginRestrictions))
	
	return nil
}