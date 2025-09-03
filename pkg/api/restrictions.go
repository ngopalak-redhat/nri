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
	"fmt"
	"slices"
	"strings"
)

// RestrictionAction defines whether a list is an allowlist or denylist
type RestrictionAction string

const (
	RestrictionAllow RestrictionAction = "allow"
	RestrictionDeny  RestrictionAction = "deny"
)

// MutationCapability represents different types of mutations plugins can make
type MutationCapability string

const (
	// Container adjustment capabilities
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
	
	// Resource-specific capabilities
	MutationMemory        MutationCapability = "memory"
	MutationCPU           MutationCapability = "cpu"
	MutationBlockIO       MutationCapability = "blockio"
	MutationRDT           MutationCapability = "rdt"
	MutationUnified       MutationCapability = "unified"
)

// PodSelector defines criteria for selecting pods
type PodSelector struct {
	// Namespaces specifies namespace patterns (supports glob like "dev-*")
	Namespaces []string `json:"namespaces,omitempty"`
	
	// Labels specifies label selectors
	Labels map[string]string `json:"labels,omitempty"`
	
	// Names specifies pod name patterns
	Names []string `json:"names,omitempty"`
}

// PluginRestriction defines restrictions for a specific plugin or plugin pattern
type PluginRestriction struct {
	// PluginPattern specifies which plugins this restriction applies to
	// Supports glob patterns like "cpu-*" or exact names
	PluginPattern string `json:"pluginPattern"`
	
	// MutationRestrictions defines what mutations are allowed/denied
	MutationRestrictions []MutationRestriction `json:"mutationRestrictions,omitempty"`
	
	// PodRestrictions defines which pods can be modified
	PodRestrictions []PodRestriction `json:"podRestrictions,omitempty"`
}

// MutationRestriction defines allowed/denied mutation capabilities
type MutationRestriction struct {
	// Action specifies whether this is an allowlist or denylist
	Action RestrictionAction `json:"action"`
	
	// Capabilities lists the mutation capabilities
	Capabilities []MutationCapability `json:"capabilities"`
}

// PodRestriction defines allowed/denied pod selectors
type PodRestriction struct {
	// Action specifies whether this is an allowlist or denylist
	Action RestrictionAction `json:"action"`
	
	// Selector defines the pod selection criteria
	Selector PodSelector `json:"selector"`
}

// RestrictionsConfig holds the complete restrictions configuration
type RestrictionsConfig struct {
	// DefaultAction specifies the default behavior when no restrictions match
	// If "deny", plugins are denied unless explicitly allowed
	// If "allow", plugins are allowed unless explicitly denied
	DefaultAction RestrictionAction `json:"defaultAction,omitempty"`
	
	// GlobalRestrictions apply to all plugins
	GlobalRestrictions []MutationRestriction `json:"globalRestrictions,omitempty"`
	
	// PluginRestrictions define per-plugin restrictions
	PluginRestrictions []PluginRestriction `json:"pluginRestrictions,omitempty"`
	
	// GlobalPodRestrictions apply to all plugins for pod selection
	GlobalPodRestrictions []PodRestriction `json:"globalPodRestrictions,omitempty"`
}

// RestrictionsValidator validates container adjustments against restrictions
type RestrictionsValidator struct {
	config RestrictionsConfig
}

// NewRestrictionsValidator creates a new restrictions validator
func NewRestrictionsValidator(config RestrictionsConfig) *RestrictionsValidator {
	return &RestrictionsValidator{
		config: config,
	}
}

// ValidateContainerAdjustment validates a container adjustment against restrictions
func (rv *RestrictionsValidator) ValidateContainerAdjustment(req *ValidateContainerAdjustmentRequest) error {
	pod := req.GetPod()
	if pod == nil {
		return fmt.Errorf("pod information is required for restrictions validation")
	}

	plugins := req.GetPluginMap()
	
	// Validate each plugin's mutations
	for pluginName := range plugins {
		if err := rv.validatePluginMutations(pluginName, req); err != nil {
			return fmt.Errorf("plugin %s restricted: %w", pluginName, err)
		}
		
		if err := rv.validatePodAccess(pluginName, pod); err != nil {
			return fmt.Errorf("plugin %s denied pod access: %w", pluginName, err)
		}
	}
	
	return nil
}

// validatePluginMutations validates that a plugin's mutations are allowed
func (rv *RestrictionsValidator) validatePluginMutations(pluginName string, req *ValidateContainerAdjustmentRequest) error {
	// Get mutation capabilities from the adjustment
	capabilities := rv.extractMutationCapabilities(req.Adjust)
	
	// Check global restrictions first
	for _, restriction := range rv.config.GlobalRestrictions {
		if err := rv.checkMutationRestriction(restriction, capabilities); err != nil {
			return err
		}
	}
	
	// Check plugin-specific restrictions
	pluginRestrictions := rv.findPluginRestrictions(pluginName)
	for _, pluginRestriction := range pluginRestrictions {
		for _, mutationRestriction := range pluginRestriction.MutationRestrictions {
			if err := rv.checkMutationRestriction(mutationRestriction, capabilities); err != nil {
				return err
			}
		}
	}
	
	return nil
}

// validatePodAccess validates that a plugin can access the specified pod
func (rv *RestrictionsValidator) validatePodAccess(pluginName string, pod *PodSandbox) error {
	// Check global pod restrictions
	for _, restriction := range rv.config.GlobalPodRestrictions {
		if err := rv.checkPodRestriction(restriction, pod); err != nil {
			return err
		}
	}
	
	// Check plugin-specific pod restrictions
	pluginRestrictions := rv.findPluginRestrictions(pluginName)
	for _, pluginRestriction := range pluginRestrictions {
		for _, podRestriction := range pluginRestriction.PodRestrictions {
			if err := rv.checkPodRestriction(podRestriction, pod); err != nil {
				return err
			}
		}
	}
	
	return nil
}

// extractMutationCapabilities determines what capabilities are being used in an adjustment
func (rv *RestrictionsValidator) extractMutationCapabilities(adjust *ContainerAdjustment) []MutationCapability {
	if adjust == nil {
		return nil
	}
	
	var capabilities []MutationCapability
	
	if adjust.Annotations != nil && len(adjust.Annotations) > 0 {
		capabilities = append(capabilities, MutationAnnotations)
	}
	
	if adjust.Mounts != nil && len(adjust.Mounts) > 0 {
		capabilities = append(capabilities, MutationMounts)
	}
	
	if adjust.Args != nil && len(adjust.Args) > 0 {
		capabilities = append(capabilities, MutationArgs)
	}
	
	if adjust.Env != nil && len(adjust.Env) > 0 {
		capabilities = append(capabilities, MutationEnv)
	}
	
	if adjust.Hooks != nil {
		capabilities = append(capabilities, MutationHooks)
	}
	
	if adjust.Rlimits != nil && len(adjust.Rlimits) > 0 {
		capabilities = append(capabilities, MutationRlimits)
	}
	
	if adjust.Linux != nil {
		linux := adjust.Linux
		
		if linux.Devices != nil && len(linux.Devices) > 0 {
			capabilities = append(capabilities, MutationDevices)
		}
		
		if linux.Resources != nil {
			capabilities = append(capabilities, MutationResources)
			
			// More specific resource capabilities
			if linux.Resources.Memory != nil {
				capabilities = append(capabilities, MutationMemory)
			}
			if linux.Resources.Cpu != nil {
				capabilities = append(capabilities, MutationCPU)
			}
			if linux.Resources.BlockioClass != nil && linux.Resources.BlockioClass.GetValue() != "" {
				capabilities = append(capabilities, MutationBlockIO)
			}
			if linux.Resources.RdtClass != nil && linux.Resources.RdtClass.GetValue() != "" {
				capabilities = append(capabilities, MutationRDT)
			}
			if linux.Resources.Unified != nil && len(linux.Resources.Unified) > 0 {
				capabilities = append(capabilities, MutationUnified)
			}
		}
		
		// SeccompProfile is only in LinuxContainer, not LinuxContainerAdjustment
		// We'll check for seccomp via other means if needed
		
		if linux.Namespaces != nil && len(linux.Namespaces) > 0 {
			capabilities = append(capabilities, MutationNamespaces)
		}
	}
	
	return capabilities
}

// checkMutationRestriction checks if mutations are allowed by a restriction
func (rv *RestrictionsValidator) checkMutationRestriction(restriction MutationRestriction, capabilities []MutationCapability) error {
	switch restriction.Action {
	case RestrictionAllow:
		// Allowlist: all capabilities must be in the allowed list
		for _, cap := range capabilities {
			if !slices.Contains(restriction.Capabilities, cap) {
				return fmt.Errorf("mutation capability %s not in allowlist", cap)
			}
		}
	case RestrictionDeny:
		// Denylist: no capabilities should be in the denied list
		for _, cap := range capabilities {
			if slices.Contains(restriction.Capabilities, cap) {
				return fmt.Errorf("mutation capability %s is denied", cap)
			}
		}
	}
	
	return nil
}

// checkPodRestriction checks if pod access is allowed by a restriction
func (rv *RestrictionsValidator) checkPodRestriction(restriction PodRestriction, pod *PodSandbox) error {
	matches := rv.podMatches(restriction.Selector, pod)
	
	switch restriction.Action {
	case RestrictionAllow:
		// Allowlist: pod must match to be allowed
		if !matches {
			return fmt.Errorf("pod not in allowlist")
		}
	case RestrictionDeny:
		// Denylist: pod must not match to be allowed
		if matches {
			return fmt.Errorf("pod is in denylist")
		}
	}
	
	return nil
}

// findPluginRestrictions finds all restrictions that apply to a plugin
func (rv *RestrictionsValidator) findPluginRestrictions(pluginName string) []PluginRestriction {
	var matching []PluginRestriction
	
	for _, restriction := range rv.config.PluginRestrictions {
		if rv.globMatch(restriction.PluginPattern, pluginName) {
			matching = append(matching, restriction)
		}
	}
	
	return matching
}

// podMatches checks if a pod matches a selector
func (rv *RestrictionsValidator) podMatches(selector PodSelector, pod *PodSandbox) bool {
	// Check namespace
	if len(selector.Namespaces) > 0 {
		namespaceMatches := false
		for _, nsPattern := range selector.Namespaces {
			if rv.globMatch(nsPattern, pod.GetNamespace()) {
				namespaceMatches = true
				break
			}
		}
		if !namespaceMatches {
			return false
		}
	}
	
	// Check labels
	if len(selector.Labels) > 0 {
		podLabels := pod.GetLabels()
		for key, value := range selector.Labels {
			if podValue, exists := podLabels[key]; !exists || podValue != value {
				return false
			}
		}
	}
	
	// Check names
	if len(selector.Names) > 0 {
		nameMatches := false
		for _, namePattern := range selector.Names {
			if rv.globMatch(namePattern, pod.GetName()) {
				nameMatches = true
				break
			}
		}
		if !nameMatches {
			return false
		}
	}
	
	return true
}

// globMatch performs simple glob pattern matching
func (rv *RestrictionsValidator) globMatch(pattern, str string) bool {
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
	}
	
	return pattern == str
}