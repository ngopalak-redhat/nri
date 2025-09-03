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

package main

import (
	"context"
	"testing"

	"github.com/containerd/nri/pkg/api"
)

func TestPolicyValidation(t *testing.T) {
	// Test policy with defaultDeny: true
	policy := NRIValidationPolicySpec{
		DefaultDeny: true,
		Rules: []PolicyRule{
			{
				Namespaces: []string{"dev-*"},
				Plugins:    []string{"*"},
				Subjects: []PolicySubject{
					{Kind: "User", Name: "developer"},
				},
			},
		},
	}

	validator := NewPolicyBasedValidator(policy, nil)

	// Test case 1: Allowed user in allowed namespace
	ctx := context.Background()
	req := &api.ValidateContainerAdjustmentRequest{
		Pod: &api.PodSandbox{
			Namespace: "dev-test",
			Name:      "test-pod",
		},
		Plugins: []*api.PluginInstance{
			{Name: "test-plugin"},
		},
	}

	validationCtx := &ValidationContext{
		Subject: &PolicySubject{
			Kind: "User",
			Name: "developer",
		},
		PodNamespace: "dev-test",
		PluginName:   "test-plugin",
	}

	err := validator.ValidateContainerAdjustment(ctx, req, validationCtx)
	if err != nil {
		t.Errorf("Expected validation to pass for allowed user, got: %v", err)
	}

	// Test case 2: Denied user (not in subjects list)
	validationCtx.Subject.Name = "unauthorized-user"
	err = validator.ValidateContainerAdjustment(ctx, req, validationCtx)
	if err == nil {
		t.Error("Expected validation to fail for unauthorized user")
	}

	// Test case 3: Wrong namespace
	validationCtx.Subject.Name = "developer"
	req.Pod.Namespace = "production"
	validationCtx.PodNamespace = "production"
	err = validator.ValidateContainerAdjustment(ctx, req, validationCtx)
	if err == nil {
		t.Error("Expected validation to fail for wrong namespace")
	}
}

func TestRestrictionsValidation(t *testing.T) {
	// Test restrictions with global deny for namespaces
	config := RestrictionsConfig{
		DefaultAction: RestrictionAllow,
		GlobalRestrictions: []MutationRestriction{
			{
				Action:       RestrictionDeny,
				Capabilities: []MutationCapability{MutationNamespaces},
			},
		},
	}

	validator := NewRestrictionsValidator(config)

	// Create a request with namespace mutation
	req := &api.ValidateContainerAdjustmentRequest{
		Pod: &api.PodSandbox{
			Namespace: "test",
			Name:      "test-pod",
		},
		Adjust: &api.ContainerAdjustment{
			Linux: &api.LinuxContainerAdjustment{
				Namespaces: []*api.LinuxNamespace{
					{Type: "pid", Path: "/proc/1/ns/pid"},
				},
			},
		},
		Plugins: []*api.PluginInstance{
			{Name: "test-plugin"},
		},
	}

	err := validator.ValidateContainerAdjustment(req)
	if err == nil {
		t.Error("Expected validation to fail for namespace mutation")
	}

	// Test without namespace mutation should pass
	req.Adjust.Linux.Namespaces = nil
	err = validator.ValidateContainerAdjustment(req)
	if err != nil {
		t.Errorf("Expected validation to pass without namespace mutation, got: %v", err)
	}
}

func TestConfigValidation(t *testing.T) {
	// Test valid configuration
	config := ValidationConfig{
		EnableDefaultValidator: true,
		Policy: &NRIValidationPolicySpec{
			DefaultDeny: false,
			Rules: []PolicyRule{
				{
					Namespaces: []string{"test"},
					Plugins:    []string{"test-plugin"},
					Subjects: []PolicySubject{
						{Kind: "User", Name: "test-user"},
					},
				},
			},
		},
		Restrictions: &RestrictionsConfig{
			DefaultAction: RestrictionAllow,
		},
	}

	err := ValidateConfig(&config)
	if err != nil {
		t.Errorf("Expected valid config to pass validation, got: %v", err)
	}

	// Test invalid configuration - empty namespaces
	config.Policy.Rules[0].Namespaces = []string{}
	err = ValidateConfig(&config)
	if err == nil {
		t.Error("Expected invalid config to fail validation")
	}
}

func TestGlobMatching(t *testing.T) {
	validator := &PolicyBasedValidator{}

	tests := []struct {
		pattern   string
		str       string
		shouldMatch bool
	}{
		{"*", "anything", true},
		{"dev-*", "dev-test", true},
		{"dev-*", "prod-test", false},
		{"*-test", "dev-test", true},
		{"*-test", "dev-prod", false},
		{"exact", "exact", true},
		{"exact", "different", false},
	}

	for _, test := range tests {
		result := validator.globMatch(test.pattern, test.str)
		if result != test.shouldMatch {
			t.Errorf("Pattern %q vs %q: expected %v, got %v", 
				test.pattern, test.str, test.shouldMatch, result)
		}
	}
}