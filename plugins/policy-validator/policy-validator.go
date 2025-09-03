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
	"flag"
	"fmt"
	"log"

	"github.com/containerd/nri/pkg/api"
	"github.com/containerd/nri/pkg/stub"
)

type pluginPolicyValidator struct {
	stub              stub.Stub
	mask              api.EventMask
	validationManager *ValidationManager
}

var (
	pluginName = "policy-validator"
	pluginIdx  = "99" // Run late in the chain to validate other plugins' changes
	configPath = flag.String("config", "/etc/nri/validation.yaml", "Path to validation configuration file")
	verbose    = flag.Bool("verbose", false, "Enable verbose logging")
)

func main() {
	flag.Parse()

	p := &pluginPolicyValidator{}

	// Load validation configuration
	config, err := LoadConfigFromFile(*configPath)
	if err != nil {
		log.Fatalf("Failed to load validation config: %v", err)
	}

	// Validate configuration
	if err := ValidateConfig(config); err != nil {
		log.Fatalf("Invalid validation config: %v", err)
	}

	// Create validation manager
	p.validationManager, err = NewValidationManager(*config)
	if err != nil {
		log.Fatalf("Failed to create validation manager: %v", err)
	}

	// We only need to handle validation events
	p.mask = api.EventMask(1 << (api.Event_VALIDATE_CONTAINER_ADJUSTMENT - 1))

	if p.stub, err = stub.New(p, stub.WithPluginName(pluginName), stub.WithPluginIdx(pluginIdx)); err != nil {
		log.Fatalf("failed to create plugin stub: %v", err)
	}

	log.Printf("Starting NRI policy validator plugin...")
	err = p.stub.Run(context.Background())
	if err != nil {
		log.Fatalf("plugin exited with error %v", err)
	}
}

func (p *pluginPolicyValidator) Configure(_ context.Context, config, runtime, version string) (api.EventMask, error) {
	if *verbose {
		log.Printf("Got configuration data: %q from runtime %s %s", config, runtime, version)
	}
	log.Printf("Policy validator configured for runtime %s %s", runtime, version)
	return p.mask, nil
}

func (p *pluginPolicyValidator) Synchronize(_ context.Context, pods []*api.PodSandbox, containers []*api.Container) ([]*api.ContainerUpdate, error) {
	log.Printf("Synchronized with %d pods and %d containers", len(pods), len(containers))
	return nil, nil
}

func (p *pluginPolicyValidator) Shutdown(_ context.Context) error {
	log.Printf("Policy validator shutting down")
	return nil
}

func (p *pluginPolicyValidator) ValidateContainerAdjustment(ctx context.Context, req *api.ValidateContainerAdjustmentRequest) error {
	pod := req.GetPod()
	container := req.GetContainer()

	if *verbose {
		log.Printf("Validating adjustment for container %s in pod %s/%s",
			container.GetName(), pod.GetNamespace(), pod.GetName())
	}

	// Extract subject information from pod annotations or other sources
	// In a real implementation, this might come from:
	// - Pod annotations set by admission controllers
	// - Service account tokens
	// - User identity from authentication systems
	subject := extractSubjectFromPod(pod)

	// Perform validation using the validation manager
	err := p.validationManager.ValidateContainerAdjustment(ctx, req, subject)
	if err != nil {
		log.Printf("Validation DENIED for container %s/%s/%s: %v",
			pod.GetNamespace(), pod.GetName(), container.GetName(), err)
		return fmt.Errorf("policy validation failed: %w", err)
	}

	if *verbose {
		log.Printf("Validation ALLOWED for container %s/%s/%s",
			pod.GetNamespace(), pod.GetName(), container.GetName())
	}
	return nil
}

// extractSubjectFromPod extracts subject information from pod metadata
func extractSubjectFromPod(pod *api.PodSandbox) *PolicySubject {
	annotations := pod.GetAnnotations()

	// Check for user annotation
	if user, exists := annotations["nri.io/user"]; exists {
		return &PolicySubject{
			Kind: "User",
			Name: user,
		}
	}

	// Check for group annotation
	if group, exists := annotations["nri.io/group"]; exists {
		return &PolicySubject{
			Kind: "Group",
			Name: group,
		}
	}

	// Use service account as default
	// In Kubernetes, this would be pod.Spec.ServiceAccountName
	serviceAccount := "default"
	if sa, exists := annotations["nri.io/service-account"]; exists {
		serviceAccount = sa
	}

	return &PolicySubject{
		Kind: "ServiceAccount",
		Name: serviceAccount,
	}
}

// Stubs for required interfaces - these are no-ops since we only do validation
func (p *pluginPolicyValidator) CreateContainer(_ context.Context, pod *api.PodSandbox, container *api.Container) (*api.ContainerAdjustment, []*api.ContainerUpdate, error) {
	return nil, nil, nil
}

func (p *pluginPolicyValidator) UpdateContainer(_ context.Context, pod *api.PodSandbox, container *api.Container, r *api.LinuxResources) ([]*api.ContainerUpdate, error) {
	return nil, nil
}

func (p *pluginPolicyValidator) StopContainer(_ context.Context, pod *api.PodSandbox, container *api.Container) ([]*api.ContainerUpdate, error) {
	return nil, nil
}