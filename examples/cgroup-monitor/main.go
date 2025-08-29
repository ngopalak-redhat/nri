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
	"os"
	"path/filepath"

	"github.com/containerd/nri/pkg/api"
	"github.com/containerd/nri/pkg/stub"
	"github.com/sirupsen/logrus"
)

type plugin struct {
	stub stub.Stub
}

var (
	log *logrus.Logger
)

func main() {
	var (
		pluginName = "cgroup-monitor"
		pluginIdx  = "01"
	)

	log = logrus.StandardLogger()
	log.SetFormatter(&logrus.TextFormatter{
		PadLevelText: true,
	})

	p := &plugin{}
	if stub, err := stub.New(p, append([]stub.Option{
		stub.WithPluginName(pluginName),
		stub.WithPluginIdx(pluginIdx),
	})...); err != nil {
		log.Errorf("failed to create plugin stub: %v", err)
		os.Exit(1)
	} else {
		p.stub = stub
	}

	err := p.stub.Run(context.Background())
	if err != nil {
		log.Errorf("plugin exited with error %v", err)
		os.Exit(1)
	}
}

func (p *plugin) Configure(ctx context.Context, config, runtime, version string) (api.EventMask, error) {
	log.Infof("cgroup-monitor plugin starting...")
	log.Infof("runtime: %s, version: %s", runtime, version)
	
	// Subscribe to container lifecycle events
	return api.MustParseEventMask("RunPodSandbox", "CreateContainer", "StartContainer"), nil
}

func (p *plugin) Synchronize(ctx context.Context, pods []*api.PodSandbox, containers []*api.Container) ([]*api.ContainerUpdate, error) {
	log.Infof("synchronizing with %d pods and %d containers", len(pods), len(containers))
	
	// Monitor existing pods and containers
	for _, pod := range pods {
		p.monitorPodCgroups(pod)
	}
	
	for _, container := range containers {
		p.monitorContainerCgroups(container)
	}
	
	return nil, nil
}

func (p *plugin) RunPodSandbox(ctx context.Context, pod *api.PodSandbox) error {
	log.Infof("pod %s started", pod.Name)
	p.monitorPodCgroups(pod)
	return nil
}

func (p *plugin) CreateContainer(ctx context.Context, pod *api.PodSandbox, container *api.Container) (*api.ContainerAdjustment, []*api.ContainerUpdate, error) {
	log.Infof("container %s created in pod %s", container.Name, pod.Name)
	p.monitorContainerCgroups(container)
	return nil, nil, nil
}

func (p *plugin) StartContainer(ctx context.Context, pod *api.PodSandbox, container *api.Container) error {
	log.Infof("container %s started in pod %s", container.Name, pod.Name)
	p.monitorContainerCgroups(container)
	return nil
}

// monitorPodCgroups demonstrates how to access pod cgroup information
func (p *plugin) monitorPodCgroups(pod *api.PodSandbox) {
	// Get the relative cgroups path (old way)
	relativePath := pod.GetLinux().GetCgroupsPath()
	
	// Get the absolute cgroups path (new way)
	absolutePath := pod.GetCgroup2AbsPath()
	
	log.Infof("Pod %s cgroup paths:", pod.Name)
	log.Infof("  Relative: %s", relativePath)
	log.Infof("  Absolute: %s", absolutePath)
	
	// Check if the cgroup directory exists and read controllers
	if absolutePath != "" {
		p.readCgroupControllers(absolutePath, "pod", pod.Name)
		p.checkCgroupMemoryUsage(absolutePath, "pod", pod.Name)
	}
}

// monitorContainerCgroups demonstrates how to access container cgroup information
func (p *plugin) monitorContainerCgroups(container *api.Container) {
	// Get the relative cgroups path (old way)
	relativePath := container.GetLinux().GetCgroupsPath()
	
	// Get the absolute cgroups path (new way)
	absolutePath := container.GetCgroup2AbsPath()
	
	log.Infof("Container %s cgroup paths:", container.Name)
	log.Infof("  Relative: %s", relativePath)
	log.Infof("  Absolute: %s", absolutePath)
	
	// Check if the cgroup directory exists and read controllers
	if absolutePath != "" {
		p.readCgroupControllers(absolutePath, "container", container.Name)
		p.checkCgroupMemoryUsage(absolutePath, "container", container.Name)
	}
}

// readCgroupControllers reads the available cgroup controllers
func (p *plugin) readCgroupControllers(cgroupPath, resourceType, name string) {
	controllersFile := filepath.Join(cgroupPath, "cgroup.controllers")
	if data, err := os.ReadFile(controllersFile); err == nil {
		log.Infof("%s %s controllers: %s", resourceType, name, string(data))
	} else {
		log.Debugf("Could not read controllers for %s %s: %v", resourceType, name, err)
	}
}

// checkCgroupMemoryUsage reads current memory usage from cgroup v2
func (p *plugin) checkCgroupMemoryUsage(cgroupPath, resourceType, name string) {
	memoryCurrentFile := filepath.Join(cgroupPath, "memory.current")
	if data, err := os.ReadFile(memoryCurrentFile); err == nil {
		log.Infof("%s %s memory usage: %s bytes", resourceType, name, string(data))
	} else {
		log.Debugf("Could not read memory usage for %s %s: %v", resourceType, name, err)
	}
	
	memoryMaxFile := filepath.Join(cgroupPath, "memory.max")
	if data, err := os.ReadFile(memoryMaxFile); err == nil {
		log.Infof("%s %s memory limit: %s", resourceType, name, string(data))
	} else {
		log.Debugf("Could not read memory limit for %s %s: %v", resourceType, name, err)
	}
}