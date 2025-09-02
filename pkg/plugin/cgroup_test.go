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

package plugin

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/containerd/nri/pkg/api"
)

func TestGetCgroupsV2AbsPath(t *testing.T) {
	tests := []struct {
		name        string
		container   *api.Container
		expected    string
		description string
	}{
		{
			name:        "nil container",
			container:   nil,
			expected:    "",
			description: "should return empty string for nil container",
		},
		{
			name: "container without linux config",
			container: &api.Container{
				Id: "test-container",
			},
			expected:    "",
			description: "should return empty string for container without Linux config",
		},
		{
			name: "container without cgroups path",
			container: &api.Container{
				Id: "test-container",
				Linux: &api.LinuxContainer{
					CgroupsPath: "",
				},
			},
			expected:    "",
			description: "should return empty string for container without cgroups path",
		},
		{
			name: "container with absolute cgroups path",
			container: &api.Container{
				Id: "test-container",
				Linux: &api.LinuxContainer{
					CgroupsPath: "/sys/fs/cgroup/kubepods/pod123/container456",
				},
			},
			expected:    "/sys/fs/cgroup/kubepods/pod123/container456",
			description: "should return absolute path as-is",
		},
		{
			name: "container with relative cgroups path",
			container: &api.Container{
				Id: "test-container",
				Linux: &api.LinuxContainer{
					CgroupsPath: "kubepods/pod123/container456",
				},
			},
			expected:    "/sys/fs/cgroup/kubepods/pod123/container456",
			description: "should join relative path with cgroup v2 root",
		},
		{
			name: "container with systemd-style cgroups path",
			container: &api.Container{
				Id: "test-container",
				Linux: &api.LinuxContainer{
					CgroupsPath: "system.slice/containerd.service/kubepods-burstable-pod123.slice:cri-containerd:container456",
				},
			},
			expected:    "/sys/fs/cgroup/system.slice/containerd.service/kubepods-burstable-pod123.slice/cri-containerd:container456",
			description: "should handle systemd-style paths with proper colon conversion",
		},
		{
			name: "container with cgroupfs driver path",
			container: &api.Container{
				Id: "test-container",
				Linux: &api.LinuxContainer{
					CgroupsPath: "kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod123.slice/cri-containerd-container456.scope",
				},
			},
			expected:    "/sys/fs/cgroup/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod123.slice/cri-containerd-container456.scope",
			description: "should handle cgroupfs driver paths",
		},
		{
			name: "container with complex systemd path",
			container: &api.Container{
				Id: "test-container",
				Linux: &api.LinuxContainer{
					CgroupsPath: "machine.slice/libpod-container123.scope:container:runtime",
				},
			},
			expected:    "/sys/fs/cgroup/machine.slice/libpod-container123.scope/container:runtime",
			description: "should handle complex systemd paths with multiple colons",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetContainerCgroupsV2AbsPath(tt.container)
			if result != tt.expected {
				t.Errorf("GetContainerCgroupsV2AbsPath() = %v, expected %v\nDescription: %s", result, tt.expected, tt.description)
			}
		})
	}
}

func TestGetPodCgroupsV2AbsPath(t *testing.T) {
	tests := []struct {
		name        string
		pod         *api.PodSandbox
		expected    string
		description string
	}{
		{
			name:        "nil pod",
			pod:         nil,
			expected:    "",
			description: "should return empty string for nil pod",
		},
		{
			name: "pod without linux config",
			pod: &api.PodSandbox{
				Id: "test-pod",
			},
			expected:    "",
			description: "should return empty string for pod without Linux config",
		},
		{
			name: "pod without cgroups path",
			pod: &api.PodSandbox{
				Id: "test-pod",
				Linux: &api.LinuxPodSandbox{
					CgroupsPath: "",
				},
			},
			expected:    "",
			description: "should return empty string for pod without cgroups path",
		},
		{
			name: "pod with absolute cgroups path",
			pod: &api.PodSandbox{
				Id: "test-pod",
				Linux: &api.LinuxPodSandbox{
					CgroupsPath: "/sys/fs/cgroup/kubepods/pod123",
				},
			},
			expected:    "/sys/fs/cgroup/kubepods/pod123",
			description: "should return absolute path as-is",
		},
		{
			name: "pod with relative cgroups path",
			pod: &api.PodSandbox{
				Id: "test-pod",
				Linux: &api.LinuxPodSandbox{
					CgroupsPath: "kubepods/pod123",
				},
			},
			expected:    "/sys/fs/cgroup/kubepods/pod123",
			description: "should join relative path with cgroup v2 root",
		},
		{
			name: "pod with QoS burstable path",
			pod: &api.PodSandbox{
				Id: "test-pod",
				Linux: &api.LinuxPodSandbox{
					CgroupsPath: "kubepods/burstable/pod123",
				},
			},
			expected:    "/sys/fs/cgroup/kubepods/burstable/pod123",
			description: "should handle QoS class paths",
		},
		{
			name: "pod with QoS besteffort path",
			pod: &api.PodSandbox{
				Id: "test-pod",
				Linux: &api.LinuxPodSandbox{
					CgroupsPath: "kubepods/besteffort/pod123",
				},
			},
			expected:    "/sys/fs/cgroup/kubepods/besteffort/pod123",
			description: "should handle besteffort QoS class",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetPodCgroupsV2AbsPath(tt.pod)
			if result != tt.expected {
				t.Errorf("GetPodCgroupsV2AbsPath() = %v, expected %v\nDescription: %s", result, tt.expected, tt.description)
			}
		})
	}
}

func TestIsSystemdPath(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected bool
	}{
		{
			name:     "systemd slice path",
			path:     "system.slice/containerd.service",
			expected: true,
		},
		{
			name:     "systemd path with colons",
			path:     "kubepods-burstable-pod123.slice:cri-containerd:container456",
			expected: true,
		},
		{
			name:     "cgroupfs path",
			path:     "kubepods/burstable/pod123/container456",
			expected: false,
		},
		{
			name:     "simple path",
			path:     "kubepods/pod123",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isSystemdPath(tt.path)
			if result != tt.expected {
				t.Errorf("isSystemdPath(%s) = %v, expected %v", tt.path, result, tt.expected)
			}
		})
	}
}

func TestConvertSystemdPath(t *testing.T) {
	tests := []struct {
		name        string
		cgroupRoot  string
		systemdPath string
		expected    string
	}{
		{
			name:        "systemd path with colons",
			cgroupRoot:  "/sys/fs/cgroup",
			systemdPath: "system.slice/containerd.service/kubepods-burstable-pod123.slice:cri-containerd:container456",
			expected:    "/sys/fs/cgroup/system.slice/containerd.service/kubepods-burstable-pod123.slice/cri-containerd:container456",
		},
		{
			name:        "systemd path without colons",
			cgroupRoot:  "/sys/fs/cgroup",
			systemdPath: "system.slice/containerd.service",
			expected:    "/sys/fs/cgroup/system.slice/containerd.service",
		},
		{
			name:        "complex systemd path",
			cgroupRoot:  "/sys/fs/cgroup",
			systemdPath: "machine.slice/libpod-container123.scope:container:runtime",
			expected:    "/sys/fs/cgroup/machine.slice/libpod-container123.scope/container:runtime",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := convertSystemdPath(tt.cgroupRoot, tt.systemdPath)
			if result != tt.expected {
				t.Errorf("convertSystemdPath(%s, %s) = %s, expected %s", tt.cgroupRoot, tt.systemdPath, result, tt.expected)
			}
		})
	}
}

func TestResolveCgroupPath(t *testing.T) {
	tmpDir := t.TempDir()

	cgroupfsPath := filepath.Join(tmpDir, "kubepods", "burstable", "pod123")
	systemdPath := filepath.Join(tmpDir, "system.slice", "containerd.service", "kubepods-burstable-pod123.slice")

	err := os.MkdirAll(cgroupfsPath, 0755)
	if err != nil {
		t.Fatalf("Failed to create test directory: %v", err)
	}

	err = os.MkdirAll(systemdPath, 0755)
	if err != nil {
		t.Fatalf("Failed to create test directory: %v", err)
	}

	tests := []struct {
		name       string
		cgroupRoot string
		cgroupPath string
		expected   string
	}{
		{
			name:       "existing cgroupfs path",
			cgroupRoot: tmpDir,
			cgroupPath: "kubepods/burstable/pod123",
			expected:   filepath.Join(tmpDir, "kubepods/burstable/pod123"),
		},
		{
			name:       "systemd path conversion",
			cgroupRoot: tmpDir,
			cgroupPath: "system.slice/containerd.service/kubepods-burstable-pod123.slice:cri-containerd:container456",
			expected:   filepath.Join(tmpDir, "system.slice/containerd.service/kubepods-burstable-pod123.slice/cri-containerd:container456"),
		},
		{
			name:       "non-existing path falls back to cgroupfs",
			cgroupRoot: tmpDir,
			cgroupPath: "nonexistent/path",
			expected:   filepath.Join(tmpDir, "nonexistent/path"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := resolveCgroupPath(tt.cgroupRoot, tt.cgroupPath)
			if result != tt.expected {
				t.Errorf("resolveCgroupPath(%s, %s) = %s, expected %s", tt.cgroupRoot, tt.cgroupPath, result, tt.expected)
			}
		})
	}
}
