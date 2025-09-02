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
	"strings"

	"github.com/containerd/nri/pkg/api"
)

// GetContainerCgroupsV2AbsPath returns the absolute path to the cgroup v2 directory for a container.
// This method converts relative cgroup paths to absolute paths, for different cgroup managers,
// QoS classes, and custom cgroup hierarchies.
// It returns an empty string if the container has no Linux configuration or cgroups path.
func GetContainerCgroupsV2AbsPath(container *api.Container) string {
	if container == nil || container.Linux == nil || container.Linux.CgroupsPath == "" {
		return ""
	}

	cgroupPath := container.Linux.CgroupsPath
	return getCGroupsV2Path(cgroupPath)
}

// GetPodCgroupsV2AbsPath returns the absolute path to the cgroup v2 directory for a pod sandbox.
// This method converts relative cgroup paths to absolute paths, for different cgroup managers,
// QoS classes, and custom cgroup hierarchies.
// It returns an empty string if the pod has no Linux configuration or cgroups path.
func GetPodCgroupsV2AbsPath(pod *api.PodSandbox) string {
	if pod == nil || pod.Linux == nil || pod.Linux.CgroupsPath == "" {
		return ""
	}

	cgroupPath := pod.Linux.CgroupsPath
	return getCGroupsV2Path(cgroupPath)
}

// Helper functions

// getCGroupsV2Path helper
// Same implementation for both sandbox and container
func getCGroupsV2Path(cgroupPath string) string {
	if filepath.IsAbs(cgroupPath) {
		return cgroupPath
	}

	cgroupV2Root := getCgroupV2Root()
	if cgroupV2Root == "" {
		// Fallback to default cgroup v2 mount point
		cgroupV2Root = "/sys/fs/cgroup"
	}

	// Try to resolve the path using different cgroup drivers
	resolvedPath := resolveCgroupPath(cgroupV2Root, cgroupPath)
	return resolvedPath
}

// getCgroupV2Root finds the cgroup v2 mount point by reading /proc/mounts
// It returns an empty string if no cgroup v2 mount point is found
func getCgroupV2Root() string {
	commonPaths := []string{
		"/sys/fs/cgroup",
		"/cgroup2",
	}

	if mountPoint := findCgroupV2Mount(); mountPoint != "" {
		return mountPoint
	}

	for _, path := range commonPaths {
		if isCgroupV2Mount(path) {
			return path
		}
	}

	return "/sys/fs/cgroup"
}

// findCgroupV2Mount reads /proc/mounts to find the cgroup2 filesystem mount point
func findCgroupV2Mount() string {
	data, err := os.ReadFile("/proc/mounts")
	if err != nil {
		return ""
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) >= 3 && fields[2] == "cgroup2" {
			return fields[1]
		}
	}
	return ""
}

// isCgroupV2Mount checks if the given path is a cgroup v2 mount point
func isCgroupV2Mount(path string) bool {
	// Check if the path exists and has the cgroup.controllers file (cgroup v2 indicator)
	if _, err := os.Stat(filepath.Join(path, "cgroup.controllers")); err == nil {
		return true
	}
	return false
}

// resolveCgroupPath resolves the cgroup path by trying cgroupfs and systemd cgroup drivers
// It first detects if the path is systemd-style, then applies conversion
func resolveCgroupPath(cgroupRoot, cgroupPath string) string {
	if isSystemdPath(cgroupPath) {
		return convertSystemdPath(cgroupRoot, cgroupPath)
	}

	// For non-systemd paths, use cgroupfs driver (direct filesystem path)
	cgroupfsPath := filepath.Join(cgroupRoot, cgroupPath)
	return cgroupfsPath
}

// isSystemdPath checks if the path looks like a systemd slice path
func isSystemdPath(path string) bool {
	// Systemd paths typically contain .slice or have : notation
	return strings.Contains(path, ".slice") || strings.Contains(path, ":")
}

// convertSystemdPath converts systemd slice notation to filesystem path
func convertSystemdPath(cgroupRoot, systemdPath string) string {
	// Convert systemd slice notation to filesystem path
	// Example: "system.slice/containerd.service/kubepods-burstable-pod123.slice:cri-containerd:container456"
	// becomes: "/sys/fs/cgroup/system.slice/containerd.service/kubepods-burstable-pod123.slice/cri-containerd:container456"

	parts := strings.Split(systemdPath, ":")
	if len(parts) > 1 {
		// Handle the case with colons - the first part is the slice hierarchy
		slicePath := parts[0]

		// Join the remaining parts with colons to form the final component
		finalComponent := strings.Join(parts[1:], ":")

		return filepath.Join(cgroupRoot, slicePath, finalComponent)
	}

	// No colons found, treat as regular path
	return filepath.Join(cgroupRoot, systemdPath)
}
