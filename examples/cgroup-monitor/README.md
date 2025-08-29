# Cgroup Monitor Plugin Example

This example demonstrates how to use the new `GetCgroup2AbsPath()` method to access absolute cgroup v2 paths for pods and containers.

## What it demonstrates

- How to obtain absolute cgroup v2 paths for both pods and containers
- How to read cgroup v2 controllers and resource information
- Comparison between relative paths (old way) and absolute paths (new way)

## Key Features

The example shows how the new `GetCgroup2AbsPath()` method:

1. **Automatically resolves absolute paths**: Converts relative cgroup paths to absolute paths by finding the cgroup v2 mount point
2. **Handles various cgroup managers**: Works with systemd, cgroupfs, and custom cgroup managers
3. **Supports different QoS classes**: Correctly handles Kubernetes QoS classes (BestEffort, Burstable, Guaranteed)
4. **Provides fallback behavior**: Returns sensible defaults when cgroup information is not available

## Usage

### Building the plugin

```bash
cd examples/cgroup-monitor
go build -o cgroup-monitor .
```

### Running the plugin

The plugin can be run as an NRI plugin with containerd or other CRI runtimes:

```bash
./cgroup-monitor
```

### Example output

```
INFO[2023-01-01T00:00:00Z] cgroup-monitor plugin starting...
INFO[2023-01-01T00:00:00Z] runtime: containerd, version: 1.7.0
INFO[2023-01-01T00:00:00Z] pod my-pod started
INFO[2023-01-01T00:00:00Z] Pod my-pod cgroup paths:
INFO[2023-01-01T00:00:00Z]   Relative: kubepods/burstable/pod123-456-789
INFO[2023-01-01T00:00:00Z]   Absolute: /sys/fs/cgroup/kubepods/burstable/pod123-456-789
INFO[2023-01-01T00:00:00Z] pod my-pod controllers: cpuset cpu io memory pids
INFO[2023-01-01T00:00:00Z] container my-container created in pod my-pod
INFO[2023-01-01T00:00:00Z] Container my-container cgroup paths:
INFO[2023-01-01T00:00:00Z]   Relative: kubepods/burstable/pod123-456-789/container-abc-def
INFO[2023-01-01T00:00:00Z]   Absolute: /sys/fs/cgroup/kubepods/burstable/pod123-456-789/container-abc-def
INFO[2023-01-01T00:00:00Z] container my-container memory usage: 12345678 bytes
INFO[2023-01-01T00:00:00Z] container my-container memory limit: 134217728
```

## Implementation Details

The plugin uses the new `GetCgroup2AbsPath()` method which:

1. Checks if the path is already absolute and returns it as-is
2. Finds the cgroup v2 mount point by reading `/proc/mounts`
3. Falls back to common mount points like `/sys/fs/cgroup`
4. Joins relative paths with the discovered mount point

This approach eliminates the need for plugin developers to implement complex path resolution logic themselves.

## Error Handling

The method gracefully handles various edge cases:

- Returns empty string for nil containers/pods
- Returns empty string when Linux config is missing
- Returns empty string when cgroups path is empty
- Provides sensible fallbacks when mount point detection fails

## Benefits over manual path resolution

Before this method, plugin developers had to:

1. Manually detect the cgroup v2 mount point
2. Handle different cgroup manager layouts (systemd vs cgroupfs)
3. Parse Kubernetes QoS class information
4. Construct absolute paths from various relative path formats

Now, all this complexity is handled by the NRI framework, making plugin development much simpler and more reliable.