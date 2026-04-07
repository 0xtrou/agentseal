use std::{env, fs, path::Path};

use crate::model::RuntimeKind;

pub fn detect_runtime() -> RuntimeKind {
    let mut saw_probe_data = false;

    if let Ok(cgroup) = fs::read_to_string("/proc/1/cgroup") {
        saw_probe_data = true;
        let lower = cgroup.to_ascii_lowercase();
        if lower.contains("docker") || lower.contains("containerd") {
            return RuntimeKind::Docker;
        }
    }

    if let Ok(cmdline) = fs::read_to_string("/proc/cmdline") {
        saw_probe_data = true;
        let lower = cmdline.to_ascii_lowercase();
        if lower.contains("firecracker")
            || lower.contains("fc_vcpu")
            || lower.contains("virtio_mmio")
        {
            return RuntimeKind::Firecracker;
        }
    }

    let ns_self = fs::read_link(Path::new("/proc/self/ns/user"));
    let ns_init = fs::read_link(Path::new("/proc/1/ns/user"));
    if let (Ok(self_ns), Ok(init_ns)) = (ns_self, ns_init) {
        saw_probe_data = true;
        if self_ns != init_ns {
            return RuntimeKind::Docker;
        }
    }

    if let Some(container) = env::var_os("container") {
        saw_probe_data = true;
        let value = container.to_string_lossy().to_ascii_lowercase();
        if value.contains("runsc") || value.contains("gvisor") {
            return RuntimeKind::Gvisor;
        }
        if value.contains("nspawn") || value.contains("systemd-nspawn") {
            return RuntimeKind::Nspawn;
        }
        if value.contains("kata") {
            return RuntimeKind::Kata;
        }
        if value.contains("docker") || value.contains("containerd") {
            return RuntimeKind::Docker;
        }
    }

    if saw_probe_data {
        RuntimeKind::GenericLinux
    } else {
        RuntimeKind::Unknown
    }
}

#[cfg(test)]
mod tests {
    use super::detect_runtime;
    use crate::model::RuntimeKind;

    #[test]
    fn detect_runtime_returns_runtime_kind() {
        let runtime = detect_runtime();
        match runtime {
            RuntimeKind::Docker
            | RuntimeKind::Firecracker
            | RuntimeKind::Gvisor
            | RuntimeKind::Kata
            | RuntimeKind::Nspawn
            | RuntimeKind::GenericLinux
            | RuntimeKind::Unknown => {}
        }
    }
}
