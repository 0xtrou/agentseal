use serde::{Deserialize, Deserializer, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RuntimeKind {
    Docker,
    Firecracker,
    Gvisor,
    Kata,
    Nspawn,
    GenericLinux,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Stability {
    Stable,
    SemiStable,
    Ephemeral,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SourceValue {
    pub id: &'static str,
    pub value: Vec<u8>,
    pub confidence: u8,
    pub stability: Stability,
}

impl<'de> Deserialize<'de> for SourceValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct SourceValueOwned {
            id: String,
            value: Vec<u8>,
            confidence: u8,
            stability: Stability,
        }

        let owned = SourceValueOwned::deserialize(deserializer)?;
        let leaked_id: &'static str = Box::leak(owned.id.into_boxed_str());

        Ok(Self {
            id: leaked_id,
            value: owned.value,
            confidence: owned.confidence,
            stability: owned.stability,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FingerprintSnapshot {
    pub runtime: RuntimeKind,
    pub stable: Vec<SourceValue>,
    pub ephemeral: Vec<SourceValue>,
    pub collected_at_unix_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FingerprintSourceDef {
    pub id: &'static str,
    pub class: Stability,
    pub default_on: bool,
    pub privileged: bool,
    pub description: &'static str,
}

pub const FINGERPRINT_SOURCES: &[FingerprintSourceDef] = &[
    FingerprintSourceDef {
        id: "linux.machine_id_hmac",
        class: Stability::Stable,
        default_on: true,
        privileged: false,
        description: "Hashed /etc/machine-id using app-scoped HMAC or SHA-256 fallback.",
    },
    FingerprintSourceDef {
        id: "linux.hostname",
        class: Stability::Stable,
        default_on: true,
        privileged: false,
        description: "Normalized kernel hostname for the current runtime.",
    },
    FingerprintSourceDef {
        id: "linux.kernel_release",
        class: Stability::Stable,
        default_on: true,
        privileged: false,
        description: "Kernel release string reported by uname.",
    },
    FingerprintSourceDef {
        id: "linux.cgroup_path",
        class: Stability::Stable,
        default_on: true,
        privileged: false,
        description: "Normalized cgroup path from /proc/self/cgroup.",
    },
    FingerprintSourceDef {
        id: "linux.proc_cmdline_hash",
        class: Stability::Stable,
        default_on: true,
        privileged: false,
        description: "SHA-256 hash of allowlisted boot arguments from /proc/cmdline.",
    },
    FingerprintSourceDef {
        id: "linux.mount_namespace_inode",
        class: Stability::Ephemeral,
        default_on: true,
        privileged: false,
        description: "Namespace inode for /proc/self/ns/mnt.",
    },
    FingerprintSourceDef {
        id: "linux.pid_namespace_inode",
        class: Stability::Ephemeral,
        default_on: true,
        privileged: false,
        description: "Namespace inode for /proc/self/ns/pid.",
    },
    FingerprintSourceDef {
        id: "linux.net_namespace_inode",
        class: Stability::Ephemeral,
        default_on: true,
        privileged: false,
        description: "Namespace inode for /proc/self/ns/net.",
    },
    FingerprintSourceDef {
        id: "linux.uts_namespace_inode",
        class: Stability::Ephemeral,
        default_on: true,
        privileged: false,
        description: "Namespace inode for /proc/self/ns/uts.",
    },
];

#[cfg(test)]
mod tests {
    use super::{SourceValue, Stability};

    #[test]
    fn source_value_round_trip_serialize_deserialize() {
        let value = SourceValue {
            id: "linux.hostname",
            value: b"sandbox-a".to_vec(),
            confidence: 95,
            stability: Stability::Stable,
        };

        let serialized = serde_json::to_string(&value).expect("serialize source value");
        let round_trip: SourceValue =
            serde_json::from_str(&serialized).expect("deserialize source value");

        assert_eq!(round_trip, value);
    }
}
