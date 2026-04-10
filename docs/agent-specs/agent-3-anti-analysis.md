# Agent 3: Anti-Analysis

## Mission

Implement comprehensive anti-debugging and VM detection to prevent runtime analysis.

---

## Layers

1. Debugger detection
2. Breakpoint detection
3. Timing checks
4. VM detection
5. Environment poisoning

---

## Implementation

**File: `crates/snapfzz-seal-launcher/src/anti_analysis.rs`** (CREATE - file exists but enhance it)

```rust
use std::time::{Duration, Instant};
use std::fs;
use std::arch::x86_64::__cpuid;

/// Multi-layer debugger detection
pub fn detect_debugger() -> bool {
    // Method 1: ptrace check (Linux)
    #[cfg(target_os = "linux")]
    {
        if detect_ptrace() {
            return true;
        }
    }
    
    // Method 2: /proc/self/status TracerPid
    #[cfg(target_os = "linux")]
    {
        if check_tracer_pid() {
            return true;
        }
    }
    
    // Method 3: Check for breakpoints in code
    if detect_breakpoints() {
        return true;
    }
    
    // Method 4: Timing anomaly detection
    if timing_check() {
        return true;
    }
    
    false
}

/// Check if process is being ptraced
#[cfg(target_os = "linux")]
fn detect_ptrace() -> bool {
    unsafe {
        // PTRACE_TRACEME fails if already being traced
        libc::ptrace(libc::PTRACE_TRACEME, 0, 0, 0) == -1
    }
}

/// Check TracerPid in /proc/self/status
#[cfg(target_os = "linux")]
fn check_tracer_pid() -> bool {
    if let Ok(status) = fs::read_to_string("/proc/self/status") {
        for line in status.lines() {
            if line.starts_with("TracerPid:") {
                let pid: i32 = line.split(':')
                    .nth(1)
                    .unwrap_or("0")
                    .trim()
                    .parse()
                    .unwrap_or(0);
                return pid != 0;
            }
        }
    }
    false
}

/// Detect software breakpoints (INT3 = 0xCC) in critical functions
fn detect_breakpoints() -> bool {
    // Get addresses of critical functions
    let critical_functions: Vec<*const u8> = vec![
        decrypt_payload as *const u8,
        verify_signature as *const u8,
        load_master_secret as *const u8,
    ];
    
    unsafe {
        for func_ptr in critical_functions {
            // Check first 32 bytes for INT3 instruction (0xCC)
            for offset in 0..32 {
                let byte = *func_ptr.add(offset);
                if byte == 0xCC {
                    tracing::warn!("Breakpoint detected at {:p}+{}", func_ptr, offset);
                    return true;
                }
            }
        }
    }
    
    false
}

/// Timing check - detect if execution is being traced/instrumented
fn timing_check() -> bool {
    let iterations = 100_000;
    let expected_duration = Duration::from_micros(500); // ~5ns per iteration
    
    let start = Instant::now();
    
    // Known computation with predictable timing
    let mut sum: u64 = 0;
    for i in 0..iterations {
        sum = sum.wrapping_add(i);
        std::hint::black_box(sum);
    }
    
    let elapsed = start.elapsed();
    
    // If >50x slower, likely being traced
    if elapsed > expected_duration * 50 {
        tracing::warn!(
            "Timing anomaly detected: {:?} expected {:?}",
            elapsed,
            expected_duration
        );
        return true;
    }
    
    false
}

/// Detect if running inside a virtual machine
pub fn detect_virtual_machine() -> bool {
    // Method 1: CPUID hypervisor bit
    #[cfg(target_arch = "x86_64")]
    {
        if check_cpuid_hypervisor() {
            return true;
        }
    }
    
    // Method 2: Check for VM artifacts in system files
    #[cfg(target_os = "linux")]
    {
        if check_vm_artifacts() {
            return true;
        }
    }
    
    // Method 3: Check MAC address for known VM prefixes
    #[cfg(target_os = "linux")]
    {
        if check_vm_mac_address() {
            return true;
        }
    }
    
    false
}

/// Check CPUID for hypervisor presence
#[cfg(target_arch = "x86_64")]
fn check_cpuid_hypervisor() -> bool {
    unsafe {
        // CPUID leaf 1, ECX bit 31 = hypervisor present
        let cpuid = __cpuid(1);
        (cpuid.ecx >> 31) & 1 == 1
    }
}

/// Check system files for VM indicators
#[cfg(target_os = "linux")]
fn check_vm_artifacts() -> bool {
    let vm_indicators = [
        "/sys/class/dmi/id/product_name",
        "/sys/class/dmi/id/board_vendor",
        "/proc/scsi/scsi",
    ];
    
    let vm_keywords = [
        "vmware", "virtualbox", "qemu", "xen", "kvm",
        "virtual", "hyperv", "parallels", "bochs",
    ];
    
    for path in &vm_indicators {
        if let Ok(content) = fs::read_to_string(path) {
            let content_lower = content.to_lowercase();
            for keyword in &vm_keywords {
                if content_lower.contains(keyword) {
                    tracing::debug!("VM artifact found in {}: {}", path, keyword);
                    return true;
                }
            }
        }
    }
    
    false
}

/// Check MAC address for VM vendor prefixes
#[cfg(target_os = "linux")]
fn check_vm_mac_address() -> bool {
    let vm_mac_prefixes = [
        "00:05:69",  // VMware
        "00:0c:29",  // VMware
        "00:1c:14",  // VMware
        "00:50:56",  // VMware
        "08:00:27",  // VirtualBox
        "52:54:00",  // QEMU/KVM
        "00:16:3e",  // Xen
        "00:1c:42",  // Parallels
    ];
    
    // Check common interface names
    let interfaces = ["eth0", "ens3", "enp0s3"];
    
    for iface in &interfaces {
        let path = format!("/sys/class/net/{}/address", iface);
        if let Ok(mac) = fs::read_to_string(&path) {
            let mac_lower = mac.to_lowercase();
            for prefix in &vm_mac_prefixes {
                if mac_lower.starts_with(prefix) {
                    tracing::debug!("VM MAC detected: {}", mac.trim());
                    return true;
                }
            }
        }
    }
    
    false
}

/// Comprehensive check if being analyzed
pub fn is_being_analyzed() -> bool {
    detect_debugger() || detect_virtual_machine()
}

/// Poison the environment with fake data
pub fn poison_environment() {
    // Set fake environment variables
    unsafe {
        std::env::set_var(
            "SNAPFZZ_SEAL_MASTER_SECRET_HEX",
            "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
        );
        std::env::set_var("SNAPFZZ_SEAL_DEBUG", "true");
        std::env::set_var("SNAPFZZ_SEAL_TRACE", "1");
    }
    
    // Create decoy files
    let decoy_files = [
        "/tmp/.snapfzz_seal_cache",
        "/tmp/.snapfzz_key_backup",
        "/var/tmp/snapfzz_debug.log",
    ];
    
    for path in &decoy_files {
        let _ = fs::write(path, b"DECOY_DATA_DO_NOT_USE");
    }
    
    tracing::debug!("Environment poisoned with decoy data");
}

/// Stub functions for references
fn decrypt_payload() {}
fn verify_signature() {}
fn load_master_secret() {}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_timing_check() {
        // Should pass when not being traced
        assert!(!timing_check());
    }
    
    #[test]
    fn test_vm_detection() {
        // May or may not detect VM depending on environment
        let is_vm = detect_virtual_machine();
        println!("Running in VM: {}", is_vm);
    }
    
    #[test]
    fn test_environment_poisoning() {
        poison_environment();
        
        assert_eq!(
            std::env::var("SNAPFZZ_SEAL_DEBUG").unwrap(),
            "true"
        );
    }
}
```

---

## Integration

**File: `crates/snapfzz-seal-launcher/src/lib.rs`** (MODIFY)

```rust
mod anti_analysis;

// In main execution path
pub fn run(cli: Cli) -> Result<(), SealError> {
    // Early check: Are we being analyzed?
    if anti_analysis::is_being_analyzed() {
        tracing::error!("Analysis detected, aborting");
        std::process::exit(1);
    }
    
    // Poison environment with decoy data
    anti_analysis::poison_environment();
    
    // Continue with normal execution
    // ...
}
```

---

## Files to Create/Modify

1. **CREATE/ENHANCE:** `crates/snapfzz-seal-launcher/src/anti_analysis.rs`
2. **MODIFY:** `crates/snapfzz-seal-launcher/src/lib.rs`
3. **MODIFY:** `crates/snapfzz-seal-launcher/Cargo.toml`

**Cargo.toml additions:**
```toml
[target.'cfg(target_os = "linux")'.dependencies]
libc = "0.2"
```

---

## Testing

```bash
# Normal test
cargo test --package snapfzz-seal-launcher anti_analysis

# Test under debugger (should fail)
cargo test --package snapfzz-seal-launcher anti_analysis -- --test-threads=1
# Then: gdb --args <test-binary>
# (gdb) run
# Should detect debugger
```

---

## Trade-offs

**Pros:**
- Raises attacker cost significantly
- Standard practice in security software
- Multiple detection methods

**Cons:**
- May have false positives (legitimate VM users)
- Can be bypassed by skilled RE
- Performance overhead for timing checks

---

## Success Criteria

- [ ] Debugger detection works (ptrace, TracerPid)
- [ ] Breakpoint detection works
- [ ] Timing check detects instrumentation
- [ ] VM detection identifies common hypervisors
- [ ] Environment poisoning adds decoy data
- [ ] All tests pass
- [ ] No crashes on non-Linux platforms

---

## Future Enhancements

1. **Anti-anti-debug:** Detect attempts to bypass our checks
2. **Control flow integrity:** Verify execution follows expected paths
3. **Memory integrity:** Detect memory dumping attempts
4. **Self-modifying code:** Obfuscate critical sections at runtime