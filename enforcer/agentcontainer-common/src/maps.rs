//! BPF map key and value types shared between kernel and userspace.
//!
//! These types must have a stable memory layout (`repr(C)`) and match exactly
//! between the BPF programs and the userspace map operations.

// --- Network map keys ---

/// Key for IPv4 LPM trie (longest prefix match).
/// `prefixlen` MUST be the first field for BPF LPM trie compatibility.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LpmKeyV4 {
    pub prefixlen: u32,
    pub addr: u32,
}

/// Key for IPv6 LPM trie (longest prefix match).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LpmKeyV6 {
    pub prefixlen: u32,
    pub addr: [u32; 4],
}

/// Key for the allowed ports hash map (IPv4).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PortKeyV4 {
    pub ip: u32,
    pub port: u16,
    pub protocol: u8,
    pub _pad: u8,
}

/// Scoped key data for allowed IPv4 LPM trie entries.
///
/// Used with `aya`/`aya-ebpf` LPM `Key`, which stores the prefix length outside
/// this struct. The cgroup must be the first data field so exact cgroup matching
/// can be included in the LPM prefix before the address bits.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScopedLpmKeyV4 {
    pub cgroup_id: u64,
    pub addr: u32,
    pub _pad: u32,
}

/// Scoped key data for allowed IPv6 LPM trie entries.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScopedLpmKeyV6 {
    pub cgroup_id: u64,
    pub addr: [u32; 4],
}

/// Key for container-scoped IPv4 IP+port+protocol allow rules.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScopedPortKeyV4 {
    pub cgroup_id: u64,
    pub ip: u32,
    pub port: u16,
    pub protocol: u8,
    pub _pad: u8,
}

// --- Filesystem map keys ---

/// Key for the filesystem inode allow/deny maps.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FsInodeKey {
    pub inode: u64,
    pub dev_major: u32,
    pub dev_minor: u32,
}

/// Container-scoped filesystem inode key.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScopedFsInodeKey {
    pub inode: u64,
    pub cgroup_id: u64,
    pub dev_major: u32,
    pub dev_minor: u32,
}

// --- Process deny-set map keys ---

/// Key for deny-set policy lookup: (deny_set_id, inode, dev).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DenySetKey {
    pub deny_set_id: u32,
    pub _pad: u32,
    pub inode: u64,
    pub dev_major: u32,
    pub dev_minor: u32,
}

// --- Bind map keys ---

/// Key for allowed bind ports.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BindKey {
    pub port: u16,
    pub protocol: u8,
    pub _pad: u8,
}

/// Container-scoped bind allow key.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScopedBindKey {
    pub cgroup_id: u64,
    pub port: u16,
    pub protocol: u8,
    pub _pad: u8,
}

// --- Credential map keys ---

/// Key for credential/secret ACL enforcement.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SecretAclKey {
    pub inode: u64,
    pub dev_major: u32,
    pub dev_minor: u32,
    pub cgroup_id: u64,
}

/// Value for credential/secret ACL entries.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SecretAclValue {
    pub expires_at_ns: u64,
    pub allowed_ops: u8,
    pub _pad: [u8; 7],
}

// --- Permission constants ---

pub const FS_PERM_READ: u8 = 0x01;
pub const FS_PERM_WRITE: u8 = 0x02;

// --- Per-cgroup statistics ---

/// Per-cgroup enforcement statistics tracked in BPF per-CPU hash maps.
///
/// Each enforced cgroup gets one entry in the `CGROUP_STATS` per-CPU hash map.
/// BPF programs increment the relevant counter on each enforcement decision.
/// Userspace sums across CPUs to get totals.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CgroupStats {
    pub network_allowed: u64,
    pub network_blocked: u64,
    pub filesystem_allowed: u64,
    pub filesystem_blocked: u64,
    pub process_allowed: u64,
    pub process_blocked: u64,
    pub credential_allowed: u64,
    pub credential_blocked: u64,
    pub bind_allowed: u64,
    pub bind_blocked: u64,
    pub denyset_allowed: u64,
    pub denyset_blocked: u64,
}


// --- Cgroup enforcement flags (values stored in ENFORCED_CGROUPS) ---

/// The cgroup is enforced (registered) — network + filesystem hooks apply.
/// Every registered cgroup carries this bit; the other hooks read the map via
/// `.is_some()` and ignore the value, so a nonzero flag byte is compatible.
pub const CGROUP_FLAG_ENFORCED: u8 = 0x01;
/// The cgroup has a non-empty exec allowlist; bprm_check authorizes its execs.
/// Exec enforcement is opt-in: without this bit, execs run freely (a cgroup
/// with no declared binaries — e.g. a tool-runner backend — is not exec-gated).
pub const CGROUP_FLAG_EXEC_ENFORCED: u8 = 0x02;

// --- Kernel struct field offsets (CO-RE substitute) ---

/// Byte offsets of the kernel struct fields the LSM hooks walk, resolved from
/// the running kernel's BTF in userspace at startup and published to the eBPF
/// programs via the single-entry `KERNEL_OFFSETS` array map.
///
/// The Rust eBPF toolchain emits no CO-RE field relocations (aya-ebpf 0.1.x),
/// so hardcoded `#[repr(C)]` mirror offsets silently break across kernel
/// versions — e.g. `linux_binprm`'s first field is `vma`, not `file`, on 6.x.
/// Resolving offsets from BTF and reading `base + offset` is portable across
/// 5.15–6.x. All values are byte offsets.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct KernelOffsets {
    pub binprm_file: u32,   // linux_binprm.file       (*file)
    pub file_f_inode: u32,  // file.f_inode            (*inode)  — stable since v3.9
    pub file_f_path: u32,   // file.f_path             (struct path, embedded)
    pub file_f_flags: u32,  // file.f_flags            (u32)
    pub path_dentry: u32,   // path.dentry             (*dentry)
    pub dentry_d_name: u32, // dentry.d_name          (struct qstr, embedded)
    pub qstr_name: u32,     // qstr.name               (*u8)
    pub inode_i_ino: u32,   // inode.i_ino             (unsigned long)
    pub inode_i_sb: u32,    // inode.i_sb              (*super_block)
    pub sb_s_dev: u32,      // super_block.s_dev       (dev_t / u32)
    pub sb_s_magic: u32,    // super_block.s_magic     (unsigned long)
}

// --- Verdicts ---

pub const VERDICT_ALLOW: i32 = 1;
pub const VERDICT_BLOCK: i32 = 0;

// --- LSM verdicts ---

pub const LSM_ALLOW: i32 = 0;
pub const LSM_DENY: i32 = -13; // -EACCES

// --- Procfs ---

pub const PROC_SUPER_MAGIC: u64 = 0x9fa0;
pub const DENTRY_NAME_LEN: usize = 32;

// --- aya Pod impls (userspace only) ---

// SAFETY: All types are #[repr(C)], Copy, and 'static — they satisfy Pod requirements.
// Pod is needed for aya's userspace HashMap/LpmTrie map operations.
#[cfg(target_os = "linux")]
mod pod_impls {
    unsafe impl aya::Pod for super::PortKeyV4 {}
    unsafe impl aya::Pod for super::ScopedLpmKeyV4 {}
    unsafe impl aya::Pod for super::ScopedLpmKeyV6 {}
    unsafe impl aya::Pod for super::ScopedPortKeyV4 {}
    unsafe impl aya::Pod for super::FsInodeKey {}
    unsafe impl aya::Pod for super::ScopedFsInodeKey {}
    unsafe impl aya::Pod for super::SecretAclKey {}
    unsafe impl aya::Pod for super::SecretAclValue {}
    unsafe impl aya::Pod for super::LpmKeyV4 {}
    unsafe impl aya::Pod for super::LpmKeyV6 {}
    unsafe impl aya::Pod for super::CgroupStats {}
    unsafe impl aya::Pod for super::DenySetKey {}
    unsafe impl aya::Pod for super::BindKey {}
    unsafe impl aya::Pod for super::ScopedBindKey {}
    unsafe impl aya::Pod for super::KernelOffsets {}
}
