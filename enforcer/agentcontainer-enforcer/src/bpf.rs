//! BPF program loader and map manager.
//!
//! [`BpfPolicyManager`] implements [`PolicyManager`] by translating high-level
//! policy requests into BPF map operations via aya.
//!
//! On non-Linux platforms (macOS, Windows), BPF is unavailable so a stub
//! implementation logs warnings and returns `Ok(())` for all operations.
//! This allows the enforcer to compile and run its gRPC server on macOS
//! during development, deferring BPF enforcement to Linux containers.

use std::collections::HashMap;
use std::sync::RwLock;

use tonic::async_trait;
#[cfg(target_os = "linux")]
use tracing::info;
use tracing::warn;

use crate::events::{ContainerRegistry, EventBus};
use crate::policy::{
    BindPolicy, ContainerHandle, CredentialPolicy, DenySetPolicy, EnforcementEvent,
    EnforcementStats, FilesystemPolicy, NetworkPolicy, PolicyManager, ProcessPolicy,
    ResolvedDenySetEntry, ReverseShellConfig,
};

#[cfg(any(target_os = "linux", all(test, unix)))]
use std::path::{Path, PathBuf};

/// Minimal common prefix for all event records written to ring buffers.
#[cfg(any(target_os = "linux", all(test, unix)))]
#[repr(C)]
#[derive(Clone, Copy)]
struct EventPidHeader {
    timestamp_ns: u64,
    pid: u32,
}

#[cfg(any(target_os = "linux", all(test, unix)))]
fn read_event_pid(data: &[u8]) -> Option<u32> {
    if data.len() < std::mem::size_of::<EventPidHeader>() {
        return None;
    }

    let header: EventPidHeader = unsafe { std::ptr::read_unaligned(data.as_ptr() as *const _) };
    Some(header.pid)
}

#[cfg(any(target_os = "linux", all(test, unix)))]
fn parse_proc_cgroup_relative_path(contents: &str) -> Option<&str> {
    let mut fallback = None;

    for line in contents.lines() {
        let (hierarchy, rest) = line.split_once(':')?;
        let (_, path) = rest.split_once(':')?;
        if path.is_empty() {
            continue;
        }
        if hierarchy == "0" {
            return Some(path);
        }
        fallback.get_or_insert(path);
    }

    fallback
}

#[cfg(any(target_os = "linux", all(test, unix)))]
fn resolve_cgroup_path_for_pid_with_roots(
    pid: u32,
    proc_root: &Path,
    cgroup_root: &Path,
) -> anyhow::Result<PathBuf> {
    let cgroup_file = proc_root.join(pid.to_string()).join("cgroup");
    let contents = std::fs::read_to_string(&cgroup_file)
        .map_err(|e| anyhow::anyhow!("failed to read {}: {e}", cgroup_file.display()))?;
    let relative = parse_proc_cgroup_relative_path(&contents)
        .ok_or_else(|| anyhow::anyhow!("no cgroup path found in {}", cgroup_file.display()))?;
    let relative = relative.strip_prefix('/').unwrap_or(relative);
    Ok(cgroup_root.join(relative))
}

#[cfg(any(target_os = "linux", all(test, unix)))]
fn resolve_cgroup_id_for_pid_with_roots(
    pid: u32,
    proc_root: &Path,
    cgroup_root: &Path,
) -> anyhow::Result<u64> {
    use std::os::unix::fs::MetadataExt;

    let cgroup_path = resolve_cgroup_path_for_pid_with_roots(pid, proc_root, cgroup_root)?;
    let meta = std::fs::metadata(&cgroup_path).map_err(|e| {
        anyhow::anyhow!("failed to stat cgroup path {}: {e}", cgroup_path.display())
    })?;
    Ok(meta.ino())
}

// ===========================================================================
// Linux implementation — real BPF via aya
// ===========================================================================

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use crate::events::{
        parse_bind_event, parse_cred_event, parse_dns_event, parse_exec_event, parse_fs_event,
        parse_memfd_event, parse_network_event, parse_reverse_shell_event, MemfdEvent,
    };
    use agentcontainer_common::events as bpf_events;
    use agentcontainer_common::maps::{
        CgroupStats, DenySetKey, KernelOffsets, ScopedBindKey, ScopedFsInodeKey, ScopedLpmKeyV4,
        ScopedPortKeyV4, SecretAclKey, SecretAclValue, CGROUP_FLAG_ENFORCED,
        CGROUP_FLAG_EXEC_ENFORCED, FS_PERM_READ, FS_PERM_WRITE,
    };
    use aya::maps::lpm_trie::Key as LpmKey;
    use aya::maps::{HashMap as AyaHashMap, LpmTrie, PerCpuHashMap, RingBuf};
    use aya::Ebpf;
    use std::os::unix::fs::MetadataExt;

    const CGROUP_PREFIX_BITS: u32 = 64;
    const IPV4_PREFIX_BITS: u32 = CGROUP_PREFIX_BITS + 32;

    /// Well-known paths where the BPF ELF may be found, in priority order.
    ///
    /// 1. Installed path (in containers).
    /// 2. xtask release build (manual `cargo xtask build-ebpf --release`).
    /// 3. xtask debug build (manual `cargo xtask build-ebpf`).
    const BPF_ELF_PATHS: &[&str] = &[
        "/usr/lib/agentcontainer-enforcer/agentcontainer-ebpf-progs",
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../target/bpfel-unknown-none/release/agentcontainer-ebpf-progs"
        ),
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../target/bpfel-unknown-none/debug/agentcontainer-ebpf-progs"
        ),
    ];

    /// Path to BPF ELF compiled by aya-build during `cargo build`.
    /// Set by build.rs via `cargo:rustc-env`. None when BPF build was skipped.
    const BPF_ELF_AYA_BUILD: Option<&str> = option_env!("AC_BPF_OUT_DIR");

    /// Environment variable to override the BPF ELF path.
    const BPF_ELF_ENV: &str = "AC_BPF_ELF_PATH";

    /// Real BPF-backed policy manager for Linux.
    ///
    /// Holds the loaded BPF programs and typed map handles. Methods translate
    /// high-level policy types from [`crate::policy`] into BPF map key/value
    /// insertions via aya.
    pub struct BpfPolicyManager {
        /// The loaded eBPF programs (network hooks, LSM hooks, DNS parser).
        programs: std::sync::Mutex<Ebpf>,

        /// Tracks cgroup_id -> container_id for ring buffer event correlation.
        registry: ContainerRegistry,

        /// Fan-out event bus for gRPC streaming.
        #[allow(dead_code)]
        event_bus: EventBus,

        /// In-memory tracking of which cgroup IDs have been registered,
        /// so we can clean up all related map entries on unregister.
        container_cgroups: RwLock<HashMap<String, u64>>,
    }

    impl BpfPolicyManager {
        /// Load BPF programs from the compiled ELF object.
        ///
        /// The ELF is located by checking (in order):
        /// 1. `AC_BPF_ELF_PATH` environment variable
        /// 2. aya-build output (compiled automatically by build.rs)
        /// 3. `/usr/lib/agentcontainer-enforcer/agentcontainer-ebpf` (installed path)
        /// 4. `target/bpfel-unknown-none/release/agentcontainer-ebpf` (xtask release build)
        /// 5. `target/bpfel-unknown-none/debug/agentcontainer-ebpf` (xtask debug build)
        ///
        /// This requires:
        /// - Linux 5.15+ with BTF support
        /// - CAP_BPF + CAP_NET_ADMIN capabilities
        /// - The `agentcontainer-ebpf` crate compiled to BPF bytecode (automatic via `cargo build`)
        pub fn new() -> anyhow::Result<Self> {
            let elf_bytes = Self::load_bpf_elf()?;
            let mut bpf = Ebpf::load(&elf_bytes)
                .map_err(|e| anyhow::anyhow!("failed to load BPF programs: {e}"))?;

            // Initialize BPF logging (non-fatal — tracing may not be wired yet).
            if let Err(e) = aya_log::EbpfLogger::init(&mut bpf) {
                warn!("BPF logger initialization failed (non-fatal): {e}");
            }

            info!("BPF programs loaded successfully");

            // Attach programs to their kernel hook points.
            Self::populate_kernel_offsets(&mut bpf)?;
            Self::attach_programs(&mut bpf)?;

            let registry = ContainerRegistry::new();
            let event_bus = EventBus::new();

            let mgr = Self {
                programs: std::sync::Mutex::new(bpf),
                registry,
                event_bus,
                container_cgroups: RwLock::new(HashMap::new()),
            };

            // Spawn background ring buffer readers for all event sources.
            mgr.spawn_event_readers();

            Ok(mgr)
        }

        /// Attach all BPF programs to their kernel hook points.
        ///
        /// Programs are attached in a best-effort manner: if a specific hook is
        /// unavailable on the running kernel (e.g., `sys_enter_memfd_create` on
        /// older kernels), a warning is logged but startup continues. Only
        /// critical failures (e.g., unable to open the root cgroup) are fatal.
        fn attach_programs(bpf: &mut Ebpf) -> anyhow::Result<()> {
            use aya::programs::{CgroupAttachMode, CgroupSockAddr, KProbe, Lsm, TracePoint};
            use aya::Btf;
            use std::os::fd::AsFd;

            // Open the root cgroup v2 hierarchy for cgroup-attached programs.
            let cgroup_file = std::fs::File::open("/sys/fs/cgroup/")
                .map_err(|e| anyhow::anyhow!("failed to open cgroup v2 root: {e}"))?;
            let cgroup_fd = cgroup_file.as_fd();

            let btf = Btf::from_sys_fs()
                .map_err(|e| anyhow::anyhow!("failed to load kernel BTF for LSM hooks: {e}"))?;

            // ---------------------------------------------------------------
            // LSM hooks (required for process enforcement)
            // ---------------------------------------------------------------

            match bpf.program_mut("ac_bprm_check") {
                Some(prog) => {
                    let lsm: &mut Lsm = prog.try_into()?;
                    lsm.load("bprm_check_security", &btf)?;
                    lsm.attach()
                        .map_err(|e| anyhow::anyhow!("failed to attach ac_bprm_check: {e}"))?;
                    info!("attached ac_bprm_check to LSM bprm_check_security");
                }
                None => {
                    return Err(anyhow::anyhow!(
                        "BPF program ac_bprm_check not found in ELF"
                    ));
                }
            }

            match bpf.program_mut("ac_file_open") {
                Some(prog) => {
                    let lsm: &mut Lsm = prog.try_into()?;
                    lsm.load("file_open", &btf)?;
                    lsm.attach()
                        .map_err(|e| anyhow::anyhow!("failed to attach ac_file_open: {e}"))?;
                    info!("attached ac_file_open to LSM file_open");
                }
                None => {
                    return Err(anyhow::anyhow!("BPF program ac_file_open not found in ELF"));
                }
            }

            // ---------------------------------------------------------------
            // Tracepoints
            // ---------------------------------------------------------------

            // sched/sched_process_fork — deny-set inheritance tracking.
            match bpf.program_mut("ac_sched_fork") {
                Some(prog) => {
                    let tp: &mut TracePoint = prog.try_into()?;
                    tp.load()?;
                    match tp.attach("sched", "sched_process_fork") {
                        Ok(_link) => info!("attached ac_sched_fork to sched/sched_process_fork"),
                        Err(e) => warn!(error = %e, "failed to attach ac_sched_fork (non-fatal)"),
                    }
                }
                None => warn!("BPF program ac_sched_fork not found in ELF"),
            }

            // sched/sched_process_exit — deny-set cleanup on process exit.
            match bpf.program_mut("ac_sched_exit") {
                Some(prog) => {
                    let tp: &mut TracePoint = prog.try_into()?;
                    tp.load()?;
                    match tp.attach("sched", "sched_process_exit") {
                        Ok(_link) => info!("attached ac_sched_exit to sched/sched_process_exit"),
                        Err(e) => warn!(error = %e, "failed to attach ac_sched_exit (non-fatal)"),
                    }
                }
                None => warn!("BPF program ac_sched_exit not found in ELF"),
            }

            // syscalls/sys_enter_memfd_create — fileless execution detection.
            match bpf.program_mut("ac_memfd_create") {
                Some(prog) => {
                    let tp: &mut TracePoint = prog.try_into()?;
                    tp.load()?;
                    match tp.attach("syscalls", "sys_enter_memfd_create") {
                        Ok(_link) => {
                            info!("attached ac_memfd_create to syscalls/sys_enter_memfd_create")
                        }
                        Err(e) => warn!(
                            error = %e,
                            "failed to attach ac_memfd_create — kernel may lack this tracepoint (non-fatal)"
                        ),
                    }
                }
                None => warn!("BPF program ac_memfd_create not found in ELF"),
            }

            // ---------------------------------------------------------------
            // Cgroup socket address hooks (bind enforcement)
            // ---------------------------------------------------------------

            for program_name in ["ac_connect4", "ac_connect6", "ac_sendmsg4", "ac_sendmsg6"] {
                match bpf.program_mut(program_name) {
                    Some(prog) => {
                        let cg: &mut CgroupSockAddr = prog.try_into()?;
                        cg.load()?;
                        cg.attach(cgroup_fd, CgroupAttachMode::Single)
                            .map_err(|e| anyhow::anyhow!("failed to attach {program_name}: {e}"))?;
                        info!(
                            program = program_name,
                            "attached cgroup socket address program"
                        );
                    }
                    None => {
                        return Err(anyhow::anyhow!(
                            "BPF program {program_name} not found in ELF"
                        ));
                    }
                }
            }

            // cgroup/bind4 — IPv4 bind enforcement.
            match bpf.program_mut("ac_bind4") {
                Some(prog) => {
                    let cg: &mut CgroupSockAddr = prog.try_into()?;
                    cg.load()?;
                    cg.attach(cgroup_fd, CgroupAttachMode::Single)
                        .map_err(|e| anyhow::anyhow!("failed to attach ac_bind4: {e}"))?;
                    info!("attached ac_bind4 to cgroup bind4");
                }
                None => return Err(anyhow::anyhow!("BPF program ac_bind4 not found in ELF")),
            }

            // cgroup/bind6 — IPv6 bind enforcement.
            match bpf.program_mut("ac_bind6") {
                Some(prog) => {
                    let cg: &mut CgroupSockAddr = prog.try_into()?;
                    cg.load()?;
                    cg.attach(cgroup_fd, CgroupAttachMode::Single)
                        .map_err(|e| anyhow::anyhow!("failed to attach ac_bind6: {e}"))?;
                    info!("attached ac_bind6 to cgroup bind6");
                }
                None => return Err(anyhow::anyhow!("BPF program ac_bind6 not found in ELF")),
            }

            // ---------------------------------------------------------------
            // Kprobe — reverse shell dup2 detection
            // ---------------------------------------------------------------

            // kprobe/__x64_sys_dup2 — detects stdin/stdout redirection to sockets.
            match bpf.program_mut("ac_dup2_check") {
                Some(prog) => {
                    let kp: &mut KProbe = prog.try_into()?;
                    kp.load()?;
                    match kp.attach("__x64_sys_dup2", 0) {
                        Ok(_link) => info!("attached ac_dup2_check to kprobe __x64_sys_dup2"),
                        Err(e) => warn!(
                            error = %e,
                            "failed to attach ac_dup2_check — __x64_sys_dup2 may not exist on this arch (non-fatal)"
                        ),
                    }
                }
                None => warn!("BPF program ac_dup2_check not found in ELF"),
            }

            // ---------------------------------------------------------------
            // LSM hooks — loaded and attached by aya automatically when the
            // ELF contains BTF-based LSM programs. We log their presence here
            // for observability but no manual attachment is needed.
            // ---------------------------------------------------------------

            // Suppress unused variable warning for cgroup_fd — it's used above
            // and kept alive until this function returns.
            let _ = &cgroup_file;

            info!("BPF program attachment complete");
            Ok(())
        }

        /// Spawn background tasks that drain all BPF ring buffers and publish
        /// parsed events to the [`EventBus`].
        ///
        /// Each ring buffer gets its own tokio task. Tasks run until the
        /// ring buffer is closed (i.e. the BPF programs are unloaded). Events
        /// are parsed into [`EnforcementEvent`]s and fanned out via the
        /// [`EventBus`] to all gRPC stream subscribers.
        fn spawn_event_readers(&self) {
            // Spawn a dedicated OS thread that holds the BPF programs lock and
            // runs all ring buffer readers. We pass a raw pointer to self.programs
            // because the Mutex<Ebpf> is not Arc-wrapped. This is safe because
            // BpfPolicyManager lives for the process lifetime (created at startup,
            // never dropped).
            let programs_ptr = &self.programs as *const std::sync::Mutex<Ebpf>;
            // SAFETY: BpfPolicyManager is created once at startup and lives until
            // process exit. The thread we spawn accesses programs through this
            // pointer for its entire lifetime.
            let programs: &'static std::sync::Mutex<Ebpf> = unsafe { &*programs_ptr };
            let bus = self.event_bus.clone();
            let registry = self.registry.clone();

            std::thread::Builder::new()
                .name("event-readers".into())
                .spawn(move || {
                    let rt = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .expect("event reader runtime");

                    let local = tokio::task::LocalSet::new();
                    local.block_on(&rt, async {
                        // Leak the MutexGuard — held for the process lifetime.
                        // Ring buffer readers need 'static refs to MapData inside.
                        let bpf = Box::leak(Box::new(programs.lock().unwrap()));
                        let mut handles = Vec::new();

                        macro_rules! spawn_reader {
                            ($map_name:expr, $event_type:ty, $parse_fn:expr) => {
                                if let Some(map_data) = bpf.map($map_name) {
                                    if let Ok(ring_buf) = RingBuf::try_from(map_data) {
                                        let b = bus.clone();
                                        let r = registry.clone();
                                        handles.push(tokio::task::spawn_local(async move {
                                            Self::run_ring_buf_reader(
                                                ring_buf,
                                                b,
                                                r,
                                                |data, cid| {
                                                    if data.len()
                                                        >= std::mem::size_of::<$event_type>()
                                                    {
                                                        let raw: $event_type = unsafe {
                                                            std::ptr::read_unaligned(
                                                                data.as_ptr() as *const _
                                                            )
                                                        };
                                                        Some($parse_fn(&raw, cid))
                                                    } else {
                                                        None
                                                    }
                                                },
                                            )
                                            .await;
                                        }));
                                        info!("{} ring buffer reader started", $map_name);
                                    }
                                }
                            };
                        }

                        spawn_reader!("NET_EVENTS", bpf_events::NetworkEvent, parse_network_event);
                        spawn_reader!("DNS_EVENTS", bpf_events::DnsEvent, parse_dns_event);
                        spawn_reader!("FS_EVENTS", bpf_events::FsEvent, parse_fs_event);
                        spawn_reader!("PROC_EVENTS", bpf_events::ExecEvent, parse_exec_event);
                        spawn_reader!("CRED_EVENTS", bpf_events::CredEvent, parse_cred_event);
                        spawn_reader!("BIND_EVENTS", bpf_events::BindEvent, parse_bind_event);
                        spawn_reader!(
                            "REVERSE_SHELL_EVENTS",
                            bpf_events::ReverseShellEvent,
                            parse_reverse_shell_event
                        );
                        spawn_reader!("MEMFD_EVENTS", MemfdEvent, parse_memfd_event);

                        for h in handles {
                            let _ = h.await;
                        }
                    });
                })
                .expect("spawn event reader thread");
        }

        /// Generic ring buffer drain loop.
        ///
        /// Reads events from the ring buffer, resolves the `cgroup_id` field in the
        /// raw data to a container ID via the [`ContainerRegistry`], calls `parse` to
        /// produce an [`EnforcementEvent`], and publishes it to the [`EventBus`].
        ///
        /// `parse` receives the raw byte slice and the resolved container ID string.
        /// It returns `None` if the data is malformed or should be skipped.
        ///
        /// The loop terminates when the ring buffer returns no items (i.e. the BPF
        /// programs have been unloaded) — this is expected during normal shutdown.
        async fn run_ring_buf_reader<F>(
            mut ring_buf: RingBuf<&aya::maps::MapData>,
            bus: EventBus,
            registry: ContainerRegistry,
            parse: F,
        ) where
            F: Fn(&[u8], &str) -> Option<crate::policy::EnforcementEvent> + Send + 'static,
        {
            use aya::util::online_cpus;
            use tokio::io::unix::AsyncFd;

            // Wrap the ring buffer fd for async readiness notifications.
            let raw_fd = {
                use std::os::unix::io::AsRawFd;
                ring_buf.as_raw_fd()
            };

            // Safety: we hold `ring_buf` for the lifetime of this future, so the fd is valid.
            let async_fd = match AsyncFd::new(raw_fd) {
                Ok(fd) => fd,
                Err(e) => {
                    warn!(error = %e, "failed to create AsyncFd for ring buffer — event reader disabled");
                    return;
                }
            };

            loop {
                // Wait until the ring buffer has data.
                let mut guard = match async_fd.readable().await {
                    Ok(g) => g,
                    Err(e) => {
                        warn!(error = %e, "ring buffer readable() error, stopping reader");
                        break;
                    }
                };

                // Drain all available records.
                while let Some(item) = ring_buf.next() {
                    let data: &[u8] = &item;
                    let container_id = match read_event_pid(data) {
                        Some(pid) => Self::resolve_container_id_for_pid(&registry, pid)
                            .await
                            .unwrap_or_default(),
                        None => String::new(),
                    };

                    if let Some(event) = parse(data, &container_id) {
                        bus.publish(event);
                    }
                }

                guard.clear_ready();
                let _ = online_cpus(); // suppress unused import warning
            }
        }

        async fn resolve_container_id_for_pid(
            registry: &ContainerRegistry,
            pid: u32,
        ) -> Option<String> {
            let cgroup_id = match resolve_cgroup_id_for_pid_with_roots(
                pid,
                Path::new("/proc"),
                Path::new("/sys/fs/cgroup"),
            ) {
                Ok(cgroup_id) => cgroup_id,
                Err(e) => {
                    warn!(pid, error = %e, "failed to resolve event pid to cgroup");
                    return None;
                }
            };

            registry.lookup(cgroup_id).await
        }

        /// Locate and read the BPF ELF binary.
        fn load_bpf_elf() -> anyhow::Result<Vec<u8>> {
            // Check environment variable override first.
            if let Ok(path) = std::env::var(BPF_ELF_ENV) {
                info!(path, "loading BPF ELF from environment variable");
                return std::fs::read(&path).map_err(|e| {
                    anyhow::anyhow!("failed to read BPF ELF from {BPF_ELF_ENV}={path}: {e}")
                });
            }

            // Check aya-build output (compiled automatically by build.rs).
            if let Some(out_dir) = BPF_ELF_AYA_BUILD {
                let path = format!("{out_dir}/agentcontainer-ebpf-progs");
                if std::path::Path::new(&path).exists() {
                    info!(path, "loading BPF ELF from aya-build output");
                    return std::fs::read(&path)
                        .map_err(|e| anyhow::anyhow!("failed to read BPF ELF from {path}: {e}"));
                }
            }

            // Try well-known paths.
            for path in BPF_ELF_PATHS {
                if std::path::Path::new(path).exists() {
                    info!(path, "loading BPF ELF from well-known path");
                    return std::fs::read(path)
                        .map_err(|e| anyhow::anyhow!("failed to read BPF ELF from {path}: {e}"));
                }
            }

            anyhow::bail!(
                "BPF ELF not found. Run `cargo build` (aya-build compiles it automatically) \
                 or set {BPF_ELF_ENV} to the path of the compiled agentcontainer-ebpf binary. \
                 Searched paths: {:?}",
                BPF_ELF_PATHS,
            )
        }

        /// Resolve the kernel struct field byte-offsets the LSM hooks need from
        /// the running kernel's BTF. Portable across kernel versions — the Rust
        /// eBPF toolchain emits no CO-RE relocations, so the eBPF side reads
        /// `base + offset` using these instead of hardcoded `#[repr(C)]` mirrors.
        fn resolve_kernel_offsets() -> anyhow::Result<KernelOffsets> {
            use btf_rs::Type;
            let btf = btf_rs::Btf::from_file("/sys/kernel/btf/vmlinux").map_err(|e| {
                anyhow::anyhow!("loading kernel BTF (/sys/kernel/btf/vmlinux): {e}")
            })?;
            let byte_off = |strct: &str, field: &str| -> anyhow::Result<u32> {
                let types = btf
                    .resolve_types_by_name(strct)
                    .map_err(|e| anyhow::anyhow!("BTF lookup for struct {strct}: {e}"))?;
                for t in types {
                    let s = match t {
                        Type::Struct(s) | Type::Union(s) => s,
                        _ => continue,
                    };
                    for m in &s.members {
                        let name = btf
                            .resolve_name(m)
                            .map_err(|e| anyhow::anyhow!("BTF member name in {strct}: {e}"))?;
                        if name == field {
                            if m.bitfield_size().unwrap_or(0) != 0 {
                                anyhow::bail!("{strct}.{field} is a bitfield (unsupported)");
                            }
                            return Ok(m.bit_offset() / 8);
                        }
                    }
                }
                anyhow::bail!("{strct}.{field} not found in kernel BTF")
            };
            Ok(KernelOffsets {
                binprm_file: byte_off("linux_binprm", "file")?,
                file_f_inode: byte_off("file", "f_inode")?,
                file_f_path: byte_off("file", "f_path")?,
                file_f_flags: byte_off("file", "f_flags")?,
                path_dentry: byte_off("path", "dentry")?,
                dentry_d_name: byte_off("dentry", "d_name")?,
                qstr_name: byte_off("qstr", "name")?,
                inode_i_ino: byte_off("inode", "i_ino")?,
                inode_i_sb: byte_off("inode", "i_sb")?,
                sb_s_dev: byte_off("super_block", "s_dev")?,
                sb_s_magic: byte_off("super_block", "s_magic")?,
            })
        }

        /// Populate the single-entry KERNEL_OFFSETS array map from BTF, before
        /// any program is attached. A failure here is fatal: without correct
        /// offsets the LSM hooks cannot verify executable/file identity.
        fn populate_kernel_offsets(bpf: &mut Ebpf) -> anyhow::Result<()> {
            let offsets = Self::resolve_kernel_offsets()?;
            let map = bpf
                .map_mut("KERNEL_OFFSETS")
                .ok_or_else(|| anyhow::anyhow!("BPF map KERNEL_OFFSETS not found"))?;
            let mut arr: aya::maps::Array<_, KernelOffsets> = aya::maps::Array::try_from(map)?;
            arr.set(0, offsets, 0)?;
            info!(?offsets, "resolved kernel struct offsets from BTF");
            Ok(())
        }

        /// Resolve a cgroup filesystem path to a cgroup ID (inode number).
        fn resolve_cgroup_id(cgroup_path: &str) -> anyhow::Result<u64> {
            let meta = std::fs::metadata(cgroup_path)
                .map_err(|e| anyhow::anyhow!("failed to stat cgroup path {cgroup_path}: {e}"))?;
            Ok(meta.ino())
        }

        /// Resolve a filesystem path to an (inode, dev_major, dev_minor) triple.
        fn resolve_inode(path: &str) -> anyhow::Result<(u64, u32, u32)> {
            let meta = std::fs::metadata(path)
                .map_err(|e| anyhow::anyhow!("failed to stat {path}: {e}"))?;
            let dev = meta.dev();
            // Match Linux's userspace dev_t major/minor decoding.
            let dev_major = (((dev >> 8) & 0xfff) | ((dev >> 32) & !0xfff)) as u32;
            let dev_minor = ((dev & 0xff) | ((dev >> 12) & !0xff)) as u32;
            Ok((meta.ino(), dev_major, dev_minor))
        }
    }

    #[async_trait]
    impl PolicyManager for BpfPolicyManager {
        async fn register(
            &self,
            container_id: &str,
            cgroup_path: &str,
            init_pid: u32,
        ) -> anyhow::Result<ContainerHandle> {
            let cgroup_id = Self::resolve_cgroup_id(cgroup_path)?;
            info!(
                container_id,
                cgroup_id, cgroup_path, init_pid, "registering cgroup for BPF enforcement"
            );

            // Insert into ENFORCED_CGROUPS BPF map.
            {
                let mut bpf = self.programs.lock().unwrap();
                let mut map: AyaHashMap<_, u64, u8> = AyaHashMap::try_from(
                    bpf.map_mut("ENFORCED_CGROUPS")
                        .ok_or_else(|| anyhow::anyhow!("BPF map ENFORCED_CGROUPS not found"))?,
                )?;
                map.insert(cgroup_id, CGROUP_FLAG_ENFORCED, 0)?;

                // Seed process-tree sticky map so forks inherit the subject even
                // when they land in sibling/non-ancestor cgroups (cron, systemd).
                if init_pid != 0 {
                    let mut sticky: AyaHashMap<_, u32, u64> = AyaHashMap::try_from(
                        bpf.map_mut("PROC_ENFORCED")
                            .ok_or_else(|| anyhow::anyhow!("BPF map PROC_ENFORCED not found"))?,
                    )?;
                    sticky.insert(init_pid, cgroup_id, 0)?;
                    info!(
                        init_pid,
                        cgroup_id, "seeded PROC_ENFORCED for container init"
                    );
                }
            }

            // Track in registry for event correlation.
            self.registry
                .register_container(cgroup_id, container_id.to_string())
                .await;

            self.container_cgroups
                .write()
                .unwrap()
                .insert(container_id.to_string(), cgroup_id);

            Ok(ContainerHandle {
                container_id: container_id.to_string(),
                cgroup_id,
            })
        }

        async fn unregister(&self, container_id: &str) -> anyhow::Result<()> {
            let cgroup_id = self.container_cgroups.write().unwrap().remove(container_id);

            if let Some(cgroup_id) = cgroup_id {
                info!(
                    container_id,
                    cgroup_id, "unregistering cgroup from BPF enforcement"
                );

                {
                    let mut bpf = self.programs.lock().unwrap();

                    // Remove from ENFORCED_CGROUPS BPF map.
                    if let Some(map) = bpf.map_mut("ENFORCED_CGROUPS") {
                        if let Ok(mut map) = AyaHashMap::<_, u64, u8>::try_from(map) {
                            if let Err(e) = map.remove(&cgroup_id) {
                                warn!(cgroup_id, error = %e, "failed to remove cgroup from ENFORCED_CGROUPS");
                            }
                        }
                    }

                    // Clean up per-cgroup stats.
                    if let Some(map) = bpf.map_mut("CGROUP_STATS") {
                        if let Ok(mut map) = PerCpuHashMap::<_, u64, CgroupStats>::try_from(map) {
                            if let Err(e) = map.remove(&cgroup_id) {
                                warn!(cgroup_id, error = %e, "failed to remove cgroup from CGROUP_STATS");
                            }
                        }
                    }

                    // Policy maps are scoped by cgroup where possible; exact
                    // key cleanup is handled by the follow-up policy index.

                    // Clean up SECRET_ACLS entries for this cgroup.
                    // SecretAclKey includes cgroup_id, but we'd need to iterate all keys.
                    // For now, log that cleanup is best-effort.
                    warn!(
                        cgroup_id,
                        "per-cgroup cleanup for scoped policy maps/SECRET_ACLS is best-effort; \
                         stale entries expire naturally or on next policy apply"
                    );
                } // MutexGuard dropped before await

                self.registry.unregister_container(cgroup_id).await;
            } else {
                warn!(container_id, "unregister called for unknown container");
            }

            Ok(())
        }

        async fn apply_network(
            &self,
            container_id: &str,
            policy: &NetworkPolicy,
        ) -> anyhow::Result<()> {
            let cgroup_id = self.lookup_cgroup(container_id)?;
            info!(container_id, cgroup_id, hosts = ?policy.allowed_hosts, "applying network policy to BPF maps");

            // Resolve allowed_hosts to IPs and insert into ALLOWED_V4 LPM trie.
            for host in &policy.allowed_hosts {
                match tokio::net::lookup_host(format!("{host}:0")).await {
                    Ok(addrs) => {
                        let mut bpf = self.programs.lock().unwrap();
                        for addr in addrs {
                            if let std::net::IpAddr::V4(ip) = addr.ip() {
                                let key = LpmKey::new(
                                    IPV4_PREFIX_BITS,
                                    ScopedLpmKeyV4 {
                                        cgroup_id,
                                        addr: u32::from(ip).to_be(),
                                        _pad: 0,
                                    },
                                );
                                let map_data = bpf.map_mut("ALLOWED_V4").ok_or_else(|| {
                                    anyhow::anyhow!("BPF map ALLOWED_V4 not found")
                                })?;
                                let mut map: LpmTrie<_, ScopedLpmKeyV4, u8> =
                                    LpmTrie::try_from(map_data)?;
                                map.insert(&key, 1, 0)?;
                                info!(host, ip = %ip, "added IP to ALLOWED_V4");
                            }
                        }
                    }
                    Err(e) => {
                        warn!(host, error = %e, "DNS resolution failed for allowed host, skipping");
                    }
                }
            }

            // Insert egress rules into ALLOWED_PORTS map.
            for rule in &policy.egress_rules {
                match tokio::net::lookup_host(format!("{}:0", rule.host)).await {
                    Ok(addrs) => {
                        let proto = match rule.protocol.to_lowercase().as_str() {
                            "tcp" => 6u8,
                            "udp" => 17u8,
                            _ => {
                                warn!(protocol = %rule.protocol, "unknown protocol in egress rule, skipping");
                                continue;
                            }
                        };
                        let mut bpf = self.programs.lock().unwrap();
                        for addr in addrs {
                            if let std::net::IpAddr::V4(ip) = addr.ip() {
                                let key = ScopedPortKeyV4 {
                                    cgroup_id,
                                    ip: u32::from(ip).to_be(),
                                    port: rule.port,
                                    protocol: proto,
                                    _pad: 0,
                                };
                                let map_data = bpf.map_mut("ALLOWED_PORTS").ok_or_else(|| {
                                    anyhow::anyhow!("BPF map ALLOWED_PORTS not found")
                                })?;
                                let mut map: AyaHashMap<_, ScopedPortKeyV4, u8> =
                                    AyaHashMap::try_from(map_data)?;
                                map.insert(key, 1, 0)?;
                                info!(
                                    host = %rule.host,
                                    ip = %ip,
                                    port = rule.port,
                                    protocol = %rule.protocol,
                                    "added port rule to ALLOWED_PORTS"
                                );
                            }
                        }
                    }
                    Err(e) => {
                        warn!(
                            host = %rule.host,
                            error = %e,
                            "DNS resolution failed for egress rule host, skipping"
                        );
                    }
                }
            }

            Ok(())
        }

        async fn apply_filesystem(
            &self,
            container_id: &str,
            policy: &FilesystemPolicy,
        ) -> anyhow::Result<()> {
            let cgroup_id = self.lookup_cgroup(container_id)?;
            info!(
                container_id,
                cgroup_id, "applying filesystem policy to BPF maps"
            );

            let mut bpf = self.programs.lock().unwrap();

            // Insert read-only paths.
            for path in &policy.read_paths {
                match Self::resolve_inode(path) {
                    Ok((inode, dev_major, dev_minor)) => {
                        let key = ScopedFsInodeKey {
                            inode,
                            cgroup_id,
                            dev_major,
                            dev_minor,
                        };
                        let map_data = bpf
                            .map_mut("ALLOWED_INODES")
                            .ok_or_else(|| anyhow::anyhow!("BPF map ALLOWED_INODES not found"))?;
                        let mut map: AyaHashMap<_, ScopedFsInodeKey, u8> =
                            AyaHashMap::try_from(map_data)?;
                        map.insert(key, FS_PERM_READ, 0)?;
                        info!(path, inode, "added read-only inode to ALLOWED_INODES");
                    }
                    Err(e) => {
                        warn!(path, error = %e, "failed to resolve read path inode, skipping");
                    }
                }
            }

            // Insert read+write paths.
            for path in &policy.write_paths {
                match Self::resolve_inode(path) {
                    Ok((inode, dev_major, dev_minor)) => {
                        let key = ScopedFsInodeKey {
                            inode,
                            cgroup_id,
                            dev_major,
                            dev_minor,
                        };
                        let map_data = bpf
                            .map_mut("ALLOWED_INODES")
                            .ok_or_else(|| anyhow::anyhow!("BPF map ALLOWED_INODES not found"))?;
                        let mut map: AyaHashMap<_, ScopedFsInodeKey, u8> =
                            AyaHashMap::try_from(map_data)?;
                        map.insert(key, FS_PERM_READ | FS_PERM_WRITE, 0)?;
                        info!(path, inode, "added read-write inode to ALLOWED_INODES");
                    }
                    Err(e) => {
                        warn!(path, error = %e, "failed to resolve write path inode, skipping");
                    }
                }
            }

            // Insert denied paths. Deny entries take priority in the BPF hook.
            for path in &policy.deny_paths {
                match Self::resolve_inode(path) {
                    Ok((inode, dev_major, dev_minor)) => {
                        let key = ScopedFsInodeKey {
                            inode,
                            cgroup_id,
                            dev_major,
                            dev_minor,
                        };
                        let map_data = bpf
                            .map_mut("DENIED_INODES")
                            .ok_or_else(|| anyhow::anyhow!("BPF map DENIED_INODES not found"))?;
                        let mut map: AyaHashMap<_, ScopedFsInodeKey, u8> =
                            AyaHashMap::try_from(map_data)?;
                        map.insert(key, 1, 0)?;
                        info!(path, inode, "added denied inode to DENIED_INODES");
                    }
                    Err(e) => {
                        warn!(path, error = %e, "failed to resolve deny path inode, skipping");
                    }
                }
            }

            Ok(())
        }

        async fn apply_process(
            &self,
            container_id: &str,
            policy: &ProcessPolicy,
        ) -> anyhow::Result<()> {
            let cgroup_id = self.lookup_cgroup(container_id)?;
            info!(container_id, cgroup_id, binaries = ?policy.allowed_binaries, "applying process policy to BPF maps");

            let mut bpf = self.programs.lock().unwrap();

            for binary in &policy.allowed_binaries {
                match Self::resolve_inode(binary) {
                    Ok((inode, dev_major, dev_minor)) => {
                        let key = ScopedFsInodeKey {
                            inode,
                            cgroup_id,
                            dev_major,
                            dev_minor,
                        };
                        let map_data = bpf
                            .map_mut("ALLOWED_EXECS")
                            .ok_or_else(|| anyhow::anyhow!("BPF map ALLOWED_EXECS not found"))?;
                        let mut map: AyaHashMap<_, ScopedFsInodeKey, u8> =
                            AyaHashMap::try_from(map_data)?;
                        map.insert(key, 1, 0)?;
                        info!(binary, inode, "added binary inode to ALLOWED_EXECS");
                    }
                    Err(e) => {
                        warn!(binary, error = %e, "failed to resolve binary inode, skipping");
                    }
                }
            }

            // Opt-in exec enforcement: set EXEC_ENFORCED only when allowlist non-empty.
            {
                let map_data = bpf
                    .map_mut("ENFORCED_CGROUPS")
                    .ok_or_else(|| anyhow::anyhow!("BPF map ENFORCED_CGROUPS not found"))?;
                let mut emap: AyaHashMap<_, u64, u8> = AyaHashMap::try_from(map_data)?;
                let cur = emap.get(&cgroup_id, 0).unwrap_or(CGROUP_FLAG_ENFORCED);
                let new = if !policy.allowed_binaries.is_empty() {
                    cur | CGROUP_FLAG_EXEC_ENFORCED
                } else {
                    cur & !CGROUP_FLAG_EXEC_ENFORCED
                };
                emap.insert(cgroup_id, new, 0)?;
            }

            Ok(())
        }

        async fn apply_credential(
            &self,
            container_id: &str,
            policy: &CredentialPolicy,
        ) -> anyhow::Result<()> {
            let cgroup_id = self.lookup_cgroup(container_id)?;
            info!(
                container_id,
                cgroup_id,
                acls = policy.secret_acls.len(),
                "applying credential policy to BPF maps"
            );

            let mut bpf = self.programs.lock().unwrap();

            for acl in &policy.secret_acls {
                match Self::resolve_inode(&acl.path) {
                    Ok((inode, dev_major, dev_minor)) => {
                        let key = SecretAclKey {
                            inode,
                            dev_major,
                            dev_minor,
                            cgroup_id,
                        };

                        let expires_at_ns = if acl.ttl_seconds > 0 {
                            // Use CLOCK_MONOTONIC to match BPF ktime_get_ns().
                            let mut ts = libc::timespec {
                                tv_sec: 0,
                                tv_nsec: 0,
                            };
                            unsafe {
                                libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts);
                            }
                            let now_ns = ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64;
                            now_ns + acl.ttl_seconds * 1_000_000_000
                        } else {
                            0 // No expiry.
                        };

                        let value = SecretAclValue {
                            expires_at_ns,
                            allowed_ops: FS_PERM_READ,
                            _pad: [0; 7],
                        };

                        let map_data = bpf
                            .map_mut("SECRET_ACLS")
                            .ok_or_else(|| anyhow::anyhow!("BPF map SECRET_ACLS not found"))?;
                        let mut map: AyaHashMap<_, SecretAclKey, SecretAclValue> =
                            AyaHashMap::try_from(map_data)?;
                        map.insert(key, value, 0)?;
                        info!(
                            path = %acl.path,
                            inode,
                            ttl = acl.ttl_seconds,
                            "added secret ACL to SECRET_ACLS"
                        );
                    }
                    Err(e) => {
                        warn!(
                            path = %acl.path,
                            error = %e,
                            "failed to resolve secret path inode, skipping"
                        );
                    }
                }
            }

            Ok(())
        }

        async fn apply_deny_set(
            &self,
            container_id: &str,
            policy: &DenySetPolicy,
        ) -> anyhow::Result<()> {
            let _cgroup_id = self.lookup_cgroup(container_id)?;
            info!(
                container_id,
                entries = policy.entries.len(),
                transitions = policy.transitions.len(),
                init_pid = policy.init_pid,
                init_deny_set_id = policy.init_deny_set_id,
                "applying deny-set policy to BPF maps"
            );

            let mut bpf = self.programs.lock().unwrap();

            // Insert allowed entries into DENY_SET_POLICY map.
            {
                let map_data = bpf
                    .map_mut("DENY_SET_POLICY")
                    .ok_or_else(|| anyhow::anyhow!("BPF map DENY_SET_POLICY not found"))?;
                let mut map: AyaHashMap<_, DenySetKey, u8> = AyaHashMap::try_from(map_data)?;
                for entry in &policy.entries {
                    let key = DenySetKey {
                        deny_set_id: entry.deny_set_id,
                        _pad: 0,
                        inode: entry.inode,
                        dev_major: entry.dev_major,
                        dev_minor: entry.dev_minor,
                    };
                    map.insert(key, 1u8, 0)?;
                    info!(
                        deny_set_id = entry.deny_set_id,
                        inode = entry.inode,
                        "added entry to DENY_SET_POLICY"
                    );
                }
            }

            // Insert transitions into DENY_SET_TRANSITIONS map.
            {
                let map_data = bpf
                    .map_mut("DENY_SET_TRANSITIONS")
                    .ok_or_else(|| anyhow::anyhow!("BPF map DENY_SET_TRANSITIONS not found"))?;
                let mut map: AyaHashMap<_, DenySetKey, u32> = AyaHashMap::try_from(map_data)?;
                for t in &policy.transitions {
                    let key = DenySetKey {
                        deny_set_id: t.parent_deny_set_id,
                        _pad: 0,
                        inode: t.child_inode,
                        dev_major: t.child_dev_major,
                        dev_minor: t.child_dev_minor,
                    };
                    map.insert(key, t.child_deny_set_id, 0)?;
                    info!(
                        parent_deny_set_id = t.parent_deny_set_id,
                        child_deny_set_id = t.child_deny_set_id,
                        "added transition to DENY_SET_TRANSITIONS"
                    );
                }
            }

            // Insert init PID -> deny_set_id into PROC_DENY_SETS map.
            {
                let map_data = bpf
                    .map_mut("PROC_DENY_SETS")
                    .ok_or_else(|| anyhow::anyhow!("BPF map PROC_DENY_SETS not found"))?;
                let mut map: AyaHashMap<_, u32, u32> = AyaHashMap::try_from(map_data)?;
                map.insert(policy.init_pid, policy.init_deny_set_id, 0)?;
                info!(
                    init_pid = policy.init_pid,
                    init_deny_set_id = policy.init_deny_set_id,
                    "added init PID to PROC_DENY_SETS"
                );
            }

            Ok(())
        }

        async fn update_deny_set(
            &self,
            container_id: &str,
            entry: &ResolvedDenySetEntry,
        ) -> anyhow::Result<()> {
            let _cgroup_id = self.lookup_cgroup(container_id)?;
            info!(
                container_id,
                deny_set_id = entry.deny_set_id,
                inode = entry.inode,
                "updating single deny-set entry in BPF map"
            );

            let mut bpf = self.programs.lock().unwrap();
            let map_data = bpf
                .map_mut("DENY_SET_POLICY")
                .ok_or_else(|| anyhow::anyhow!("BPF map DENY_SET_POLICY not found"))?;
            let mut map: AyaHashMap<_, DenySetKey, u8> = AyaHashMap::try_from(map_data)?;
            let key = DenySetKey {
                deny_set_id: entry.deny_set_id,
                _pad: 0,
                inode: entry.inode,
                dev_major: entry.dev_major,
                dev_minor: entry.dev_minor,
            };
            map.insert(key, 1u8, 0)?;

            Ok(())
        }

        async fn apply_bind(&self, container_id: &str, policy: &BindPolicy) -> anyhow::Result<()> {
            let cgroup_id = self.lookup_cgroup(container_id)?;
            info!(
                container_id,
                cgroup_id,
                rules = policy.rules.len(),
                "applying bind policy to BPF maps"
            );

            let mut bpf = self.programs.lock().unwrap();
            let map_data = bpf
                .map_mut("ALLOWED_BINDS")
                .ok_or_else(|| anyhow::anyhow!("BPF map ALLOWED_BINDS not found"))?;
            let mut map: AyaHashMap<_, ScopedBindKey, u8> = AyaHashMap::try_from(map_data)?;

            for rule in &policy.rules {
                let key = ScopedBindKey {
                    cgroup_id,
                    port: rule.port,
                    protocol: rule.protocol,
                    _pad: 0,
                };
                map.insert(key, 1u8, 0)?;
                info!(
                    port = rule.port,
                    protocol = rule.protocol,
                    "added bind rule to ALLOWED_BINDS"
                );
            }

            Ok(())
        }

        async fn configure_reverse_shell(
            &self,
            container_id: &str,
            config: &ReverseShellConfig,
        ) -> anyhow::Result<()> {
            let _cgroup_id = self.lookup_cgroup(container_id)?;
            info!(
                container_id,
                mode = config.mode,
                "configuring reverse shell detection in BPF"
            );

            let mut bpf = self.programs.lock().unwrap();
            let map_data = bpf
                .map_mut("REVERSE_SHELL_MODE")
                .ok_or_else(|| anyhow::anyhow!("BPF map REVERSE_SHELL_MODE not found"))?;
            let mut map: aya::maps::Array<_, u8> = aya::maps::Array::try_from(map_data)?;
            map.set(0, config.mode, 0)?;

            Ok(())
        }

        async fn get_stats(&self, container_id: &str) -> anyhow::Result<EnforcementStats> {
            let cgroup_id = self.lookup_cgroup(container_id)?;

            let bpf = self.programs.lock().unwrap();
            let map_data = bpf
                .map("CGROUP_STATS")
                .ok_or_else(|| anyhow::anyhow!("BPF map CGROUP_STATS not found"))?;
            let map: PerCpuHashMap<_, u64, CgroupStats> = PerCpuHashMap::try_from(map_data)?;

            match map.get(&cgroup_id, 0) {
                Ok(per_cpu_values) => {
                    // Sum counters across all CPUs.
                    let mut totals = EnforcementStats::default();
                    for cpu_stats in per_cpu_values.iter() {
                        totals.network_allowed += cpu_stats.network_allowed;
                        totals.network_blocked += cpu_stats.network_blocked;
                        totals.filesystem_allowed += cpu_stats.filesystem_allowed;
                        totals.filesystem_blocked += cpu_stats.filesystem_blocked;
                        totals.process_allowed += cpu_stats.process_allowed;
                        totals.process_blocked += cpu_stats.process_blocked;
                        totals.credential_allowed += cpu_stats.credential_allowed;
                        totals.credential_blocked += cpu_stats.credential_blocked;
                    }
                    Ok(totals)
                }
                Err(aya::maps::MapError::KeyNotFound) => {
                    // No stats yet for this cgroup (no enforcement decisions made).
                    Ok(EnforcementStats::default())
                }
                Err(e) => Err(anyhow::anyhow!(
                    "failed to read CGROUP_STATS for cgroup {cgroup_id}: {e}"
                )),
            }
        }

        async fn subscribe_events(
            &self,
            container_id: &str,
        ) -> anyhow::Result<tokio::sync::mpsc::Receiver<EnforcementEvent>> {
            Ok(self.event_bus.subscribe(container_id))
        }
    }

    impl BpfPolicyManager {
        /// Look up the cgroup ID for a registered container.
        fn lookup_cgroup(&self, container_id: &str) -> anyhow::Result<u64> {
            self.container_cgroups
                .read()
                .unwrap()
                .get(container_id)
                .copied()
                .ok_or_else(|| {
                    anyhow::anyhow!("container {container_id} not registered — call register first")
                })
        }
    }
}

// ===========================================================================
// Non-Linux stub implementation
// ===========================================================================

#[cfg(not(target_os = "linux"))]
mod stub {
    use super::*;

    /// Stub BPF policy manager for non-Linux platforms (macOS, Windows).
    ///
    /// All operations log a warning and return `Ok(())`. This allows the
    /// enforcer binary to compile and run its gRPC server on macOS for
    /// development and testing, while actual BPF enforcement only happens
    /// on Linux.
    pub struct BpfPolicyManager {
        registry: ContainerRegistry,
        event_bus: EventBus,
        container_cgroups: RwLock<HashMap<String, u64>>,
        next_fake_id: RwLock<u64>,
    }

    impl BpfPolicyManager {
        /// Create a stub BPF policy manager (no-op on non-Linux).
        pub fn new() -> anyhow::Result<Self> {
            warn!(
                "BPF enforcement unavailable on this platform — all policy operations are no-ops"
            );
            Ok(Self {
                registry: ContainerRegistry::new(),
                event_bus: EventBus::new(),
                container_cgroups: RwLock::new(HashMap::new()),
                next_fake_id: RwLock::new(1),
            })
        }
    }

    #[async_trait]
    impl PolicyManager for BpfPolicyManager {
        async fn register(
            &self,
            container_id: &str,
            cgroup_path: &str,
            init_pid: u32,
        ) -> anyhow::Result<ContainerHandle> {
            let cgroup_id = {
                let mut id = self.next_fake_id.write().unwrap();
                let current = *id;
                *id += 1;
                current
            };
            warn!(
                container_id,
                cgroup_path,
                cgroup_id,
                init_pid,
                "stub: register is a no-op (no BPF on this platform)"
            );

            self.registry
                .register_container(cgroup_id, container_id.to_string())
                .await;
            self.container_cgroups
                .write()
                .unwrap()
                .insert(container_id.to_string(), cgroup_id);

            Ok(ContainerHandle {
                container_id: container_id.to_string(),
                cgroup_id,
            })
        }

        async fn unregister(&self, container_id: &str) -> anyhow::Result<()> {
            warn!(container_id, "stub: unregister is a no-op");
            let cgroup_id = self.container_cgroups.write().unwrap().remove(container_id);
            if let Some(cgroup_id) = cgroup_id {
                self.registry.unregister_container(cgroup_id).await;
            }
            Ok(())
        }

        async fn apply_network(
            &self,
            container_id: &str,
            policy: &NetworkPolicy,
        ) -> anyhow::Result<()> {
            warn!(
                container_id,
                hosts = ?policy.allowed_hosts,
                rules = policy.egress_rules.len(),
                "stub: apply_network is a no-op"
            );
            Ok(())
        }

        async fn apply_filesystem(
            &self,
            container_id: &str,
            policy: &FilesystemPolicy,
        ) -> anyhow::Result<()> {
            warn!(
                container_id,
                read = policy.read_paths.len(),
                write = policy.write_paths.len(),
                deny = policy.deny_paths.len(),
                "stub: apply_filesystem is a no-op"
            );
            Ok(())
        }

        async fn apply_process(
            &self,
            container_id: &str,
            policy: &ProcessPolicy,
        ) -> anyhow::Result<()> {
            warn!(
                container_id,
                binaries = policy.allowed_binaries.len(),
                "stub: apply_process is a no-op"
            );
            Ok(())
        }

        async fn apply_credential(
            &self,
            container_id: &str,
            policy: &CredentialPolicy,
        ) -> anyhow::Result<()> {
            warn!(
                container_id,
                acls = policy.secret_acls.len(),
                "stub: apply_credential is a no-op"
            );
            Ok(())
        }

        async fn apply_deny_set(
            &self,
            container_id: &str,
            policy: &DenySetPolicy,
        ) -> anyhow::Result<()> {
            warn!(
                container_id,
                entries = policy.entries.len(),
                transitions = policy.transitions.len(),
                "stub: apply_deny_set is a no-op"
            );
            Ok(())
        }

        async fn update_deny_set(
            &self,
            container_id: &str,
            entry: &ResolvedDenySetEntry,
        ) -> anyhow::Result<()> {
            warn!(
                container_id,
                deny_set_id = entry.deny_set_id,
                "stub: update_deny_set is a no-op"
            );
            Ok(())
        }

        async fn apply_bind(&self, container_id: &str, policy: &BindPolicy) -> anyhow::Result<()> {
            warn!(
                container_id,
                rules = policy.rules.len(),
                "stub: apply_bind is a no-op"
            );
            Ok(())
        }

        async fn configure_reverse_shell(
            &self,
            container_id: &str,
            config: &ReverseShellConfig,
        ) -> anyhow::Result<()> {
            warn!(
                container_id,
                mode = config.mode,
                "stub: configure_reverse_shell is a no-op"
            );
            Ok(())
        }

        async fn get_stats(&self, _container_id: &str) -> anyhow::Result<EnforcementStats> {
            Ok(EnforcementStats::default())
        }

        async fn subscribe_events(
            &self,
            container_id: &str,
        ) -> anyhow::Result<tokio::sync::mpsc::Receiver<EnforcementEvent>> {
            Ok(self.event_bus.subscribe(container_id))
        }
    }
}

// ===========================================================================
// Re-export the platform-appropriate implementation
// ===========================================================================

#[cfg(target_os = "linux")]
pub use linux::BpfPolicyManager;

#[cfg(not(target_os = "linux"))]
pub use stub::BpfPolicyManager;

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use crate::events::parse_network_event;
    use crate::policy::PolicyManager;
    #[cfg(unix)]
    use crate::policy::{EventDomain, EventVerdict};
    #[cfg(unix)]
    use agentcontainer_common::events::{EventType, NetworkEvent, Verdict, COMM_MAX};
    #[cfg(unix)]
    use std::os::unix::fs::MetadataExt;
    #[cfg(unix)]
    use tempfile::tempdir;

    #[cfg(not(target_os = "linux"))]
    #[tokio::test]
    async fn test_stub_register_unregister() {
        let mgr = BpfPolicyManager::new().unwrap();

        let handle = mgr
            .register("ctr-1", "/sys/fs/cgroup/test", 0)
            .await
            .unwrap();
        assert_eq!(handle.container_id, "ctr-1");
        assert!(handle.cgroup_id > 0);

        // Second register gets a different cgroup ID.
        let handle2 = mgr
            .register("ctr-2", "/sys/fs/cgroup/test2", 0)
            .await
            .unwrap();
        assert_ne!(handle.cgroup_id, handle2.cgroup_id);

        // Unregister should succeed.
        mgr.unregister("ctr-1").await.unwrap();

        // Double unregister should also succeed (idempotent).
        mgr.unregister("ctr-1").await.unwrap();
    }

    #[cfg(not(target_os = "linux"))]
    #[tokio::test]
    async fn test_stub_apply_policies() {
        let mgr = BpfPolicyManager::new().unwrap();
        mgr.register("ctr-1", "/sys/fs/cgroup/test", 0)
            .await
            .unwrap();

        // All apply methods should succeed as no-ops.
        mgr.apply_network(
            "ctr-1",
            &NetworkPolicy {
                allowed_hosts: vec!["example.com".into()],
                egress_rules: vec![],
                dns_servers: vec![],
            },
        )
        .await
        .unwrap();

        mgr.apply_filesystem(
            "ctr-1",
            &FilesystemPolicy {
                read_paths: vec!["/etc".into()],
                write_paths: vec!["/tmp".into()],
                deny_paths: vec![],
            },
        )
        .await
        .unwrap();

        mgr.apply_process(
            "ctr-1",
            &ProcessPolicy {
                allowed_binaries: vec!["/bin/sh".into()],
            },
        )
        .await
        .unwrap();

        mgr.apply_credential(
            "ctr-1",
            &CredentialPolicy {
                secret_acls: vec![],
            },
        )
        .await
        .unwrap();
    }

    #[cfg(not(target_os = "linux"))]
    #[tokio::test]
    async fn test_stub_get_stats_returns_defaults() {
        let mgr = BpfPolicyManager::new().unwrap();
        let stats = mgr.get_stats("ctr-1").await.unwrap();
        assert_eq!(stats.network_allowed, 0);
        assert_eq!(stats.network_blocked, 0);
    }

    #[cfg(not(target_os = "linux"))]
    #[tokio::test]
    async fn test_stub_subscribe_events() {
        let mgr = BpfPolicyManager::new().unwrap();
        let _rx = mgr.subscribe_events("ctr-1").await.unwrap();
        // Receiver is valid; no events will come from stub.
    }

    #[cfg(unix)]
    fn sample_network_event(pid: u32) -> NetworkEvent {
        let mut comm = [0u8; COMM_MAX];
        comm[..4].copy_from_slice(b"curl");

        NetworkEvent {
            timestamp_ns: 1_000,
            pid,
            uid: 1000,
            event_type: EventType::NetworkConnect as u32,
            verdict: Verdict::Block as u32,
            dst_ip4: 0x0a000001,
            dst_ip6: [0; 4],
            dst_port: 443,
            protocol: 6,
            ip_version: 4,
            comm,
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_pid_resolved_event_reaches_filtered_subscriber() {
        let tmp = tempdir().unwrap();
        let proc_root = tmp.path().join("proc");
        let cgroup_root = tmp.path().join("sys/fs/cgroup");
        let pid = 4242u32;

        let proc_pid_dir = proc_root.join(pid.to_string());
        std::fs::create_dir_all(&proc_pid_dir).unwrap();

        let cgroup_dir = cgroup_root.join("agentcontainer/test.scope");
        std::fs::create_dir_all(&cgroup_dir).unwrap();
        std::fs::write(
            proc_pid_dir.join("cgroup"),
            "0::/agentcontainer/test.scope\n",
        )
        .unwrap();

        let registry = ContainerRegistry::new();
        let cgroup_id = std::fs::metadata(&cgroup_dir).unwrap().ino();
        registry.register_container(cgroup_id, "ctr-a".into()).await;

        let raw = sample_network_event(pid);
        let data = unsafe {
            std::slice::from_raw_parts(
                (&raw as *const NetworkEvent).cast::<u8>(),
                std::mem::size_of::<NetworkEvent>(),
            )
        };
        let resolved_pid = read_event_pid(data).unwrap();
        let container_id = registry
            .lookup(
                resolve_cgroup_id_for_pid_with_roots(resolved_pid, &proc_root, &cgroup_root)
                    .unwrap(),
            )
            .await
            .unwrap();

        let bus = EventBus::new();
        let mut rx = bus.subscribe("ctr-a");
        bus.publish(parse_network_event(&raw, &container_id));

        let event = tokio::time::timeout(std::time::Duration::from_secs(1), rx.recv())
            .await
            .unwrap()
            .unwrap();

        assert_eq!(event.container_id, "ctr-a");
        assert_eq!(event.domain, EventDomain::Network);
        assert_eq!(event.verdict, EventVerdict::Block);
    }

    #[cfg(unix)]
    #[test]
    fn test_parse_proc_cgroup_relative_path_prefers_unified_hierarchy() {
        let contents = "12:cpuset:/ignored\n0::/agentcontainer/test.scope\n";
        assert_eq!(
            parse_proc_cgroup_relative_path(contents),
            Some("/agentcontainer/test.scope")
        );
    }
}
