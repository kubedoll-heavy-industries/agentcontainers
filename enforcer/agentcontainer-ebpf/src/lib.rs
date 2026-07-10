//! BPF programs for agentcontainers enforcement.
//!
//! This crate contains all eBPF programs that run inside the Linux kernel:
//! - Network: connect4/6, sendmsg4/6 hooks for egress enforcement
//! - Network: cgroup_skb/ingress for DNS response parsing
//! - LSM: file_open for filesystem access control
//! - LSM: bprm_check_security for process execution control
//!
//! All programs check the `enforced_cgroups` map before enforcing,
//! ensuring policy only applies to registered containers.

#![no_std]
#![no_main]
// BPF map accessor safety requirements vary across nightly versions.
// Some map methods (HashMap::get) require unsafe while others (LpmTrie::get)
// don't. Allow unused_unsafe so we can uniformly wrap all map operations.
#![allow(unused_unsafe)]

mod lsm;
mod maps;
mod network;
mod process;

// Panic handler required for no_std.
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
