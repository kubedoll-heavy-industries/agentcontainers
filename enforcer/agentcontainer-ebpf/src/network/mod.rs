//! Network enforcement BPF programs.
//!
//! - `bind`: cgroup_sock_addr bind4/6 hooks (listening socket enforcement)
//! - `connect`: cgroup_sock_addr connect4/6 hooks (egress IP/port enforcement)
//! - `sendmsg`: cgroup_sock_addr sendmsg4/6 hooks (UDP egress enforcement)
//! - `dns`: cgroup_skb/ingress hook (DNS response parsing and event emission)

pub mod bind;
pub mod connect;
pub mod dns;
pub mod sendmsg;
