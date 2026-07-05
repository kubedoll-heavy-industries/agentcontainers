use agentcontainer_common::maps::*;
use core::mem;

#[test]
fn test_lpm_key_v4_layout() {
    assert_eq!(mem::size_of::<LpmKeyV4>(), 8);
    assert_eq!(mem::align_of::<LpmKeyV4>(), 4);
}

#[test]
fn test_lpm_key_v6_layout() {
    assert_eq!(mem::size_of::<LpmKeyV6>(), 20);
    assert_eq!(mem::align_of::<LpmKeyV6>(), 4);
}

#[test]
fn test_port_key_v4_layout() {
    assert_eq!(mem::size_of::<PortKeyV4>(), 8);
}

#[test]
fn test_fs_inode_key_layout() {
    // 24 bytes: inode(8) + dev_major(4) + dev_minor(4) + cgroup_id(8).
    // cgroup_id scopes every inode authorization to a single container.
    assert_eq!(mem::size_of::<FsInodeKey>(), 24);
}

#[test]
fn test_secret_acl_key_layout() {
    assert_eq!(mem::size_of::<SecretAclKey>(), 24);
}

#[test]
fn test_secret_acl_value_layout() {
    assert_eq!(mem::size_of::<SecretAclValue>(), 16);
}

#[test]
fn test_permission_constants() {
    assert_eq!(FS_PERM_READ, 0x01);
    assert_eq!(FS_PERM_WRITE, 0x02);
}

#[test]
fn test_verdict_constants() {
    assert_eq!(VERDICT_ALLOW, 1);
    assert_eq!(VERDICT_BLOCK, 0);
    assert_eq!(LSM_ALLOW, 0);
    assert_eq!(LSM_DENY, -13);
}
