//! A helper module which is designed to contain windows security related functions which are used
//! across the crate.

use std::mem;

use windows::Win32::{
    Foundation::{FALSE, GENERIC_ALL},
    Security::{
        ACCESS_ALLOWED_ACE, ACL, ACL_REVISION, AddAccessAllowedAceEx, AllocateAndInitializeSid,
        CONTAINER_INHERIT_ACE, GetSidLengthRequired, InitializeAcl, InitializeSecurityDescriptor,
        OBJECT_INHERIT_ACE, PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES, SECURITY_DESCRIPTOR,
        SECURITY_WORLD_SID_AUTHORITY, SetSecurityDescriptorDacl,
    },
    System::SystemServices::{SECURITY_DESCRIPTOR_REVISION, SECURITY_WORLD_RID},
};

/// Create a permissive security descriptor allowing processes at all user levels, groups, etc to access this named pipe.
/// This will ensure processes at a low privilege can communicate with the pipe
///
/// # Note
/// A number of heap allocated structures will be leaked via `Box::leak()` - this is okay and not considered a memory leak as
/// this will be called once during the creation of the named pipe and then are required for the duration of the process.
pub fn create_security_attributes() -> SECURITY_ATTRIBUTES {
    unsafe {
        //
        // Allocate the SECURITY_DESCRIPTOR on the heap and initialise
        //
        let mut sd_box = Box::new(SECURITY_DESCRIPTOR::default());

        InitializeSecurityDescriptor(
            PSECURITY_DESCRIPTOR(&mut *sd_box as *mut _ as _),
            SECURITY_DESCRIPTOR_REVISION,
        )
        .ok()
        .expect("InitializeSecurityDescriptor failed");

        //
        // build the ACL and add the Everyone ACE
        //
        let acl_size = mem::size_of::<ACL>() as u32
            + mem::size_of::<ACCESS_ALLOWED_ACE>() as u32
            + GetSidLengthRequired(1);
        let mut acl_buf = Vec::with_capacity(acl_size as usize);
        acl_buf.set_len(acl_size as usize); // reserve space

        InitializeAcl(acl_buf.as_mut_ptr() as *mut ACL, acl_size, ACL_REVISION)
            .ok()
            .expect("InitializeAcl failed");

        //
        // Allocate the SID for Everyone
        //
        let mut everyone_sid: PSID = PSID::default();
        AllocateAndInitializeSid(
            &SECURITY_WORLD_SID_AUTHORITY,
            1,
            SECURITY_WORLD_RID as u32,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            &mut everyone_sid,
        )
        .ok()
        .expect("AllocateAndInitializeSid failed");

        AddAccessAllowedAceEx(
            acl_buf.as_mut_ptr() as *mut ACL,
            ACL_REVISION,
            OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE,
            GENERIC_ALL.0,
            everyone_sid,
        )
        .ok()
        .expect("AddAccessAllowedAceEx failed");

        //
        // Attach the ACL to the descriptor
        //
        SetSecurityDescriptorDacl(
            PSECURITY_DESCRIPTOR(&mut *sd_box as *mut _ as _),
            true,
            Some(acl_buf.as_ptr() as *const ACL),
            false,
        )
        .ok()
        .expect("SetSecurityDescriptorDacl failed");

        //
        // Allocate SECURITY_ATTRIBUTES on the heap and fill it
        //
        let mut sa_box = SECURITY_ATTRIBUTES {
            nLength: mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: &mut *sd_box as *mut _ as *mut core::ffi::c_void,
            bInheritHandle: FALSE,
        };

        //
        // Leak everything so that we can ensure their lifetime is valid for the duration of the
        // entire program. The memory will be cleaned up when the process exits.
        //
        // Box::leak(sd_box);
        // Box::leak(Box::new(acl_buf));
        // Box::leak(sa_box)

        sa_box
    }
}
