//! The host credential on Windows: encrypted with DPAPI in machine scope (`CryptProtectData`
//! with `CRYPTPROTECT_LOCAL_MACHINE`) and kept in a file in the state directory whose ACL
//! allows only SYSTEM, Administrators and LocalService.
//!
//! Machine scope lets both the service (LocalService) and an administrator running `enrol`
//! decrypt the blob; DPAPI keeps it useless off this machine (a copied disk or backup), and the
//! file ACL keeps other local accounts from reading it.

use std::fs::{self, File};
use std::io::{self, Write};
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::ptr;

use agent_core::credential::{CredentialProvider, CredentialStore, Secret, parse_host_credential};
use windows::Win32::Foundation::{ERROR_SUCCESS, HLOCAL, LocalFree};
use windows::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1, SE_FILE_OBJECT,
    SetNamedSecurityInfoW,
};
use windows::Win32::Security::Cryptography::{
    CRYPT_INTEGER_BLOB, CRYPTPROTECT_LOCAL_MACHINE, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData,
    CryptUnprotectData,
};
use windows::Win32::Security::{
    ACL, DACL_SECURITY_INFORMATION, GetSecurityDescriptorDacl, PROTECTED_DACL_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR,
};
use windows::core::{BOOL, PCWSTR, w};

/// Largest blob read; a protected credential is a few hundred bytes.
const MAX_BLOB_BYTES: u64 = 16 * 1024;

/// SYSTEM, Administrators and LocalService full control; the `P` stops inheritance.
const FILE_SDDL: PCWSTR = w!("D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;LS)");

#[derive(Debug)]
pub struct DpapiCredential {
    pub path: PathBuf,
}

impl CredentialProvider for DpapiCredential {
    fn credential(&self) -> Result<Option<Secret>, String> {
        let display = self.path.display();
        let blob = match fs::read(&self.path) {
            Ok(blob) => blob,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(format!("{display}: {e}")),
        };
        if blob.len() as u64 > MAX_BLOB_BYTES {
            return Err(format!("{display} is not a credential file"));
        }
        let plain = unprotect(&blob).map_err(|e| format!("{display}: {e}"))?;
        let text = String::from_utf8(plain)
            .map_err(|_| format!("{display} does not hold a host credential"))?;
        parse_host_credential(&text)
            .map(Some)
            .map_err(|e| format!("{display} {e}"))
    }
}

impl CredentialStore for DpapiCredential {
    fn store(&self, credential: &Secret) -> Result<(), String> {
        let display = self.path.display();
        let blob = protect(credential.expose().as_bytes())?;
        let tmp = self.path.with_extension("tmp");
        match fs::remove_file(&tmp) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(format!("{}: {e}", tmp.display())),
        }
        // Create the file empty, restrict its ACL, then write through the handle opened before
        // the change: the blob never sits in a file with the directory's inherited ACL.
        let mut file = File::create_new(&tmp).map_err(|e| format!("{}: {e}", tmp.display()))?;
        restrict_acl(&tmp)?;
        file.write_all(&blob)
            .and_then(|()| file.sync_all())
            .map_err(|e| format!("{}: {e}", tmp.display()))?;
        drop(file);
        fs::rename(&tmp, &self.path).map_err(|e| format!("cannot replace {display}: {e}"))
    }

    fn location(&self) -> String {
        format!("DPAPI-protected file {}", self.path.display())
    }
}

/// Encrypt with the machine's DPAPI key.
pub fn protect(data: &[u8]) -> Result<Vec<u8>, String> {
    let input = CRYPT_INTEGER_BLOB {
        cbData: u32::try_from(data.len()).map_err(|_| "credential too large".to_owned())?,
        pbData: data.as_ptr().cast_mut(),
    };
    let mut output = CRYPT_INTEGER_BLOB::default();
    // SAFETY: `input` points at `data`, which outlives the call and which DPAPI only reads.
    // `output` is written by the call; on success its buffer is ours to free (`take_blob`).
    unsafe {
        CryptProtectData(
            &input,
            w!("Wedgetail host credential"),
            None,
            None,
            None,
            CRYPTPROTECT_LOCAL_MACHINE | CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    }
    .map_err(|e| format!("CryptProtectData: {e}"))?;
    Ok(take_blob(output, false))
}

/// Decrypt a blob from [`protect`].
pub fn unprotect(blob: &[u8]) -> Result<Vec<u8>, String> {
    let input = CRYPT_INTEGER_BLOB {
        cbData: u32::try_from(blob.len()).map_err(|_| "blob too large".to_owned())?,
        pbData: blob.as_ptr().cast_mut(),
    };
    let mut output = CRYPT_INTEGER_BLOB::default();
    // SAFETY: as in `protect`: `input` borrows `blob` for the call only, `output` receives a
    // buffer that `take_blob` frees.
    unsafe {
        CryptUnprotectData(
            &input,
            None,
            None,
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    }
    .map_err(|e| format!("CryptUnprotectData: {e}"))?;
    Ok(take_blob(output, true))
}

/// Copy a DPAPI output buffer and free it, wiping it first when it held plaintext.
fn take_blob(blob: CRYPT_INTEGER_BLOB, wipe: bool) -> Vec<u8> {
    if blob.pbData.is_null() {
        return Vec::new();
    }
    // SAFETY: after a successful CryptProtectData/CryptUnprotectData call `pbData` points at
    // `cbData` initialised bytes that the system allocated for us and nothing else uses.
    let bytes = unsafe { std::slice::from_raw_parts_mut(blob.pbData, blob.cbData as usize) };
    let copy = bytes.to_vec();
    if wipe {
        bytes.fill(0);
    }
    // SAFETY: the buffer was allocated with LocalAlloc by DPAPI, is freed exactly once here,
    // and `bytes` is not used after this point.
    unsafe { LocalFree(Some(HLOCAL(blob.pbData.cast()))) };
    copy
}

/// Replace the file's DACL with [`FILE_SDDL`] (protected, so nothing is inherited).
pub fn restrict_acl(path: &Path) -> Result<(), String> {
    let mut sd = PSECURITY_DESCRIPTOR::default();
    // SAFETY: FILE_SDDL is a static NUL-terminated wide string; `sd` receives a descriptor
    // allocated with LocalAlloc, freed below.
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            FILE_SDDL,
            SDDL_REVISION_1,
            &mut sd,
            None,
        )
    }
    .map_err(|e| format!("security descriptor: {e}"))?;
    let result = set_dacl(path, sd);
    // SAFETY: `sd` came from ConvertStringSecurityDescriptorToSecurityDescriptorW, is freed
    // once, and the DACL pointer into it is not used after `set_dacl` returned.
    unsafe { LocalFree(Some(HLOCAL(sd.0))) };
    result
}

fn set_dacl(path: &Path, sd: PSECURITY_DESCRIPTOR) -> Result<(), String> {
    let mut present = BOOL::default();
    let mut defaulted = BOOL::default();
    let mut dacl: *mut ACL = ptr::null_mut();
    // SAFETY: `sd` is a valid self-relative descriptor; the out parameters are valid locals.
    // `dacl` points into `sd`, which the caller keeps alive until we return.
    unsafe { GetSecurityDescriptorDacl(sd, &mut present, &mut dacl, &mut defaulted) }
        .map_err(|e| format!("security descriptor: {e}"))?;
    if !present.as_bool() || dacl.is_null() {
        return Err("security descriptor has no DACL".into());
    }
    let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    // SAFETY: `wide` is NUL-terminated and outlives the call; `dacl` is valid (above). Only
    // the DACL is changed; owner, group and SACL pointers are null.
    let err = unsafe {
        SetNamedSecurityInfoW(
            PCWSTR(wide.as_ptr()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(dacl.cast_const()),
            None,
        )
    };
    if err == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(format!(
            "cannot restrict the ACL of {}: Windows error {}",
            path.display(),
            err.0
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "wgh_abc123def456_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const B: &str = "wgh_abc123def456_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "wt-dpapi-{name}-{}-{}",
            std::process::id(),
            fastrand_suffix()
        ));
        fs::create_dir_all(&dir).expect("mkdir");
        dir
    }

    fn fastrand_suffix() -> u128 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos())
    }

    #[test]
    fn dpapi_round_trip() {
        let blob = protect(A.as_bytes()).expect("protect");
        assert!(!blob.windows(A.len()).any(|w| w == A.as_bytes()));
        assert_eq!(unprotect(&blob).expect("unprotect"), A.as_bytes());
        assert!(unprotect(b"not a dpapi blob").is_err());
    }

    #[test]
    fn store_round_trip_with_a_restricted_acl() {
        let dir = temp_dir("store");
        let store = DpapiCredential {
            path: dir.join("credential.dpapi"),
        };
        assert_eq!(store.credential().expect("missing"), None);
        store.store(&Secret::new(A.into())).expect("store");
        let on_disk = fs::read(&store.path).expect("read");
        assert!(!on_disk.windows(4).any(|w| w == b"wgh_"));
        assert_eq!(
            store
                .credential()
                .expect("read")
                .map(|s| s.expose().to_owned()),
            Some(A.to_owned())
        );
        store.store(&Secret::new(B.into())).expect("replace");
        assert_eq!(
            store
                .credential()
                .expect("read")
                .map(|s| s.expose().to_owned()),
            Some(B.to_owned())
        );

        // Only SYSTEM, Administrators and LocalService, none of it inherited.
        let out = std::process::Command::new("icacls")
            .arg(&store.path)
            .output()
            .expect("icacls");
        let acl = String::from_utf8_lossy(&out.stdout);
        assert!(acl.contains(r"NT AUTHORITY\SYSTEM:(F)"), "{acl}");
        assert!(acl.contains(r"BUILTIN\Administrators:(F)"), "{acl}");
        assert!(acl.contains(r"NT AUTHORITY\LOCAL SERVICE:(F)"), "{acl}");
        assert!(!acl.contains("(I)"), "{acl}");
        assert!(!acl.contains(r"BUILTIN\Users"), "{acl}");

        fs::write(&store.path, b"garbage").expect("write");
        assert!(store.credential().is_err());
        let _ = fs::remove_dir_all(&dir);
    }
}
