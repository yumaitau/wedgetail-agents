//! Where the shipper gets the host credential, and where enrolment and rotation put it.
//!
//! [`CredentialProvider`] is read before every request; [`CredentialStore`] adds an atomic
//! replace for `enrol` and rotation. [`FileCredential`] is the Linux store; the Windows (DPAPI)
//! and macOS (System keychain) stores live in the CLI crate, next to their OS bindings.

use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use crate::buffer::sync_dir;

/// Largest credential file or store entry read.
pub const MAX_STORED_BYTES: u64 = 1024;

/// A secret string (host credential or enrolment token) that never prints its value.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(String);

impl Secret {
    pub fn new(value: String) -> Self {
        Self(value)
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret([redacted])")
    }
}

impl fmt::Display for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[redacted]")
    }
}

/// Supplies the current host credential (`wgh_<12>_<43>`). Called before every request, so a
/// rotated credential is picked up without a restart.
pub trait CredentialProvider: Send + Sync + fmt::Debug {
    /// `Ok(None)` while the host is not enrolled: events keep buffering and nothing is sent.
    fn credential(&self) -> Result<Option<Secret>, String>;
}

/// A provider that can also replace the credential (enrolment and rotation). Readers see the
/// old or the new credential, never a mix or nothing.
pub trait CredentialStore: CredentialProvider {
    fn store(&self, credential: &Secret) -> Result<(), String>;

    /// Where the credential lives, for messages (never the value).
    fn location(&self) -> String;
}

/// `<prefix>` + 12 of `[a-z0-9]` + `_` + 43 of base64url: the shape of every Wedgetail agent
/// secret (`wge_` enrolment tokens, `wgh_` host credentials).
fn has_secret_shape(value: &str, prefix: &str) -> bool {
    let Some(rest) = value.strip_prefix(prefix) else {
        return false;
    };
    let Some((id, secret)) = rest.split_once('_') else {
        return false;
    };
    id.len() == 12
        && id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        && secret.len() == 43
        && secret
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// `wgh_` + 12 of `[a-z0-9]` + `_` + 43 of base64url.
pub fn is_host_credential(value: &str) -> bool {
    has_secret_shape(value, "wgh_")
}

/// `wge_` + 12 of `[a-z0-9]` + `_` + 43 of base64url.
pub fn is_enrolment_token(value: &str) -> bool {
    has_secret_shape(value, "wge_")
}

/// Parse a stored credential (surrounding whitespace allowed). The error never echoes the value.
pub fn parse_host_credential(text: &str) -> Result<Secret, String> {
    let value = text.trim();
    if is_host_credential(value) {
        Ok(Secret::new(value.to_owned()))
    } else {
        Err("does not hold a host credential".into())
    }
}

/// A fixed credential, for tests and embedding.
#[derive(Debug)]
pub struct StaticCredential(pub Option<Secret>);

impl CredentialProvider for StaticCredential {
    fn credential(&self) -> Result<Option<Secret>, String> {
        Ok(self.0.clone())
    }
}

/// The credential in a file only the agent's account can read (the Linux layout). A missing
/// file means "not enrolled". On Unix the file must be a regular file with no group or other
/// permissions, owned by root or by the owner of its directory (the service account).
#[derive(Debug)]
pub struct FileCredential {
    pub path: PathBuf,
}

impl FileCredential {
    fn dir(&self) -> &Path {
        match self.path.parent() {
            Some(p) if !p.as_os_str().is_empty() => p,
            _ => Path::new("."),
        }
    }
}

impl CredentialProvider for FileCredential {
    fn credential(&self) -> Result<Option<Secret>, String> {
        let display = self.path.display();
        match fs::symlink_metadata(&self.path) {
            Ok(meta) if !meta.file_type().is_file() => {
                return Err(format!("{display} is not a regular file"));
            }
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(format!("{display}: {e}")),
        }
        let file = File::open(&self.path).map_err(|e| format!("{display}: {e}"))?;
        let meta = file.metadata().map_err(|e| format!("{display}: {e}"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            if meta.permissions().mode() & 0o077 != 0 {
                return Err(format!(
                    "{display} must not be readable by group or others (chmod 600)"
                ));
            }
            let dir_uid = fs::metadata(self.dir())
                .map_err(|e| format!("{}: {e}", self.dir().display()))?
                .uid();
            if !owner_allowed(meta.uid(), dir_uid) {
                return Err(format!(
                    "{display} must be owned by root or by the owner of {}",
                    self.dir().display()
                ));
            }
        }
        if meta.len() > MAX_STORED_BYTES {
            return Err(format!("{display} is not a credential file"));
        }
        let mut text = String::new();
        file.take(MAX_STORED_BYTES)
            .read_to_string(&mut text)
            .map_err(|e| format!("{display}: {e}"))?;
        parse_host_credential(&text)
            .map(Some)
            .map_err(|e| format!("{display} {e}"))
    }
}

impl CredentialStore for FileCredential {
    fn store(&self, credential: &Secret) -> Result<(), String> {
        let name = self
            .path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| format!("{} is not a file path", self.path.display()))?;
        write_private(
            self.dir(),
            name,
            format!("{}\n", credential.expose()).as_bytes(),
        )
        .map_err(|e| format!("cannot write {}: {e}", self.path.display()))
    }

    fn location(&self) -> String {
        format!("file {}", self.path.display())
    }
}

/// A file owned by root or by whoever owns the state directory (the agent's service account).
pub fn owner_allowed(file_uid: u32, dir_uid: u32) -> bool {
    file_uid == 0 || file_uid == dir_uid
}

/// Write `name` in `dir` readable only by its owner: a new temporary file created with mode
/// 0600 (never wider, not even briefly), fsynced, handed to the owner of `dir` (so a credential
/// written by root during `enrol` is readable by the service account), then renamed over the
/// old file. On Windows the file inherits the state directory's ACL.
pub fn write_private(dir: &Path, name: &str, bytes: &[u8]) -> io::Result<()> {
    let tmp = dir.join(format!("{name}.tmp"));
    match fs::remove_file(&tmp) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
        let mut f = options.open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let owner = fs::metadata(dir)?;
        if fs::metadata(&tmp)?.uid() != owner.uid() {
            std::os::unix::fs::chown(&tmp, Some(owner.uid()), Some(owner.gid()))?;
        }
    }
    fs::rename(&tmp, dir.join(name))?;
    sync_dir(dir)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::buffer::tests::TempDir;

    const GOOD: &str = "wgh_abc123def456_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const OTHER: &str = "wgh_abc123def456_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";

    #[test]
    fn credential_and_token_shapes() {
        assert!(is_host_credential(GOOD));
        assert!(is_enrolment_token(
            "wge_0123456789az_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNO-_"
        ));
        for bad in [
            "",
            "wgh_",
            "wgi_abc123def456_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "wgh_ABC123def456_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "wgh_abc123def45_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "wgh_abc123def456_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "wgh_abc123def456_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            "wgh_abc123def456_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\nx",
            "wgh_abc123déf456_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            " wgh_abc123def456_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        ] {
            assert!(!is_host_credential(bad), "{bad:?}");
            assert!(!is_enrolment_token(bad), "{bad:?}");
        }
        // Each prefix only matches its own kind.
        assert!(!is_enrolment_token(GOOD));
        assert!(!is_host_credential(
            "wge_abc123def456_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        ));
    }

    #[test]
    fn secret_debug_and_display_are_redacted() {
        let secret = Secret::new(GOOD.into());
        assert_eq!(format!("{secret:?}"), "Secret([redacted])");
        assert_eq!(format!("{secret}"), "[redacted]");
        assert!(!format!("{:?}", StaticCredential(Some(secret.clone()))).contains("wgh_"));
        assert!(!format!("{:#?}", Some(secret)).contains("AAAA"));
        let err = parse_host_credential("wgh_not_quite_right").expect_err("bad");
        assert!(!err.contains("wgh_"));
    }

    #[test]
    fn file_credential_reads_and_checks_permissions() {
        let dir = TempDir::new("cred-read");
        fs::create_dir_all(&dir.0).expect("mkdir");
        let path = dir.0.join("credential");
        let provider = FileCredential { path: path.clone() };
        assert_eq!(provider.credential().expect("missing is ok"), None);
        fs::write(&path, format!("{GOOD}\n")).expect("write");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for mode in [0o644, 0o640, 0o604, 0o660] {
                fs::set_permissions(&path, fs::Permissions::from_mode(mode)).expect("chmod");
                let err = provider.credential().expect_err("too open");
                assert!(err.contains("chmod 600"), "{err}");
                assert!(!err.contains("AAAA"), "{err}");
            }
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("chmod");
        }
        assert_eq!(
            provider
                .credential()
                .expect("ok")
                .map(|s| s.expose().to_owned()),
            Some(GOOD.to_owned())
        );
        fs::write(&path, "nonsense").expect("write");
        let err = provider.credential().expect_err("not a credential");
        assert!(!err.contains("nonsense"));
        fs::write(&path, vec![b'a'; 4096]).expect("write");
        assert!(provider.credential().is_err());
    }

    #[test]
    fn file_store_creates_0600_and_replaces_atomically() {
        let dir = TempDir::new("cred-store");
        fs::create_dir_all(&dir.0).expect("mkdir");
        let store = FileCredential {
            path: dir.0.join("credential"),
        };
        // A stale temporary file from a crash is replaced, not appended to or trusted.
        fs::write(dir.0.join("credential.tmp"), "junk").expect("write");
        store.store(&Secret::new(GOOD.into())).expect("store");
        assert_eq!(
            store
                .credential()
                .expect("read")
                .map(|s| s.expose().to_owned()),
            Some(GOOD.to_owned())
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&store.path)
                .expect("meta")
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        store.store(&Secret::new(OTHER.into())).expect("replace");
        assert_eq!(
            store
                .credential()
                .expect("read")
                .map(|s| s.expose().to_owned()),
            Some(OTHER.to_owned())
        );
        assert!(!dir.0.join("credential.tmp").exists());
        assert!(store.location().contains("credential"));
    }

    #[cfg(unix)]
    #[test]
    fn file_credential_refuses_symlinks_and_foreign_owners() {
        let dir = TempDir::new("cred-link");
        fs::create_dir_all(&dir.0).expect("mkdir");
        let target = dir.0.join("elsewhere");
        fs::write(&target, GOOD).expect("write");
        std::os::unix::fs::symlink(&target, dir.0.join("credential")).expect("symlink");
        let provider = FileCredential {
            path: dir.0.join("credential"),
        };
        assert!(
            provider
                .credential()
                .expect_err("symlink")
                .contains("not a regular file")
        );
        assert!(owner_allowed(0, 1000));
        assert!(owner_allowed(1000, 1000));
        assert!(!owner_allowed(1001, 1000));
    }
}
