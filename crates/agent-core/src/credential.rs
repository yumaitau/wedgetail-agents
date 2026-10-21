//! Where the shipper gets the host credential. Enrolment and OS-specific secure storage plug in
//! here by implementing [`CredentialProvider`].

use std::fmt;
use std::path::PathBuf;

/// A secret string that never prints its value.
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

/// Supplies the current host credential (`wgh_<12>_<43>`). Called before every request, so a
/// rotated credential is picked up without a restart.
pub trait CredentialProvider: Send + Sync + fmt::Debug {
    /// `Ok(None)` while the host is not enrolled: events keep buffering and nothing is sent.
    fn credential(&self) -> Result<Option<Secret>, String>;
}

/// `wgh_` + 12 of `[a-z0-9]` + `_` + 43 of base64url.
pub fn is_host_credential(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("wgh_") else {
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

/// A fixed credential, for tests and embedding.
#[derive(Debug)]
pub struct StaticCredential(pub Option<Secret>);

impl CredentialProvider for StaticCredential {
    fn credential(&self) -> Result<Option<Secret>, String> {
        Ok(self.0.clone())
    }
}

/// The credential in a file that only the agent can read (the Linux layout). A missing file
/// means "not enrolled". On Unix the file must not be readable by group or others.
#[derive(Debug)]
pub struct FileCredential {
    pub path: PathBuf,
}

impl CredentialProvider for FileCredential {
    fn credential(&self) -> Result<Option<Secret>, String> {
        let display = self.path.display();
        let meta = match std::fs::metadata(&self.path) {
            Ok(meta) => meta,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(format!("{display}: {e}")),
        };
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if meta.permissions().mode() & 0o077 != 0 {
                return Err(format!(
                    "{display} must not be readable by group or others (chmod 600)"
                ));
            }
        }
        if meta.len() > 1024 {
            return Err(format!("{display} is not a credential file"));
        }
        let text = std::fs::read_to_string(&self.path).map_err(|e| format!("{display}: {e}"))?;
        let value = text.trim();
        if !is_host_credential(value) {
            return Err(format!("{display} does not hold a host credential"));
        }
        Ok(Some(Secret::new(value.to_owned())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOD: &str = "wgh_abc123def456_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    #[test]
    fn credential_shape() {
        assert!(is_host_credential(GOOD));
        for bad in [
            "",
            "wgi_abc123def456_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "wgh_ABC123def456_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "wgh_abc123def45_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "wgh_abc123def456_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "wgh_abc123def456_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            "wgh_abc123def456_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\nx",
        ] {
            assert!(!is_host_credential(bad), "{bad:?}");
        }
    }

    #[test]
    fn secret_debug_is_redacted() {
        assert_eq!(
            format!("{:?}", Secret::new(GOOD.into())),
            "Secret([redacted])"
        );
        assert!(
            !format!("{:?}", StaticCredential(Some(Secret::new(GOOD.into())))).contains("wgh_")
        );
    }

    #[test]
    fn file_credential() {
        let dir = std::env::temp_dir().join(format!("wt-cred-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join("credential");
        let provider = FileCredential { path: path.clone() };
        assert_eq!(provider.credential().expect("missing is ok"), None);
        std::fs::write(&path, format!("{GOOD}\n")).expect("write");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("chmod");
            assert!(
                provider
                    .credential()
                    .expect_err("too open")
                    .contains("chmod 600")
            );
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("chmod");
        }
        assert_eq!(
            provider
                .credential()
                .expect("ok")
                .map(|s| s.expose().to_owned()),
            Some(GOOD.to_owned())
        );
        std::fs::write(&path, "nonsense").expect("write");
        assert!(provider.credential().is_err());
        std::fs::remove_dir_all(&dir).expect("cleanup");
    }
}
