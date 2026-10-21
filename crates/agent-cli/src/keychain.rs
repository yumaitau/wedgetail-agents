//! The host credential on macOS: a generic password item in the System keychain
//! (`/Library/Keychains/System.keychain`), which only root can change. The agent runs as root
//! (launchd daemon), so the service and `sudo wedgetail-agent enrol` share the item.

use std::path::PathBuf;

use agent_core::credential::{
    CredentialProvider, CredentialStore, MAX_STORED_BYTES, Secret, parse_host_credential,
};
use security_framework::item::{ItemClass, ItemSearchOptions};
use security_framework::os::macos::keychain::SecKeychain;

pub const SYSTEM_KEYCHAIN: &str = "/Library/Keychains/System.keychain";
/// Keychain item service and account names.
pub const SERVICE: &str = "au.com.yumait.wedgetail-agent";
pub const ACCOUNT: &str = "host-credential";
/// `errSecItemNotFound`.
const ITEM_NOT_FOUND: i32 = -25300;

#[derive(Debug)]
pub struct KeychainCredential {
    pub path: PathBuf,
}

impl KeychainCredential {
    pub fn system() -> Self {
        Self {
            path: SYSTEM_KEYCHAIN.into(),
        }
    }

    fn open(&self) -> Result<SecKeychain, String> {
        SecKeychain::open(&self.path).map_err(|e| format!("{}: {e}", self.path.display()))
    }
}

impl CredentialProvider for KeychainCredential {
    fn credential(&self) -> Result<Option<Secret>, String> {
        // A daemon has no one to answer a keychain prompt: fail instead of waiting for one.
        let _no_prompts = SecKeychain::disable_user_interaction().map_err(|e| e.to_string())?;
        let keychain = self.open()?;
        match keychain.find_generic_password(SERVICE, ACCOUNT) {
            Ok((password, _item)) => {
                if password.len() as u64 > MAX_STORED_BYTES {
                    return Err(format!("keychain item {SERVICE} is not a host credential"));
                }
                let text = std::str::from_utf8(&password)
                    .map_err(|_| format!("keychain item {SERVICE} is not a host credential"))?;
                parse_host_credential(text)
                    .map(Some)
                    .map_err(|e| format!("keychain item {SERVICE} {e}"))
            }
            Err(e) if e.code() == ITEM_NOT_FOUND => Ok(None),
            Err(e) => Err(format!(
                "{} item {SERVICE}: {e} (are you root?)",
                self.path.display()
            )),
        }
    }
}

impl CredentialStore for KeychainCredential {
    fn store(&self, credential: &Secret) -> Result<(), String> {
        let _no_prompts = SecKeychain::disable_user_interaction().map_err(|e| e.to_string())?;
        let keychain = self.open()?;
        let value = credential.expose().as_bytes();
        // Replaces the item's data in place when it exists, so readers see old or new.
        let Err(error) = keychain.set_generic_password(SERVICE, ACCOUNT, value) else {
            return Ok(());
        };
        // The item's access list trusts the build that created it; a differently signed build
        // (an unsigned upgrade) cannot change it. Delete it (needs root) and add a new one.
        ItemSearchOptions::new()
            .keychains(std::slice::from_ref(&keychain))
            .class(ItemClass::generic_password())
            .service(SERVICE)
            .account(ACCOUNT)
            .delete()
            .and_then(|()| keychain.add_generic_password(SERVICE, ACCOUNT, value))
            .map_err(|_| format!("{} item {SERVICE}: {error}", self.path.display()))
    }

    fn location(&self) -> String {
        format!(
            "keychain {} (service {SERVICE}, account {ACCOUNT})",
            self.path.display()
        )
    }
}

#[cfg(test)]
mod tests {
    use security_framework::os::macos::keychain::CreateOptions;

    use super::*;

    const A: &str = "wgh_abc123def456_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const B: &str = "wgh_abc123def456_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";

    /// A throwaway keychain file, deleted (and removed from the search list) on drop. Tests
    /// cannot write the System keychain without root, and must not touch it.
    struct TempKeychain {
        dir: PathBuf,
        path: PathBuf,
        keychain: SecKeychain,
    }

    impl TempKeychain {
        fn new() -> Self {
            let dir = std::env::temp_dir().join(format!(
                "wt-keychain-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| d.as_nanos())
            ));
            std::fs::create_dir_all(&dir).expect("mkdir");
            let path = dir.join("test.keychain-db");
            let keychain = CreateOptions::new()
                .password("wedgetail-test")
                .prompt_user(false)
                .create(&path)
                .expect("create keychain");
            Self {
                dir,
                path,
                keychain,
            }
        }
    }

    impl Drop for TempKeychain {
        fn drop(&mut self) {
            let _ = std::process::Command::new("/usr/bin/security")
                .arg("delete-keychain")
                .arg(&self.path)
                .output();
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn read(store: &KeychainCredential) -> Option<String> {
        store
            .credential()
            .expect("read")
            .map(|s| s.expose().to_owned())
    }

    #[test]
    fn keychain_round_trip() {
        let temp = TempKeychain::new();
        let store = KeychainCredential {
            path: temp.path.clone(),
        };
        assert_eq!(read(&store), None);
        store.store(&Secret::new(A.into())).expect("store");
        assert_eq!(read(&store).as_deref(), Some(A));
        store.store(&Secret::new(B.into())).expect("replace");
        assert_eq!(read(&store).as_deref(), Some(B));
        assert!(store.location().contains(SERVICE));

        // Something other than a credential in the item is an error that does not echo it.
        temp.keychain
            .set_generic_password(SERVICE, ACCOUNT, b"not-a-credential")
            .expect("overwrite");
        let err = store.credential().expect_err("garbage");
        assert!(!err.contains("not-a-credential"), "{err}");
    }
}
