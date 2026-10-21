//! Collector checkpoints, saved to `checkpoints.json` in the state directory after the events
//! they cover are in the disk buffer.

use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};

use agent_collectors::Checkpoint;

use crate::buffer::write_atomic;

const FILE: &str = "checkpoints.json";

#[derive(Debug)]
pub struct CheckpointStore {
    dir: PathBuf,
    map: BTreeMap<String, Checkpoint>,
}

impl CheckpointStore {
    /// Load the store. An unreadable file is logged and treated as empty: collectors then use
    /// their default start position rather than the agent refusing to start.
    pub fn open(dir: &Path) -> io::Result<Self> {
        std::fs::create_dir_all(dir)?;
        let map = match std::fs::read(dir.join(FILE)) {
            Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_else(|e| {
                log::warn!("ignoring unreadable {FILE}: {e}");
                BTreeMap::new()
            }),
            Err(e) if e.kind() == io::ErrorKind::NotFound => BTreeMap::new(),
            Err(e) => return Err(e),
        };
        Ok(Self {
            dir: dir.to_path_buf(),
            map,
        })
    }

    pub fn get(&self, rule_id: &str) -> Option<Checkpoint> {
        self.map.get(rule_id).cloned()
    }

    /// Set and persist one rule's checkpoint.
    pub fn save(&mut self, rule_id: &str, checkpoint: Checkpoint) -> io::Result<()> {
        if self.map.get(rule_id) == Some(&checkpoint) {
            return Ok(());
        }
        self.map.insert(rule_id.to_owned(), checkpoint);
        let bytes = serde_json::to_vec(&self.map).map_err(io::Error::other)?;
        write_atomic(&self.dir, FILE, &bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn persists_and_tolerates_garbage() {
        let dir = std::env::temp_dir().join(format!("wt-cp-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut store = CheckpointStore::open(&dir).expect("open");
        store
            .save(
                "ssh",
                Checkpoint::Journald {
                    cursor: "s=1".into(),
                },
            )
            .expect("save");
        let store = CheckpointStore::open(&dir).expect("reopen");
        assert_eq!(
            store.get("ssh"),
            Some(Checkpoint::Journald {
                cursor: "s=1".into()
            })
        );
        std::fs::write(dir.join(FILE), "{garbage").expect("write");
        assert_eq!(
            CheckpointStore::open(&dir).expect("reopen").get("ssh"),
            None
        );
        std::fs::remove_dir_all(&dir).expect("cleanup");
    }
}
