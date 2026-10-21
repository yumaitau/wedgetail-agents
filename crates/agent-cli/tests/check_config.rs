//! `wedgetail-agent check-config` prints every problem with its file and line and exits
//! non-zero.

use std::path::{Path, PathBuf};
use std::process::Command;

struct Dir(PathBuf);

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn setup(name: &str) -> Dir {
    let dir = std::env::temp_dir().join(format!("wt-check-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("etc/rules.d")).expect("mkdir");
    Dir(dir)
}

fn check(config: &Path) -> (bool, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_wedgetail-agent"))
        .args(["check-config", "--config"])
        .arg(config)
        .output()
        .expect("run");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn main_config(dir: &Path) -> String {
    format!(
        "[agent]\nendpoint = \"https://ingest.example.com\"\nstate_dir = {:?}\npresets = []\n",
        dir.join("state")
    )
}

#[test]
fn reports_problems_with_file_and_line() {
    let dir = setup("bad");
    let etc = dir.0.join("etc");
    std::fs::write(
        etc.join("agent.toml"),
        main_config(&dir.0) + "[[rule]]\nid = \"web\"\ntype = \"journald\"\npriority_max = 9\n",
    )
    .expect("write");
    std::fs::write(
        etc.join("rules.d").join("10-web.toml"),
        "# duplicate of agent.toml\n[[rule]]\nid = \"web\"\ntype = \"journald\"\n\n[[rule]]\nid = \"run\"\ntype = \"command\"\n",
    )
    .expect("write");
    let (ok, _, stderr) = check(&etc.join("agent.toml"));
    assert!(!ok, "{stderr}");
    let agent = etc.join("agent.toml");
    let rules = etc.join("rules.d").join("10-web.toml");
    assert!(stderr.contains("configuration is invalid"), "{stderr}");
    assert!(
        stderr.contains(&format!("{}:8: type \"command\"", rules.display())),
        "{stderr}"
    );
    assert!(
        stderr.contains(&format!(
            "{}:5: rule \"web\": priority_max",
            agent.display()
        )),
        "{stderr}"
    );
}

#[test]
fn reports_duplicates_across_files_and_accepts_a_valid_config() {
    let dir = setup("ok");
    let etc = dir.0.join("etc");
    let log = dir.0.join("app.log");
    std::fs::write(
        etc.join("agent.toml"),
        main_config(&dir.0)
            + &format!(
                "[[rule]]\nid = \"app\"\ntype = \"file\"\npaths = [{log:?}]\nparser = \"json\"\n"
            ),
    )
    .expect("write");
    let (ok, stdout, stderr) = check(&etc.join("agent.toml"));
    assert!(ok, "{stderr}");
    assert!(stdout.contains("OK"), "{stdout}");
    assert!(stdout.contains("app (file, file)"), "{stdout}");

    std::fs::write(
        etc.join("rules.d").join("50-dup.toml"),
        format!("[[rule]]\nid = \"app\"\ntype = \"file\"\npaths = [{log:?}]\n"),
    )
    .expect("write");
    let (ok, _, stderr) = check(&etc.join("agent.toml"));
    assert!(!ok);
    assert!(
        stderr.contains("rule id \"app\" is used more than once (first defined at"),
        "{stderr}"
    );
}
