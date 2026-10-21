//! Windows checks for `wedgetail-agent status`: recommended audit policy subcategories that
//! are off (from `auditpol /get /category:* /r`), whether process creation events (4688)
//! include the command line, and preset channels that are missing or disabled.
//!
//! Everything here is read only: the agent never changes audit policy, registry policy or
//! channel settings. Parsing and the report are portable so they are tested on every OS; the
//! Windows half that runs `auditpol` and reads the registry is in `os::windows::audit`.

use std::collections::BTreeMap;

use serde_json::{Value, json};

/// One audit policy subcategory a preset depends on.
#[derive(Debug)]
pub struct Recommendation {
    /// Subcategory GUID, upper case with braces (as `auditpol /r` prints it). Names are
    /// localised; GUIDs are not.
    pub guid: &'static str,
    pub name: &'static str,
    pub setting: Setting,
    /// Reported when one of these presets is loaded.
    pub presets: &'static [&'static str],
    /// Event ids the subcategory produces for those presets.
    pub events: &'static str,
}

/// Success and failure auditing of one subcategory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Setting {
    pub success: bool,
    pub failure: bool,
}

const S: Setting = Setting {
    success: true,
    failure: false,
};
const F: Setting = Setting {
    success: false,
    failure: true,
};
const SF: Setting = Setting {
    success: true,
    failure: true,
};

const SECURITY: &[&str] = &["windows-security"];
const OBJECTS: &[&str] = &["windows-security-objects"];
const DC: &[&str] = &["windows-security-dc"];

/// The subcategories in `presets/windows/recommended-audit-policy.md`.
pub static RECOMMENDED: &[Recommendation] = &[
    rec(
        "{0CCE923F-69AE-11D9-BED3-505054503030}",
        "Credential Validation",
        SF,
        SECURITY,
        "4776",
    ),
    rec(
        "{0CCE9215-69AE-11D9-BED3-505054503030}",
        "Logon",
        SF,
        SECURITY,
        "4624, 4625, 4648",
    ),
    rec(
        "{0CCE9216-69AE-11D9-BED3-505054503030}",
        "Logoff",
        S,
        SECURITY,
        "4634, 4647",
    ),
    rec(
        "{0CCE9217-69AE-11D9-BED3-505054503030}",
        "Account Lockout",
        F,
        SECURITY,
        "4625",
    ),
    rec(
        "{0CCE921B-69AE-11D9-BED3-505054503030}",
        "Special Logon",
        S,
        SECURITY,
        "4672",
    ),
    rec(
        "{0CCE921C-69AE-11D9-BED3-505054503030}",
        "Other Logon/Logoff Events",
        SF,
        SECURITY,
        "4778, 4779",
    ),
    rec(
        "{0CCE922B-69AE-11D9-BED3-505054503030}",
        "Process Creation",
        S,
        SECURITY,
        "4688",
    ),
    rec(
        "{0CCE922C-69AE-11D9-BED3-505054503030}",
        "Process Termination",
        S,
        SECURITY,
        "4689",
    ),
    rec(
        "{0CCE9235-69AE-11D9-BED3-505054503030}",
        "User Account Management",
        SF,
        SECURITY,
        "4720, 4722-4726, 4738, 4740, 4767",
    ),
    rec(
        "{0CCE9237-69AE-11D9-BED3-505054503030}",
        "Security Group Management",
        S,
        SECURITY,
        "4728, 4732, 4756",
    ),
    rec(
        "{0CCE922F-69AE-11D9-BED3-505054503030}",
        "Audit Policy Change",
        SF,
        SECURITY,
        "4719, 4904, 4905",
    ),
    rec(
        "{0CCE9230-69AE-11D9-BED3-505054503030}",
        "Authentication Policy Change",
        S,
        SECURITY,
        "4739",
    ),
    rec(
        "{0CCE9232-69AE-11D9-BED3-505054503030}",
        "MPSSVC Rule-Level Policy Change",
        SF,
        SECURITY,
        "4946, 4947, 4948",
    ),
    rec(
        "{0CCE9211-69AE-11D9-BED3-505054503030}",
        "Security System Extension",
        S,
        SECURITY,
        "4697",
    ),
    rec(
        "{0CCE9227-69AE-11D9-BED3-505054503030}",
        "Other Object Access Events",
        SF,
        SECURITY,
        "4698-4702",
    ),
    rec(
        "{0CCE921D-69AE-11D9-BED3-505054503030}",
        "File System",
        SF,
        OBJECTS,
        "4656, 4663",
    ),
    rec(
        "{0CCE921E-69AE-11D9-BED3-505054503030}",
        "Registry",
        SF,
        OBJECTS,
        "4656, 4663",
    ),
    rec(
        "{0CCE9224-69AE-11D9-BED3-505054503030}",
        "File Share",
        SF,
        OBJECTS,
        "5140",
    ),
    rec(
        "{0CCE9244-69AE-11D9-BED3-505054503030}",
        "Detailed File Share",
        SF,
        OBJECTS,
        "5145",
    ),
    rec(
        "{0CCE9242-69AE-11D9-BED3-505054503030}",
        "Kerberos Authentication Service",
        SF,
        DC,
        "4768, 4771",
    ),
    rec(
        "{0CCE9240-69AE-11D9-BED3-505054503030}",
        "Kerberos Service Ticket Operations",
        SF,
        DC,
        "4769",
    ),
    rec(
        "{0CCE923B-69AE-11D9-BED3-505054503030}",
        "Directory Service Access",
        SF,
        DC,
        "4662",
    ),
    rec(
        "{0CCE923C-69AE-11D9-BED3-505054503030}",
        "Directory Service Changes",
        S,
        DC,
        "5136, 5137",
    ),
];

const fn rec(
    guid: &'static str,
    name: &'static str,
    setting: Setting,
    presets: &'static [&'static str],
    events: &'static str,
) -> Recommendation {
    Recommendation {
        guid,
        name,
        setting,
        presets,
        events,
    }
}

impl Setting {
    /// `auditpol` English wording. Localised wording is not recognised (`None`).
    fn parse(text: &str) -> Option<Self> {
        match text.trim() {
            "No Auditing" => Some(Self {
                success: false,
                failure: false,
            }),
            "Success" => Some(S),
            "Failure" => Some(F),
            "Success and Failure" => Some(SF),
            _ => None,
        }
    }

    fn name(self) -> &'static str {
        match (self.success, self.failure) {
            (false, false) => "No Auditing",
            (true, false) => "Success",
            (false, true) => "Failure",
            (true, true) => "Success and Failure",
        }
    }

    fn covers(self, want: Self) -> bool {
        (self.success || !want.success) && (self.failure || !want.failure)
    }
}

/// One subcategory row from `auditpol /r`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    pub name: String,
    /// The setting text as printed.
    pub setting_text: String,
    pub setting: Option<Setting>,
}

/// Largest `auditpol` output read (it is about 10 KB).
const MAX_AUDITPOL_BYTES: usize = 256 * 1024;

/// Parse `auditpol /get /category:* /r` (CSV: machine name, policy target, subcategory,
/// subcategory GUID, inclusion setting, exclusion setting) into rows keyed by upper-case GUID.
/// Columns are found by the GUID field, so localised headers and names still parse.
pub fn parse_auditpol(csv: &str) -> Result<BTreeMap<String, Row>, String> {
    if csv.len() > MAX_AUDITPOL_BYTES {
        return Err("auditpol output is too large".into());
    }
    let mut rows = BTreeMap::new();
    for line in csv.lines() {
        let fields = split_csv(line);
        let Some(i) = fields.iter().position(|f| is_guid(f)) else {
            continue;
        };
        let (Some(name), Some(setting)) = (
            i.checked_sub(1).and_then(|j| fields.get(j)),
            fields.get(i + 1),
        ) else {
            continue;
        };
        rows.insert(
            fields[i].trim().to_ascii_uppercase(),
            Row {
                name: name.trim().chars().take(128).collect(),
                setting_text: setting.trim().chars().take(64).collect(),
                setting: Setting::parse(setting),
            },
        );
    }
    if rows.is_empty() {
        return Err("no audit policy subcategories in the auditpol output".into());
    }
    Ok(rows)
}

fn is_guid(field: &str) -> bool {
    let f = field.trim().as_bytes();
    f.len() == 38
        && f[0] == b'{'
        && f[37] == b'}'
        && f[1..37].iter().enumerate().all(|(i, &b)| {
            if [8, 13, 18, 23].contains(&i) {
                b == b'-'
            } else {
                b.is_ascii_hexdigit()
            }
        })
}

/// RFC 4180 fields of one line (`auditpol` does not quote, but names could hold commas).
fn split_csv(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut field = String::new();
    let mut quoted = false;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match (c, quoted) {
            ('"', true) if chars.peek() == Some(&'"') => {
                field.push('"');
                chars.next();
            }
            ('"', _) => quoted = !quoted,
            (',', false) => fields.push(std::mem::take(&mut field)),
            (c, _) => field.push(c),
        }
        if fields.len() > 64 {
            break;
        }
    }
    fields.push(field);
    fields
}

/// A preset channel that cannot be read as configured.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelProblem {
    pub channel: String,
    /// `missing` or `disabled`.
    pub state: &'static str,
    pub rules: Vec<String>,
}

/// The `windows` object of `status --json`.
///
/// `auditpol` is the command output or why it could not run; `command_line` is the
/// "Include command line in process creation events" policy (`None`: unknown).
pub fn report(
    auditpol: Result<&str, &str>,
    command_line: Option<bool>,
    channels: &[ChannelProblem],
    presets: &[String],
) -> Value {
    let loaded = |r: &Recommendation| r.presets.iter().any(|p| presets.iter().any(|q| q == p));
    let audit =
        match auditpol.and_then(|text| parse_auditpol(text).map_err(|_| "unparsable output")) {
            Err(e) => json!({"checked": false, "error": e}),
            Ok(rows) => {
                let mut off = Vec::new();
                let mut unknown = Vec::new();
                for r in RECOMMENDED.iter().filter(|r| loaded(r)) {
                    match rows.get(r.guid) {
                        Some(Row {
                            setting: Some(have),
                            ..
                        }) if have.covers(r.setting) => {}
                        Some(Row {
                            setting: Some(have),
                            ..
                        }) => off.push(json!({
                            "subcategory": r.name, "guid": r.guid, "setting": have.name(),
                            "recommended": r.setting.name(), "events": r.events,
                        })),
                        Some(Row { setting_text, .. }) => unknown.push(json!({
                            "subcategory": r.name, "guid": r.guid, "setting": setting_text,
                            "recommended": r.setting.name(), "events": r.events,
                        })),
                        None => unknown.push(json!({
                            "subcategory": r.name, "guid": r.guid, "setting": null,
                            "recommended": r.setting.name(), "events": r.events,
                        })),
                    }
                }
                json!({"checked": true, "off": off, "unrecognised": unknown})
            }
        };
    let channels: Vec<Value> = channels
        .iter()
        .map(|c| json!({"channel": c.channel, "state": c.state, "rules": c.rules}))
        .collect();
    let security = presets.iter().any(|p| p == "windows-security");
    json!({
        "audit_policy": audit,
        "process_command_line": if security { json!(command_line) } else { Value::Null },
        "channels": channels,
    })
}

/// The `status` text for [`report`].
pub fn format_report(w: &Value) -> String {
    let mut lines = vec!["windows checks (read only; the agent never changes them):".to_owned()];
    let audit = &w["audit_policy"];
    if audit["checked"] == true {
        let off = audit["off"].as_array().cloned().unwrap_or_default();
        let unknown = audit["unrecognised"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        if off.is_empty() && unknown.is_empty() {
            lines.push("  audit policy: every recommended subcategory is on".into());
        } else {
            lines.push(format!(
                "  audit policy: {} recommended subcategories are off \
                 (presets/windows/recommended-audit-policy.md):",
                off.len() + unknown.len()
            ));
            for r in off.iter().chain(&unknown) {
                let have = r["setting"].as_str().unwrap_or("not listed");
                lines.push(format!(
                    "    {:<36} {have}, recommended {} (events {})",
                    r["subcategory"].as_str().unwrap_or("?"),
                    r["recommended"].as_str().unwrap_or("?"),
                    r["events"].as_str().unwrap_or("?"),
                ));
            }
        }
    } else {
        lines.push(format!(
            "  audit policy: not checked ({}); run status as an administrator",
            audit["error"].as_str().unwrap_or("unknown error")
        ));
    }
    match w["process_command_line"].as_bool() {
        Some(false) => lines.push(
            "  warning: 4688 process creation events do not include the command line; turn on \
             \"Include command line in process creation events\" (Administrative Templates > \
             System > Audit Process Creation)"
                .into(),
        ),
        Some(true) => lines.push("  4688 command line: included".into()),
        None => {}
    }
    for c in w["channels"].as_array().into_iter().flatten() {
        let rules: Vec<&str> = c["rules"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect();
        lines.push(format!(
            "  channel {}: {} (rules {})",
            c["channel"].as_str().unwrap_or("?"),
            c["state"].as_str().unwrap_or("?"),
            rules.join(", ")
        ));
    }
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(name: &str) -> String {
        let path = format!(
            "{}/../../presets/windows/fixtures/auditpol/{name}",
            env!("CARGO_MANIFEST_DIR")
        );
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"))
    }

    fn presets(ids: &[&str]) -> Vec<String> {
        ids.iter().map(|s| (*s).to_owned()).collect()
    }

    fn off_names(w: &Value) -> Vec<String> {
        w["audit_policy"]["off"]
            .as_array()
            .expect("off")
            .iter()
            .map(|r| r["subcategory"].as_str().expect("name").to_owned())
            .collect()
    }

    #[test]
    fn recommendations_are_well_formed() {
        let mut guids: Vec<&str> = RECOMMENDED.iter().map(|r| r.guid).collect();
        assert!(
            guids
                .iter()
                .all(|g| is_guid(g) && g.to_ascii_uppercase() == *g)
        );
        guids.sort_unstable();
        guids.dedup();
        assert_eq!(guids.len(), RECOMMENDED.len());
    }

    #[test]
    fn default_policy_reports_what_is_off() {
        let rows = parse_auditpol(&fixture("default.csv")).expect("parses");
        assert_eq!(rows.len(), 59);
        let logon = &rows["{0CCE9215-69AE-11D9-BED3-505054503030}"];
        assert_eq!(logon.name, "Logon");
        assert_eq!(logon.setting, Some(SF));

        let w = report(
            Ok(&fixture("default.csv")),
            Some(false),
            &[],
            &presets(&["windows-security"]),
        );
        assert_eq!(w["audit_policy"]["checked"], true);
        assert_eq!(
            off_names(&w),
            [
                "Credential Validation",
                "Account Lockout",
                "Other Logon/Logoff Events",
                "Process Creation",
                "Process Termination",
                "User Account Management",
                "Audit Policy Change",
                "MPSSVC Rule-Level Policy Change",
                "Security System Extension",
                "Other Object Access Events"
            ]
        );
        let process = &w["audit_policy"]["off"][3];
        assert_eq!(process["setting"], "No Auditing");
        assert_eq!(process["recommended"], "Success");
        assert_eq!(process["events"], "4688");
        let text = format_report(&w);
        assert!(
            text.contains("10 recommended subcategories are off"),
            "{text}"
        );
        assert!(text.contains("Process Creation"), "{text}");
        assert!(text.contains("do not include the command line"), "{text}");

        // Opt-in presets add their subcategories.
        let w = report(
            Ok(&fixture("default.csv")),
            Some(true),
            &[],
            &presets(&["windows-security", "windows-security-dc"]),
        );
        assert!(off_names(&w).contains(&"Directory Service Changes".to_owned()));
        assert!(format_report(&w).contains("4688 command line: included"));
    }

    #[test]
    fn recommended_policy_reports_nothing() {
        let w = report(
            Ok(&fixture("recommended.csv")),
            Some(true),
            &[],
            &presets(&[
                "windows-security",
                "windows-security-objects",
                "windows-security-dc",
            ]),
        );
        assert_eq!(off_names(&w), Vec::<String>::new());
        assert_eq!(w["audit_policy"]["unrecognised"], json!([]));
        assert!(format_report(&w).contains("every recommended subcategory is on"));
    }

    #[test]
    fn localised_and_hostile_output() {
        // German wording: names and settings are localised, GUIDs are not.
        let csv = "Computername,Richtlinienziel,Unterkategorie,Unterkategorie-GUID,Einschlusseinstellung,Ausschlusseinstellung\n\
                   WEB-01,System,Anmelden,{0CCE9215-69AE-11D9-BED3-505054503030},Erfolg und Fehler,\n";
        let w = report(Ok(csv), None, &[], &presets(&["windows-security"]));
        let unknown = w["audit_policy"]["unrecognised"].as_array().expect("list");
        assert!(unknown.iter().any(|r| r["setting"] == "Erfolg und Fehler"));
        assert!(unknown.iter().any(|r| r["setting"].is_null()));
        assert_eq!(w["process_command_line"], Value::Null);

        for bad in [
            "",
            "garbage",
            "a,b,c\n,,,\n",
            "{0CCE9215-69AE-11D9-BED3-505054503030}",
        ] {
            assert!(parse_auditpol(bad).is_err(), "{bad:?}");
        }
        assert!(parse_auditpol(&"x,".repeat(200_000)).is_err());
        let quoted = "M,System,\"Name, with \"\"comma\"\"\",{0CCE9215-69AE-11D9-BED3-505054503030},Success,\n";
        let rows = parse_auditpol(quoted).expect("parses");
        assert_eq!(
            rows["{0CCE9215-69AE-11D9-BED3-505054503030}"].name,
            "Name, with \"comma\""
        );
        // Lower-case GUIDs are matched too.
        let lower = "M,System,Logon,{0cce9215-69ae-11d9-bed3-505054503030},Success,\n";
        assert!(
            parse_auditpol(lower)
                .expect("parses")
                .contains_key("{0CCE9215-69AE-11D9-BED3-505054503030}")
        );

        let w = report(
            Err("access denied"),
            None,
            &[],
            &presets(&["windows-security"]),
        );
        assert_eq!(w["audit_policy"]["checked"], false);
        assert!(format_report(&w).contains("not checked (access denied)"));
    }

    #[test]
    fn channel_problems_are_listed() {
        let channels = [ChannelProblem {
            channel: "Microsoft-Windows-TaskScheduler/Operational".into(),
            state: "disabled",
            rules: vec!["windows-operational.task-scheduler".into()],
        }];
        let w = report(Err("x"), None, &channels, &[]);
        assert_eq!(w["channels"][0]["state"], "disabled");
        assert!(format_report(&w).contains(
            "channel Microsoft-Windows-TaskScheduler/Operational: disabled (rules windows-operational.task-scheduler)"
        ));
    }
}
