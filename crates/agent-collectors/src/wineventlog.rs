//! Windows Event Log: the portable half.
//!
//! The subscription itself (`EvtSubscribe` with bookmarks) lives in `os::windows::eventlog`.
//! Everything that can be tested without Windows is here: building the XPath query, turning
//! rendered event XML into the WEF JSON shape the Wedgetail `windows` normaliser reads:
//! `{System: {Provider: {Name}, EventID, TimeCreated: {SystemTime}, EventRecordID, Channel,
//! Computer, ...}, EventData: {<Name>: <value>, ...}}`, and joining PowerShell script blocks
//! split over several events ([`script_block`]).

use quick_xml::XmlVersion;
use quick_xml::escape::resolve_predefined_entity;
use quick_xml::events::{BytesStart, Event};
use serde_json::{Map, Value};

use crate::MAX_LINE_BYTES;

pub mod script_block;

/// Rendered events larger than this are not parsed.
pub const MAX_EVENT_XML_BYTES: usize = 1024 * 1024;
const MAX_DEPTH: usize = 16;
const MAX_NODES: usize = 4096;

/// Most `EventID=` terms in one XPath expression. The Event Log service refuses expressions
/// with many more terms, so a longer `event_ids` list becomes one `Select` per chunk in a
/// structured query.
pub const MAX_IDS_PER_SELECT: usize = 20;

/// Query for `EvtSubscribe` on `channel`: the rule's raw `xpath` if set, else a filter on
/// `event_ids`, else every event. More than [`MAX_IDS_PER_SELECT`] ids give a structured
/// query (`<QueryList>`, see [`is_structured_query`]) with one `Select` per chunk.
pub fn build_xpath(channel: &str, event_ids: &[u32], xpath: Option<&str>) -> String {
    if let Some(x) = xpath {
        return x.to_owned();
    }
    if event_ids.is_empty() {
        return "*".to_owned();
    }
    let mut selects = event_ids.chunks(MAX_IDS_PER_SELECT).map(|ids| {
        let ors: Vec<String> = ids.iter().map(|id| format!("EventID={id}")).collect();
        format!("*[System[({})]]", ors.join(" or "))
    });
    if event_ids.len() <= MAX_IDS_PER_SELECT {
        return selects.next().unwrap_or_default();
    }
    let path = xml_escape(channel);
    let body: String = selects
        .map(|x| format!("<Select Path=\"{path}\">{}</Select>", xml_escape(&x)))
        .collect();
    format!("<QueryList><Query Id=\"0\" Path=\"{path}\">{body}</Query></QueryList>")
}

/// A structured query names its channels itself; `EvtSubscribe` then takes no channel path.
pub fn is_structured_query(query: &str) -> bool {
    query.trim_start().starts_with('<')
}

fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            c => out.push(c),
        }
    }
    out
}

#[derive(Debug, Default)]
struct Node {
    name: String,
    attrs: Vec<(String, String)>,
    children: Vec<Node>,
    text: String,
}

/// Parse a rendered event (`EvtRenderEventXml`) into WEF JSON. Errors are short descriptions
/// suitable for a collector error count.
pub fn event_xml_to_wef(xml: &str) -> Result<Map<String, Value>, String> {
    if xml.len() > MAX_EVENT_XML_BYTES {
        return Err("event XML is larger than 1 MiB".into());
    }
    let root = parse_tree(xml)?;
    if root.name != "Event" {
        return Err(format!("root element is {:?}, not Event", root.name));
    }
    let mut out = Map::new();
    for child in &root.children {
        match child.name.as_str() {
            "System" => {
                out.insert("System".into(), Value::Object(system(child)));
            }
            "EventData" => {
                out.insert("EventData".into(), Value::Object(event_data(child)));
            }
            "UserData" => {
                out.insert("UserData".into(), generic(child));
            }
            _ => {}
        }
    }
    if !out.contains_key("System") {
        return Err("event has no System element".into());
    }
    Ok(out)
}

/// Event time from WEF JSON, microseconds since the epoch.
pub fn wef_time_us(wef: &Map<String, Value>) -> Option<u64> {
    let t = wef
        .get("System")?
        .get("TimeCreated")?
        .get("SystemTime")?
        .as_str()?;
    crate::time::parse_timestamp_us(t)
}

fn system(node: &Node) -> Map<String, Value> {
    const NUMERIC: &[&str] = &[
        "EventID",
        "Version",
        "Level",
        "Task",
        "Opcode",
        "EventRecordID",
    ];
    let mut out = Map::new();
    for child in &node.children {
        let value = if child.attrs.is_empty() || !child.text.trim().is_empty() {
            let text = child.text.trim();
            match text.parse::<u64>() {
                Ok(n) if NUMERIC.contains(&child.name.as_str()) => Value::from(n),
                _ => Value::String(text.to_owned()),
            }
        } else {
            attrs_object(child)
        };
        out.insert(child.name.clone(), value);
    }
    out
}

fn event_data(node: &Node) -> Map<String, Value> {
    let mut out = Map::new();
    let mut unnamed = Vec::new();
    for child in &node.children {
        let name = child
            .attrs
            .iter()
            .find(|(k, _)| k == "Name")
            .map(|(_, v)| v.clone());
        match (child.name.as_str(), name) {
            ("Data", Some(name)) => {
                out.insert(name, Value::String(child.text.clone()));
            }
            ("Data", None) => unnamed.push(Value::String(child.text.clone())),
            (other, _) => {
                out.insert(other.to_owned(), Value::String(child.text.clone()));
            }
        }
    }
    if !unnamed.is_empty() {
        out.insert("Data".into(), Value::Array(unnamed));
    }
    out
}

fn attrs_object(node: &Node) -> Value {
    Value::Object(
        node.attrs
            .iter()
            .map(|(k, v)| (k.clone(), Value::String(v.clone())))
            .collect(),
    )
}

/// Elements with children become objects (repeated names become arrays), leaves become text.
fn generic(node: &Node) -> Value {
    if node.children.is_empty() {
        return if node.text.trim().is_empty() && !node.attrs.is_empty() {
            attrs_object(node)
        } else {
            Value::String(node.text.clone())
        };
    }
    let mut out = Map::new();
    for child in &node.children {
        let value = generic(child);
        match out.get_mut(&child.name) {
            Some(Value::Array(items)) => items.push(value),
            Some(existing) => {
                let first = existing.take();
                *existing = Value::Array(vec![first, value]);
            }
            None => {
                out.insert(child.name.clone(), value);
            }
        }
    }
    Value::Object(out)
}

fn parse_tree(xml: &str) -> Result<Node, String> {
    let mut reader = quick_xml::Reader::from_str(xml);
    let mut stack: Vec<Node> = Vec::new();
    let mut nodes = 0usize;
    let err = |e: quick_xml::Error| format!("malformed event XML: {e}");
    loop {
        match reader.read_event().map_err(err)? {
            Event::Start(e) => {
                nodes += 1;
                if stack.len() >= MAX_DEPTH || nodes > MAX_NODES {
                    return Err("event XML is too deep or too large".into());
                }
                stack.push(start_node(&e)?);
            }
            Event::Empty(e) => {
                nodes += 1;
                if nodes > MAX_NODES {
                    return Err("event XML is too large".into());
                }
                let node = start_node(&e)?;
                match stack.last_mut() {
                    Some(parent) => parent.children.push(node),
                    None => return Ok(node),
                }
            }
            Event::End(_) => {
                let node = stack.pop().ok_or("unbalanced event XML")?;
                match stack.last_mut() {
                    Some(parent) => parent.children.push(node),
                    None => return Ok(node),
                }
            }
            Event::Text(t) => push_text(&mut stack, &t.xml_content(XmlVersion::Implicit1_0)),
            Event::CData(t) => push_text(&mut stack, &t.xml_content(XmlVersion::Implicit1_0)),
            Event::GeneralRef(r) => {
                let resolved = match r.resolve_char_ref().map_err(err)? {
                    Some(c) => c.to_string(),
                    None => resolve_predefined_entity(&r)
                        .ok_or("unknown entity in event XML")?
                        .to_owned(),
                };
                push_text(&mut stack, &resolved);
            }
            Event::DocType(_) => return Err("DOCTYPE is not allowed in event XML".into()),
            Event::Eof => return Err("event XML ended early".into()),
            Event::Comment(_) | Event::Decl(_) | Event::PI(_) => {}
        }
    }
}

fn start_node(e: &BytesStart<'_>) -> Result<Node, String> {
    let mut node = Node {
        name: e.local_name().as_ref().to_owned(),
        ..Node::default()
    };
    for attr in e.attributes() {
        let attr = attr.map_err(|e| format!("malformed event XML attribute: {e}"))?;
        if attr.key.as_ref().starts_with("xmlns") {
            continue;
        }
        let key = attr.key.local_name().as_ref().to_owned();
        let value = attr
            .normalized_value(XmlVersion::Implicit1_0)
            .map_err(|e| format!("malformed event XML attribute: {e}"))?;
        node.attrs.push((key, cut(&value)));
    }
    Ok(node)
}

fn push_text(stack: &mut [Node], text: &str) {
    if let Some(node) = stack.last_mut()
        && node.text.len() < MAX_LINE_BYTES
    {
        node.text.push_str(text);
        if node.text.len() > MAX_LINE_BYTES {
            node.text = cut(&node.text);
        }
    }
}

fn cut(s: &str) -> String {
    let mut end = s.len().min(MAX_LINE_BYTES);
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_owned()
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    const LOGON: &str = r#"<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}"/><EventID>4624</EventID><Version>2</Version><Level>0</Level><Task>12544</Task><Opcode>0</Opcode><Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime="2026-10-21T08:00:00.1234567Z"/><EventRecordID>123456</EventRecordID><Correlation ActivityID="{00000000-0000-0000-0000-000000000000}"/><Execution ProcessID="4" ThreadID="8"/><Channel>Security</Channel><Computer>web-01.example.com</Computer><Security/></System><EventData><Data Name="SubjectUserSid">S-1-5-18</Data><Data Name="TargetUserName">alice</Data><Data Name="IpAddress">192.0.2.10</Data><Data Name="CommandLine">a &amp; b &lt;c&gt; &#x41;</Data><Data Name="Empty"/></EventData></Event>"#;

    #[test]
    fn logon_event_matches_wef_shape() {
        let wef = event_xml_to_wef(LOGON).expect("parses");
        assert_eq!(
            wef["System"],
            json!({
                "Provider": {"Name": "Microsoft-Windows-Security-Auditing", "Guid": "{54849625-5478-4994-a5ba-3e3b0328c30d}"},
                "EventID": 4624, "Version": 2, "Level": 0, "Task": 12544, "Opcode": 0,
                "Keywords": "0x8020000000000000",
                "TimeCreated": {"SystemTime": "2026-10-21T08:00:00.1234567Z"},
                "EventRecordID": 123456,
                "Correlation": {"ActivityID": "{00000000-0000-0000-0000-000000000000}"},
                "Execution": {"ProcessID": "4", "ThreadID": "8"},
                "Channel": "Security", "Computer": "web-01.example.com", "Security": ""
            })
        );
        assert_eq!(
            wef["EventData"],
            json!({"SubjectUserSid": "S-1-5-18", "TargetUserName": "alice", "IpAddress": "192.0.2.10", "CommandLine": "a & b <c> A", "Empty": ""})
        );
        assert_eq!(wef_time_us(&wef), Some(1_792_569_600_123_456));
    }

    #[test]
    fn eventid_with_qualifiers_unnamed_data_and_userdata() {
        let xml = r#"<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Application Error"/><EventID Qualifiers="0">1000</EventID><TimeCreated SystemTime="2026-10-21T08:00:00Z"/><EventRecordID>9</EventRecordID><Channel>Application</Channel><Computer>web-01</Computer></System><EventData><Data>app.exe</Data><Data>1.0</Data><Binary>00FF</Binary></EventData></Event>"#;
        let wef = event_xml_to_wef(xml).expect("parses");
        assert_eq!(wef["System"]["EventID"], 1000);
        assert_eq!(
            wef["EventData"],
            json!({"Data": ["app.exe", "1.0"], "Binary": "00FF"})
        );

        let xml = r#"<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Eventlog"/><EventID>1102</EventID><TimeCreated SystemTime="2026-10-21T08:00:00Z"/><Channel>Security</Channel><Computer>web-01</Computer></System><UserData><LogFileCleared xmlns="http://manifests.microsoft.com/win/2004/08/windows/eventlog"><SubjectUserSid>S-1-5-21-1</SubjectUserSid><SubjectUserName>admin</SubjectUserName></LogFileCleared></UserData></Event>"#;
        let wef = event_xml_to_wef(xml).expect("parses");
        assert_eq!(
            wef["UserData"],
            json!({"LogFileCleared": {"SubjectUserSid": "S-1-5-21-1", "SubjectUserName": "admin"}})
        );
    }

    #[test]
    fn hostile_xml_is_rejected() {
        let deep = format!("<Event>{}{}</Event>", "<a>".repeat(100), "</a>".repeat(100));
        let wide = format!(
            "<Event><System/><EventData>{}</EventData></Event>",
            "<Data/>".repeat(MAX_NODES + 1)
        );
        let bomb = r#"<!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;">]><Event><System/>&lol2;</Event>"#;
        let huge = format!(
            "<Event><System/>{}</Event>",
            " ".repeat(MAX_EVENT_XML_BYTES)
        );
        for xml in [
            "",
            "not xml",
            "<Event>",
            "<Event></Wrong>",
            "<Other/>",
            "<Event><EventData/></Event>",
            "<Event><System/>&unknown;</Event>",
            "<Event a='1' a='2'><System/></Event>",
            &deep,
            &wide,
            bomb,
            &huge,
        ] {
            assert!(
                event_xml_to_wef(xml).is_err(),
                "{}",
                &xml[..xml.len().min(80)]
            );
        }
    }

    #[test]
    fn long_values_are_cut() {
        let xml = format!(
            r#"<Event><System><EventID>1</EventID></System><EventData><Data Name="Big">{}</Data></EventData></Event>"#,
            "ü".repeat(MAX_LINE_BYTES)
        );
        let wef = event_xml_to_wef(&xml).expect("parses");
        assert!(wef["EventData"]["Big"].as_str().expect("str").len() <= MAX_LINE_BYTES);
    }

    #[test]
    fn xpath() {
        assert_eq!(build_xpath("Security", &[], None), "*");
        assert_eq!(
            build_xpath("Security", &[4624, 4625], None),
            "*[System[(EventID=4624 or EventID=4625)]]"
        );
        assert_eq!(
            build_xpath("Security", &[4624], Some("*[System[Level<=3]]")),
            "*[System[Level<=3]]"
        );
        assert!(!is_structured_query("*[System[(EventID=1)]]"));
        let ids: Vec<u32> = (1..=MAX_IDS_PER_SELECT as u32).collect();
        let x = build_xpath("Security", &ids, None);
        assert!(!is_structured_query(&x));
        assert_eq!(x.matches("EventID=").count(), MAX_IDS_PER_SELECT);
    }

    #[test]
    fn long_id_lists_are_split_into_selects() {
        let ids: Vec<u32> = (1..=45).collect();
        let x = build_xpath("Microsoft-Windows-AppLocker/MSI and Script", &ids, None);
        assert!(is_structured_query(&x));
        let path = "Microsoft-Windows-AppLocker/MSI and Script";
        let chunk = |r: std::ops::RangeInclusive<u32>| {
            let ors: Vec<String> = r.map(|id| format!("EventID={id}")).collect();
            format!(
                "<Select Path=\"{path}\">*[System[({})]]</Select>",
                ors.join(" or ")
            )
        };
        assert_eq!(
            x,
            format!(
                "<QueryList><Query Id=\"0\" Path=\"{path}\">{}{}{}</Query></QueryList>",
                chunk(1..=20),
                chunk(21..=40),
                chunk(41..=45)
            )
        );
        // Every id is selected exactly once, and no Select has more than the limit.
        for id in 1..=45 {
            let n = x.matches(&format!("EventID={id} ")).count()
                + x.matches(&format!("EventID={id})")).count();
            assert_eq!(n, 1, "{id}");
        }
        for select in x.split("<Select").skip(1) {
            assert!(select.matches("EventID=").count() <= MAX_IDS_PER_SELECT);
        }
        // Channel names are escaped in the XML.
        let x = build_xpath("A&B\"<x>'", &ids, None);
        assert!(x.contains("Path=\"A&amp;B&quot;&lt;x&gt;&apos;\""), "{x}");
        // The structured query is itself well-formed XML.
        let mut reader = quick_xml::Reader::from_str(&x);
        while !matches!(reader.read_event().expect("well-formed"), Event::Eof) {}
    }
}
