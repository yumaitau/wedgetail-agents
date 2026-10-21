//! Windows Event Log collector: a pull subscription (`EvtSubscribe` with a signal event) that
//! starts after a saved bookmark. Event XML parsing and script block reassembly are in the
//! portable `wineventlog` module.
//!
//! The bookmark only moves past an event once everything read up to it has been handed to the
//! pipeline: while PowerShell script block parts are held for reassembly it stays before
//! them, so a restart reads them again rather than losing them.

use std::time::{Duration, Instant};

use windows::Win32::Foundation::{
    CloseHandle, ERROR_INSUFFICIENT_BUFFER, ERROR_INVALID_OPERATION, ERROR_NO_MORE_ITEMS, HANDLE,
    WAIT_OBJECT_0,
};
use windows::Win32::System::EventLog::{
    EVT_HANDLE, EVT_RENDER_FLAGS, EvtClose, EvtCreateBookmark, EvtNext, EvtRender,
    EvtRenderBookmark, EvtRenderEventXml, EvtSubscribe, EvtSubscribeStartAfterBookmark,
    EvtSubscribeToFutureEvents, EvtUpdateBookmark,
};
use windows::Win32::System::Threading::{CreateEventW, ResetEvent, WaitForSingleObject};
use windows::core::{HSTRING, PCWSTR};

use crate::wineventlog::script_block::ScriptBlocks;
use crate::wineventlog::{MAX_EVENT_XML_BYTES, event_xml_to_wef, is_structured_query, wef_time_us};
use crate::{Batch, Checkpoint, Collector, CollectorError, EventTemplate, time};

/// Events fetched per `EvtNext` call.
const NEXT_BATCH: usize = 64;

/// An Event Log API handle, closed on drop.
struct EvtHandle(EVT_HANDLE);

impl Drop for EvtHandle {
    fn drop(&mut self) {
        if self.0.0 != 0 {
            // SAFETY: the handle came from an Evt* call, is owned by this wrapper and is closed
            // exactly once.
            let _ = unsafe { EvtClose(self.0) };
        }
    }
}

/// A Win32 event object, closed on drop.
struct SignalEvent(HANDLE);

impl Drop for SignalEvent {
    fn drop(&mut self) {
        // SAFETY: the handle came from CreateEventW, is owned by this wrapper and is closed
        // exactly once.
        let _ = unsafe { CloseHandle(self.0) };
    }
}

/// Field order matters: the subscription is closed before the signal event it uses.
struct Subscription {
    handle: EvtHandle,
    bookmark: EvtHandle,
    /// The last event read, for moving the bookmark when held events are released later.
    last: Option<EvtHandle>,
    /// The bookmark moved since it was last rendered.
    moved: bool,
    signal: SignalEvent,
}

// SAFETY: Event Log and event object handles are process-wide kernel handles that may be used
// from any thread. The subscription is owned by one collector and used by one thread at a time.
unsafe impl Send for Subscription {}

impl std::fmt::Debug for Subscription {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Subscription")
    }
}

impl Subscription {
    fn open(channel: &str, query: &str, bookmark_xml: Option<&str>) -> windows::core::Result<Self> {
        // SAFETY: no security attributes or name; manual-reset, initially signalled event.
        let signal = SignalEvent(unsafe { CreateEventW(None, true, true, PCWSTR::null()) }?);
        let bookmark = EvtHandle(match bookmark_xml {
            // SAFETY: the bookmark XML is a valid NUL-terminated wide string for the call.
            Some(xml) => unsafe { EvtCreateBookmark(&HSTRING::from(xml)) }?,
            // SAFETY: a null string asks for a new, empty bookmark.
            None => unsafe { EvtCreateBookmark(PCWSTR::null()) }?,
        });
        let (start_after, flags) = match bookmark_xml {
            Some(_) => (Some(bookmark.0), EvtSubscribeStartAfterBookmark.0),
            None => (None, EvtSubscribeToFutureEvents.0),
        };
        // A structured query (<QueryList>) names its channels; EvtSubscribe then takes none.
        let channel = HSTRING::from(channel);
        let channel = if is_structured_query(query) {
            PCWSTR::null()
        } else {
            PCWSTR(channel.as_ptr())
        };
        // SAFETY: channel (null or borrowed from an HSTRING that lives to the end of this
        // function) and query are valid wide strings for the call; the signal and bookmark
        // handles are open and outlive the subscription (field drop order); no callback or
        // context is used (pull model).
        let handle = EvtHandle(unsafe {
            EvtSubscribe(
                None,
                Some(signal.0),
                channel,
                &HSTRING::from(query),
                start_after,
                None,
                None,
                flags,
            )
        }?);
        Ok(Self {
            handle,
            bookmark,
            last: None,
            moved: false,
            signal,
        })
    }

    /// Move the bookmark to the last event read.
    fn advance(&mut self) -> windows::core::Result<()> {
        if let Some(last) = &self.last {
            // SAFETY: both handles are open.
            unsafe { EvtUpdateBookmark(self.bookmark.0, last.0) }?;
            self.moved = true;
        }
        Ok(())
    }

    /// Up to `max` events, waiting up to `wait` for the first. `each` gets every rendered
    /// event in order and returns whether the bookmark may move past it.
    fn next(
        &mut self,
        max: usize,
        wait: Duration,
        mut each: impl FnMut(String) -> bool,
    ) -> windows::core::Result<usize> {
        let mut out = 0;
        let mut waited = false;
        loop {
            // Reset before draining so an event that arrives after the drain re-signals.
            // SAFETY: the signal handle is open.
            unsafe { ResetEvent(self.signal.0) }?;
            while out < max {
                let mut raw = [0isize; NEXT_BATCH];
                let want = (max - out).min(NEXT_BATCH);
                let mut returned = 0u32;
                // SAFETY: `raw[..want]` is a writable array of event handle slots and
                // `returned` a valid out pointer; a zero timeout never blocks.
                let result =
                    unsafe { EvtNext(self.handle.0, &mut raw[..want], 0, 0, &mut returned) };
                match result {
                    Ok(()) => {
                        // Own every returned handle first so each is closed even if
                        // rendering one fails.
                        let events: Vec<EvtHandle> = raw[..(returned as usize).min(want)]
                            .iter()
                            .map(|&h| EvtHandle(EVT_HANDLE(h)))
                            .collect();
                        for event in events {
                            let xml = render(event.0, EvtRenderEventXml)?;
                            let release = each(xml);
                            self.last = Some(event);
                            out += 1;
                            if release {
                                self.advance()?;
                            }
                        }
                    }
                    // A pull subscription with nothing new reports ERROR_NO_MORE_ITEMS, or
                    // ERROR_INVALID_OPERATION before its first event.
                    Err(e)
                        if e.code() == ERROR_NO_MORE_ITEMS.to_hresult()
                            || e.code() == ERROR_INVALID_OPERATION.to_hresult() =>
                    {
                        break;
                    }
                    Err(e) => return Err(e),
                }
            }
            if out > 0 || waited {
                return Ok(out);
            }
            let ms = u32::try_from(wait.as_millis()).unwrap_or(u32::MAX);
            // SAFETY: the signal handle is open.
            let status = unsafe { WaitForSingleObject(self.signal.0, ms) };
            if status != WAIT_OBJECT_0 {
                return Ok(out);
            }
            waited = true;
        }
    }

    /// The bookmark, if it moved since the last call.
    fn take_bookmark_xml(&mut self) -> windows::core::Result<Option<String>> {
        if !self.moved {
            return Ok(None);
        }
        let xml = render(self.bookmark.0, EvtRenderBookmark)?;
        self.moved = false;
        Ok(Some(xml))
    }
}

/// Render an event or bookmark as XML.
fn render(fragment: EVT_HANDLE, flags: EVT_RENDER_FLAGS) -> windows::core::Result<String> {
    let mut used = 0u32;
    let mut count = 0u32;
    // SAFETY: a zero-sized query for the needed buffer size; the out pointers are valid.
    match unsafe { EvtRender(None, fragment, flags.0, 0, None, &mut used, &mut count) } {
        Ok(()) => return Ok(String::new()),
        Err(e) if e.code() == ERROR_INSUFFICIENT_BUFFER.to_hresult() => {}
        Err(e) => return Err(e),
    }
    // `used` is in bytes of UTF-16, including the terminating NUL.
    let units = (used as usize).div_ceil(2).min(MAX_EVENT_XML_BYTES * 2);
    let mut buf = vec![0u16; units];
    // SAFETY: `buf` is writable for `units * 2` bytes, which is the size passed.
    unsafe {
        EvtRender(
            None,
            fragment,
            flags.0,
            (units * 2) as u32,
            Some(buf.as_mut_ptr().cast()),
            &mut used,
            &mut count,
        )
    }?;
    let len = ((used as usize) / 2).min(units);
    let text = &buf[..len];
    let text = text.strip_suffix(&[0]).unwrap_or(text);
    Ok(String::from_utf16_lossy(text))
}

#[derive(Debug)]
pub struct EventLog {
    template: EventTemplate,
    channel: String,
    query: String,
    bookmark_xml: Option<String>,
    subscription: Option<Subscription>,
    script_blocks: ScriptBlocks,
}

impl EventLog {
    pub fn new(template: EventTemplate, channel: String, query: String) -> Self {
        Self {
            template,
            channel,
            query,
            bookmark_xml: None,
            subscription: None,
            script_blocks: ScriptBlocks::default(),
        }
    }
}

fn win_err(context: &str, e: windows::core::Error) -> CollectorError {
    CollectorError(format!("{context}: {e}"))
}

impl Collector for EventLog {
    fn rule_id(&self) -> &str {
        &self.template.rule_id
    }

    fn start(&mut self, checkpoint: Option<Checkpoint>) -> Result<(), CollectorError> {
        if let Some(Checkpoint::Wineventlog { bookmark_xml }) = checkpoint {
            self.bookmark_xml = Some(bookmark_xml);
        }
        self.subscription = None;
        // Held script block parts are read again from the bookmark.
        self.script_blocks = ScriptBlocks::default();
        let sub = Subscription::open(&self.channel, &self.query, self.bookmark_xml.as_deref())
            .map_err(|e| win_err(&format!("subscribe to {}", self.channel), e))?;
        self.subscription = Some(sub);
        Ok(())
    }

    fn poll(&mut self, max_events: usize, wait: Duration) -> Result<Batch, CollectorError> {
        let sub = self
            .subscription
            .as_mut()
            .ok_or_else(|| CollectorError("not subscribed".into()))?;
        let (template, blocks) = (&self.template, &mut self.script_blocks);
        let mut events = Vec::new();
        sub.next(max_events, wait, |xml| {
            match event_xml_to_wef(&xml) {
                Ok(wef) => {
                    let ts = wef_time_us(&wef).unwrap_or_else(time::now_us);
                    events.extend(blocks.push(template.event(ts, None, wef), Instant::now()));
                }
                Err(e) => log::warn!("{}: skipped an event: {e}", template.rule_id),
            }
            blocks.is_idle()
        })
        .map_err(|e| win_err("read events", e))?;
        // Script blocks that waited too long for missing parts are sent with what arrived.
        let flushed = blocks.flush_expired(Instant::now());
        if !flushed.is_empty() && blocks.is_idle() {
            sub.advance().map_err(|e| win_err("update bookmark", e))?;
        }
        events.extend(flushed);
        let checkpoint = sub
            .take_bookmark_xml()
            .map_err(|e| win_err("render bookmark", e))?
            .map(|bookmark_xml| {
                self.bookmark_xml = Some(bookmark_xml.clone());
                Checkpoint::Wineventlog { bookmark_xml }
            });
        Ok(Batch { events, checkpoint })
    }
}

/// Real subscriptions on the Application channel. Writing test events with `eventcreate` needs
/// an administrator (as on GitHub's Windows runners); those tests are skipped otherwise.
#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::Path;
    use std::process::Command;
    use std::time::{Duration, Instant};

    use windows::Win32::Foundation::{ERROR_ACCESS_DENIED, ERROR_EVT_CHANNEL_NOT_FOUND};

    use super::{EventLog, Subscription};
    use crate::wineventlog::{MAX_IDS_PER_SELECT, build_xpath, is_structured_query};
    use crate::{Checkpoint, Collector, EventTemplate};

    const SOURCE: &str = "WedgetailAgentTest";

    fn eventcreate(id: u32, message: &str) -> bool {
        Command::new("eventcreate")
            .args([
                "/T",
                "INFORMATION",
                "/ID",
                &id.to_string(),
                "/L",
                "APPLICATION",
            ])
            .args(["/SO", SOURCE, "/D", message])
            .output()
            .is_ok_and(|o| o.status.success())
    }

    fn collect(
        c: &mut EventLog,
        token: &str,
        want: usize,
        secs: u64,
    ) -> (Vec<String>, Option<Checkpoint>) {
        let deadline = Instant::now() + Duration::from_secs(secs);
        let (mut got, mut cp) = (Vec::new(), None);
        while Instant::now() < deadline && got.len() < want {
            let batch = c.poll(100, Duration::from_millis(500)).expect("poll");
            for e in &batch.events {
                assert_eq!(e.fields["System"]["Channel"], "Application");
                if e.fields["System"]["Provider"]["Name"] != SOURCE {
                    continue;
                }
                if let Some(data) = e.fields["EventData"]["Data"][0].as_str()
                    && data.starts_with(token)
                {
                    got.push(data.to_owned());
                }
            }
            cp = batch.checkpoint.or(cp);
        }
        (got, cp)
    }

    #[test]
    fn subscribes_and_resumes_after_bookmark() {
        let token = format!("wt-test-{}", std::process::id());
        let query = format!("*[System[Provider[@Name='{SOURCE}']]]");
        let template = EventTemplate::new("w", "windows.eventlog", None, &BTreeMap::new());
        let mut c = EventLog::new(template.clone(), "Application".into(), query.clone());
        c.start(None).expect("subscribe");
        if !eventcreate(100, &format!("{token} one")) {
            eprintln!("eventcreate failed (not an administrator?); skipping");
            return;
        }
        let (got, cp) = collect(&mut c, &token, 1, 20);
        assert_eq!(got, [format!("{token} one")]);
        let Some(Checkpoint::Wineventlog { bookmark_xml }) = &cp else {
            panic!("no bookmark: {cp:?}")
        };
        assert!(bookmark_xml.contains("Application"), "{bookmark_xml}");
        drop(c);

        // Written while stopped: delivered after the bookmark, without repeating "one".
        assert!(eventcreate(100, &format!("{token} two")));
        let mut c = EventLog::new(template, "Application".into(), query);
        c.start(cp).expect("resubscribe");
        let (got, _) = collect(&mut c, &token, 2, 5);
        assert_eq!(got, [format!("{token} two")]);
    }

    /// A long id list becomes a structured query with several Selects; an id in the last
    /// chunk is delivered, and an id that is not listed is not.
    #[test]
    fn long_event_id_lists_are_split_and_still_filter() {
        let ids: Vec<u32> = (101..=160).collect();
        let query = build_xpath("Application", &ids, None);
        assert!(is_structured_query(&query));
        // Evidence for the per-Select limit: the same ids as one expression.
        let ors: Vec<String> = ids.iter().map(|id| format!("EventID={id}")).collect();
        let single = format!("*[System[({})]]", ors.join(" or "));
        match Subscription::open("Application", &single, None) {
            Ok(_) => eprintln!("a single {}-term XPath was accepted here", ids.len()),
            Err(e) => eprintln!("a single {}-term XPath was refused: {e}", ids.len()),
        }

        let token = format!("wt-split-{}", std::process::id());
        let template = EventTemplate::new("w", "windows.eventlog", None, &BTreeMap::new());
        let mut c = EventLog::new(template, "Application".into(), query);
        c.start(None).expect("subscribe with a structured query");
        assert!(ids.len() > 2 * MAX_IDS_PER_SELECT);
        if !eventcreate(99, &format!("{token} not listed")) {
            eprintln!("eventcreate failed (not an administrator?); skipping");
            return;
        }
        assert!(eventcreate(155, &format!("{token} listed")));
        let (got, cp) = collect(&mut c, &token, 2, 10);
        assert_eq!(got, [format!("{token} listed")]);
        assert!(cp.is_some());
    }

    /// Every Windows preset rule's query is accepted by the Event Log service. Channels that
    /// do not exist on this host are reported, not failed; Security needs an administrator.
    #[test]
    fn preset_queries_are_valid() {
        let presets: Vec<&str> = agent_config::presets::BUILTIN
            .iter()
            .filter(|p| p.os == "windows")
            .map(|p| p.id)
            .collect();
        let main =
            format!("[agent]\nendpoint = \"https://ingest.example.com\"\npresets = {presets:?}\n");
        let config = agent_config::AgentConfig::from_sources(
            Path::new("agent.toml"),
            &main,
            &[],
            agent_config::presets::BUILTIN,
            "windows",
            None,
        )
        .expect("presets load");
        let mut problems = Vec::new();
        for rule in &config.rules {
            let channel = rule.channel.as_deref().expect("channel");
            let query = build_xpath(channel, &rule.event_ids, rule.xpath.as_deref());
            match Subscription::open(channel, &query, None) {
                Ok(_) => eprintln!("{}: {channel}: subscribed", rule.id),
                Err(e) if e.code() == ERROR_EVT_CHANNEL_NOT_FOUND.to_hresult() => {
                    eprintln!("{}: {channel}: channel not on this host", rule.id);
                }
                Err(e) if e.code() == ERROR_ACCESS_DENIED.to_hresult() => {
                    eprintln!(
                        "{}: {channel}: access denied (not an administrator?)",
                        rule.id
                    );
                }
                Err(e) => problems.push(format!("{}: {channel}: {query}: {e}", rule.id)),
            }
        }
        assert!(problems.is_empty(), "{problems:#?}");
    }
}
