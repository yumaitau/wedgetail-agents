//! Windows Event Log collector: a pull subscription (`EvtSubscribe` with a signal event) that
//! starts after a saved bookmark. Event XML parsing is in the portable `wineventlog` module.

use std::time::Duration;

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

use crate::wineventlog::{MAX_EVENT_XML_BYTES, event_xml_to_wef, wef_time_us};
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
        // SAFETY: channel and query are valid wide strings for the call; the signal and
        // bookmark handles are open and outlive the subscription (field drop order); no
        // callback or context is used (pull model).
        let handle = EvtHandle(unsafe {
            EvtSubscribe(
                None,
                Some(signal.0),
                &HSTRING::from(channel),
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
            signal,
        })
    }

    /// Up to `max` rendered events, waiting up to `wait` for the first.
    fn next(&mut self, max: usize, wait: Duration) -> windows::core::Result<Vec<String>> {
        let mut out = Vec::new();
        let mut waited = false;
        loop {
            // Reset before draining so an event that arrives after the drain re-signals.
            // SAFETY: the signal handle is open.
            unsafe { ResetEvent(self.signal.0) }?;
            while out.len() < max {
                let mut raw = [0isize; NEXT_BATCH];
                let want = (max - out.len()).min(NEXT_BATCH);
                let mut returned = 0u32;
                // SAFETY: `raw[..want]` is a writable array of event handle slots and
                // `returned` a valid out pointer; a zero timeout never blocks.
                let result =
                    unsafe { EvtNext(self.handle.0, &mut raw[..want], 0, 0, &mut returned) };
                match result {
                    Ok(()) => {
                        for &h in &raw[..(returned as usize).min(want)] {
                            let event = EvtHandle(EVT_HANDLE(h));
                            out.push(render(event.0, EvtRenderEventXml)?);
                            // SAFETY: both handles are open.
                            unsafe { EvtUpdateBookmark(self.bookmark.0, event.0) }?;
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
            if !out.is_empty() || waited {
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

    fn bookmark_xml(&self) -> windows::core::Result<String> {
        render(self.bookmark.0, EvtRenderBookmark)
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
}

impl EventLog {
    pub fn new(template: EventTemplate, channel: String, query: String) -> Self {
        Self {
            template,
            channel,
            query,
            bookmark_xml: None,
            subscription: None,
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
        let xmls = sub
            .next(max_events, wait)
            .map_err(|e| win_err("read events", e))?;
        if xmls.is_empty() {
            return Ok(Batch::default());
        }
        let mut events = Vec::with_capacity(xmls.len());
        for xml in xmls {
            match event_xml_to_wef(&xml) {
                Ok(wef) => {
                    let ts = wef_time_us(&wef).unwrap_or_else(time::now_us);
                    events.push(self.template.event(ts, None, wef));
                }
                Err(e) => log::warn!("{}: skipped an event: {e}", self.template.rule_id),
            }
        }
        let bookmark_xml = sub
            .bookmark_xml()
            .map_err(|e| win_err("render bookmark", e))?;
        self.bookmark_xml = Some(bookmark_xml.clone());
        Ok(Batch {
            events,
            checkpoint: Some(Checkpoint::Wineventlog { bookmark_xml }),
        })
    }
}

/// Runs a real subscription on the Application channel. Writing test events with
/// `eventcreate` needs an administrator (as on GitHub's Windows runners); skipped otherwise.
#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::process::Command;
    use std::time::{Duration, Instant};

    use super::EventLog;
    use crate::{Checkpoint, Collector, EventTemplate};

    const SOURCE: &str = "WedgetailAgentTest";

    fn eventcreate(message: &str) -> bool {
        Command::new("eventcreate")
            .args([
                "/T",
                "INFORMATION",
                "/ID",
                "100",
                "/L",
                "APPLICATION",
                "/SO",
                SOURCE,
                "/D",
                message,
            ])
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
                assert_eq!(e.fields["System"]["Provider"]["Name"], SOURCE);
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
        if !eventcreate(&format!("{token} one")) {
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
        assert!(eventcreate(&format!("{token} two")));
        let mut c = EventLog::new(template, "Application".into(), query);
        c.start(cp).expect("resubscribe");
        let (got, _) = collect(&mut c, &token, 2, 5);
        assert_eq!(got, [format!("{token} two")]);
    }
}
