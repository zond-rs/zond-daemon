// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Daemon, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # The scans this process is running, and what each of them has said
//!
//! ## One reader, one log, one cursor
//!
//! The engine's event stream is a broadcast that drops under pressure, and says
//! so rather than pretending otherwise. That is right for a consumer inside the
//! process and useless for a client that closed its connection and came back.
//!
//! So exactly one task per scan reads that stream, and the engine never sees a
//! slow consumer. On each notice it reads the host back out of the store,
//! writes it down, and appends it to a numbered log only if the host actually
//! changed, which matters because a port scan announces the same host again
//! every time one of its ports settles.
//!
//! A client reads that log from a cursor. Asking from nothing gets a snapshot of
//! every host as it now stands and then the tail, so reopening a scan of a `/16`
//! costs one snapshot rather than a replay of two hundred thousand notices.
//!
//! ## What this does not do yet
//!
//! The log lives in memory, so it goes when the process does. Its durable form
//! is the journal the engine already writes, which is what will let a scan that
//! finished last week be read through the same call as one still running.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use tokio::sync::Notify;

use zond_engine::export::{ExportOptions, Redaction, schema::HostDto};
use zond_engine::format::time;
use zond_engine::journal::store;
use zond_engine::journal::store::Retention;
use zond_engine::model::ip::scoped::ScopedIp;
use zond_engine::report::ScanReport;
use zond_engine::scanner::handle::ScanHandle;
use zond_engine::scanner::session::{HostStore, Progress, ScanEvent, ScanEvents};
use zond_engine::{ScanTask, Stage};

use crate::convert;
use crate::error::Error;
use crate::proto;

/// Everything one scan has said, numbered.
#[derive(Debug, Default)]
struct Log {
    entries: Mutex<Vec<proto::Event>>,
    /// The document last written down for each address, hashed.
    ///
    /// Hashed rather than kept, because the point of holding it is to answer
    /// whether the host changed and a hash answers that in eight bytes where the
    /// document itself can run to kilobytes per host.
    seen: Mutex<HashMap<ScopedIp, u64>>,
    /// Wakes whoever is waiting for the next entry.
    arrived: Notify,
    /// Set once the scan is over and nothing further will be appended.
    closed: AtomicBool,
}

impl Log {
    /// Appends one entry and wakes the readers.
    fn push(&self, body: proto::event::Body) {
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());

        // Numbered from one, so a cursor of zero means "everything" without
        // needing a separate way to say it.
        let seq = entries.len() as u64 + 1;
        entries.push(proto::Event {
            seq,
            body: Some(body),
        });
        drop(entries);

        self.arrived.notify_waiters();
    }

    /// Whether this host has anything new to say, and remembers the answer.
    fn changed(&self, address: &ScopedIp, document: &str) -> bool {
        let digest = hash(document);
        let mut seen = self.seen.lock().unwrap_or_else(|e| e.into_inner());

        seen.insert(address.clone(), digest) != Some(digest)
    }

    fn watermark(&self) -> u64 {
        self.entries.lock().unwrap_or_else(|e| e.into_inner()).len() as u64
    }

    fn after(&self, cursor: u64) -> Vec<proto::Event> {
        let entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());

        entries
            .iter()
            .filter(|entry| entry.seq > cursor)
            .cloned()
            .collect()
    }

    fn close(&self) {
        self.closed.store(true, Ordering::Release);
        self.arrived.notify_waiters();
    }

    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }
}

/// FNV-1a, which is enough to answer "is this the same document as last time".
///
/// Nothing here is a security decision: the worst a collision costs is one host
/// update a client does not receive, and the next change to that host sends the
/// whole of its current state anyway.
fn hash(text: &str) -> u64 {
    let mut digest: u64 = 0xcbf2_9ce4_8422_2325;

    for byte in text.as_bytes() {
        digest ^= u64::from(*byte);
        digest = digest.wrapping_mul(0x0000_0100_0000_01b3);
    }

    digest
}

/// One scan, as this process holds it.
#[derive(Debug)]
pub struct Scan {
    /// What a client calls it.
    pub id: String,
    hosts: HostStore,
    progress: Progress,
    handle: ScanHandle,
    log: Arc<Log>,
    redaction: Redaction,
    /// What the scan amounted to, once it is over.
    ///
    /// Kept rather than dropped: it is what `Export` writes, and rebuilding it
    /// from the journal a moment after the engine handed it over would be
    /// reading back something already in hand.
    report: Mutex<Option<ScanReport>>,
}

impl Scan {
    /// Where the scan has got to, as one answer.
    pub fn state(&self) -> proto::ScanState {
        let running = !self.log.is_closed();

        proto::ScanState {
            scan_id: self.id.clone(),
            running,
            cause: (!running).then(|| convert::stop_cause(self.handle.stopped()) as i32),
            progress: Some(self.progress()),
            seq: self.log.watermark(),
            // `report` is deprecated and stays unset: `Export` writes one, in
            // any of five formats, rather than every answer about how a scan is
            // going carrying the whole of it.
            ..Default::default()
        }
    }

    /// How far along the scan is, in the schema's terms.
    pub fn progress(&self) -> proto::Progress {
        let (stage_done, stage_total) = match self.progress.counted() {
            Some((done, total)) => (Some(done), Some(total)),
            None => (None, None),
        };
        let (overall_done, overall_total) = match self.progress.overall() {
            Some((done, total)) => (Some(done), Some(total)),
            None => (None, None),
        };

        proto::Progress {
            stage: convert::stage(self.progress.stage()) as i32,
            stage_done,
            stage_total,
            overall_done,
            overall_total,
        }
    }

    /// Every host as it now stands, as the events a client would have seen had
    /// it been watching from the start.
    ///
    /// All carrying the log's current mark rather than one of their own: they
    /// describe the scan as of that point, and a client resuming from it has
    /// missed nothing.
    pub fn snapshot(&self) -> Vec<proto::Event> {
        let seq = self.log.watermark();
        let options = ExportOptions::new().with_redaction(self.redaction);

        let mut caught_up: Vec<proto::Event> = self
            .hosts
            .snapshot()
            .iter()
            .filter_map(|host| {
                let document = serde_json::to_string(&HostDto::new(host, &options)).ok()?;

                Some(proto::Event {
                    seq,
                    body: Some(proto::event::Body::Host(proto::HostChanged {
                        address: host.scoped_ip().to_string(),
                        document,
                    })),
                })
            })
            .collect();

        // Where the scan stands, which a client starting here would otherwise
        // not learn until the next time it changed.
        caught_up.push(proto::Event {
            seq,
            body: Some(proto::event::Body::Progress(self.progress())),
        });

        caught_up
    }

    /// Everything after `cursor`, waiting for more if the scan is still running.
    ///
    /// Empty only when the scan is over and the cursor has reached the end,
    /// which is how a caller knows to stop asking.
    pub async fn after(&self, cursor: u64) -> Vec<proto::Event> {
        loop {
            let waiting = self.log.arrived.notified();

            let entries = self.log.after(cursor);
            if !entries.is_empty() || self.log.is_closed() {
                return entries;
            }

            waiting.await;
        }
    }

    /// Winds the scan down. What it has already found is kept.
    pub fn stop(&self) {
        self.handle.abort();
    }
}

/// Every scan this process is running or has run.
#[derive(Debug, Default)]
pub struct Scans {
    inner: Mutex<HashMap<String, Arc<Scan>>>,
    /// Where scans are written down, and `None` for a daemon that records
    /// nothing.
    root: Option<PathBuf>,
}

impl Scans {
    /// A registry that records its scans under `root`.
    ///
    /// `None` records nothing, which is a daemon whose scans die with it. That
    /// is a choice a caller makes rather than one this crate makes for them: a
    /// process with no writable place to record is still a process that can
    /// scan, and a test has no business writing into the operator's own journal
    /// directory.
    pub fn recording_in(root: Option<PathBuf>) -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            root,
        }
    }

    /// Starts a scan and files it under a name of its own.
    pub async fn start(&self, request: proto::StartRequest) -> Result<Arc<Scan>, Error> {
        let started = crate::start::scan(request, self.root.as_deref()).await?;
        let scan = Arc::new(started.scan);

        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(scan.id.clone(), scan.clone());

        follow(scan.clone(), started.events, started.task);

        Ok(scan)
    }

    /// The scans this daemon has a record of, newest first.
    ///
    /// Read off disk rather than out of memory, because what is in memory is
    /// only what this process happens to have started and the record covers
    /// every run that ever wrote one, this one's included. A daemon recording
    /// nothing has nothing to list; a client that started a scan there holds its
    /// name from the answer that started it.
    pub fn list(&self, limit: Option<u32>) -> Result<Vec<proto::ScanListing>, Error> {
        let Some(root) = self.root.as_deref() else {
            return Ok(Vec::new());
        };

        let mut entries = store::list(root).map_err(Error::engine)?;
        entries.sort_by_key(|entry| std::cmp::Reverse(entry.manifest.created_at));

        let limit = match limit {
            Some(0) | None => DEFAULT_LISTING,
            Some(limit) => usize::try_from(limit).unwrap_or(DEFAULT_LISTING),
        };

        Ok(entries.into_iter().take(limit).map(listing).collect())
    }

    /// Throws away the records this daemon no longer needs.
    ///
    /// A field left out keeps every record of that kind however old, and zero
    /// means older than no time at all, which is all of them. A record a running
    /// scan is using stays where it is and comes back in `kept`: it is not an
    /// error, and it will be prunable once that scan is done.
    pub fn prune(&self, asked: proto::PruneRequest) -> Result<proto::PruneResponse, Error> {
        let Some(root) = self.root.as_deref() else {
            return Ok(proto::PruneResponse::default());
        };

        let mut retention = Retention::keep_everything();
        retention.completed_for = asked
            .completed_after_seconds
            .map(|seconds| Duration::from_secs(u64::from(seconds)));
        retention.incomplete_for = asked
            .incomplete_after_seconds
            .map(|seconds| Duration::from_secs(u64::from(seconds)));

        let pruned = store::prune(root, &retention).map_err(Error::engine)?;

        Ok(proto::PruneResponse {
            removed: pruned.removed,
            kept: pruned
                .held
                .into_iter()
                .map(|held| proto::HeldRecord {
                    scan_id: held.id,
                    reason: held.reason,
                })
                .collect(),
        })
    }

    /// The scan named `id`, whether or not this process is the one running it.
    ///
    /// A scan still going is held here. One that is not is read back out of the
    /// journal the engine wrote while it ran, which is how a scan outlives the
    /// process that started it and how the same call answers for one that
    /// finished last week.
    pub fn get(&self, id: &str) -> Result<Found, Error> {
        let running = self
            .inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(id)
            .cloned();

        match running {
            Some(scan) => Ok(Found::Live(scan)),
            None => match self.root.as_deref() {
                Some(root) => Recorded::read(root, id).map(Found::Recorded),
                None => Err(Error::no_such_scan(id)),
            },
        }
    }
}

/// How many scans a listing that named no limit holds.
///
/// Enough that a person looking for one they ran this week finds it, and few
/// enough that a daemon with years of records does not answer with all of them.
const DEFAULT_LISTING: usize = 100;

/// A scan this process is running, or one it only has the record of.
#[derive(Debug, Clone)]
pub enum Found {
    /// Still going, or finished since this process started.
    Live(Arc<Scan>),
    /// Written down by some earlier run, and read back off disk.
    Recorded(Arc<Recorded>),
}

impl Found {
    /// Where the scan got to.
    pub fn state(&self) -> proto::ScanState {
        match self {
            Found::Live(scan) => scan.state(),
            Found::Recorded(recorded) => recorded.state(),
        }
    }

    /// Every host as it stands, and where the scan is.
    pub fn snapshot(&self) -> Vec<proto::Event> {
        match self {
            Found::Live(scan) => scan.snapshot(),
            Found::Recorded(recorded) => recorded.snapshot(),
        }
    }

    /// Whatever happened after `cursor`, waiting if there is more to come.
    pub async fn after(&self, cursor: u64) -> Vec<proto::Event> {
        match self {
            Found::Live(scan) => scan.after(cursor).await,
            // Nothing further will ever happen to a scan that is over.
            Found::Recorded(_) => Vec::new(),
        }
    }

    /// What the scan amounted to, or nothing while it is still going.
    pub fn report(&self) -> Option<ScanReport> {
        match self {
            Found::Live(scan) => scan.report(),
            Found::Recorded(recorded) => Some(recorded.report.clone()),
        }
    }

    /// The masking this scan's findings are handed out under.
    ///
    /// A scan read back off disk carries none: the journal keeps what was found
    /// rather than what a reader was allowed to see, so masking it is a decision
    /// made when it is written out rather than one already made.
    pub fn redaction(&self) -> Redaction {
        match self {
            Found::Live(scan) => scan.redaction,
            Found::Recorded(_) => Redaction::None,
        }
    }

    /// Winds the scan down, where there is anything left to wind down.
    pub fn stop(&self) {
        if let Found::Live(scan) = self {
            scan.stop();
        }
    }
}

/// One recorded scan, as much of it as can be said without reading the whole
/// record.
fn listing(entry: store::Entry) -> proto::ScanListing {
    let kind = convert::scan_kind(entry.kind()) as i32;
    let hold = convert::scan_hold(&entry.lock) as i32;
    let complete = entry.is_complete();
    let settled = entry.settled().and_then(|count| u64::try_from(count).ok());

    proto::ScanListing {
        scan_id: entry.manifest.id,
        kind,
        started_at: time::rfc3339(entry.manifest.created_at),
        summary: entry.manifest.summary,
        // Absent rather than clamped where the plan will not fit, which
        // describes a plan no run finishes.
        planned: u64::try_from(entry.manifest.total_targets).ok(),
        settled,
        complete,
        hold,
    }
}

/// A scan read back out of its journal.
///
/// Everything it found, and nothing about how it got there: the journal keeps
/// the findings rather than the order they arrived in, so this answers a watch
/// with one frame per host and then the end.
#[derive(Debug)]
pub struct Recorded {
    id: String,
    hosts: Vec<proto::Event>,
    report: ScanReport,
}

impl Recorded {
    /// Reads the scan named `id` off disk.
    fn read(root: &Path, id: &str) -> Result<Arc<Self>, Error> {
        let entries = store::list(root).map_err(Error::engine)?;

        let entry = entries
            .into_iter()
            .find(|entry| entry.manifest.id == id)
            .ok_or_else(|| Error::no_such_scan(id))?;

        let report = store::report(&entry.directory).map_err(Error::engine)?;
        let options = ExportOptions::new();

        let hosts = report
            .hosts()
            .enumerate()
            .filter_map(|(index, host)| {
                let document = serde_json::to_string(&HostDto::new(host, &options)).ok()?;

                Some(proto::Event {
                    seq: index as u64 + 1,
                    body: Some(proto::event::Body::Host(proto::HostChanged {
                        address: host.scoped_ip().to_string(),
                        document,
                    })),
                })
            })
            .collect::<Vec<_>>();

        Ok(Arc::new(Self {
            id: entry.manifest.id,
            hosts,
            report,
        }))
    }

    fn state(&self) -> proto::ScanState {
        proto::ScanState {
            scan_id: self.id.clone(),
            running: false,
            // The record keeps what the scan found rather than why it stopped,
            // so this build says nothing rather than guessing at `completed`.
            cause: None,
            progress: Some(proto::Progress {
                stage: proto::Stage::Finishing as i32,
                stage_done: None,
                stage_total: None,
                overall_done: None,
                overall_total: None,
            }),
            seq: self.hosts.len() as u64,
            ..Default::default()
        }
    }

    fn snapshot(&self) -> Vec<proto::Event> {
        self.hosts.clone()
    }
}

/// The one task that reads a scan's event stream.
///
/// It is the only consumer, so the engine's channel never has a slow reader to
/// drop events for. What it appends to the log is what a client eventually sees,
/// and it goes on until the scan ends whether or not anybody is watching.
fn follow(scan: Arc<Scan>, mut events: ScanEvents, task: ScanTask) {
    let log = scan.log.clone();
    let options = ExportOptions::new().with_redaction(scan.redaction);

    tokio::spawn(async move {
        let draining = async {
            while let Some(event) = events.recv().await {
                match event {
                    ScanEvent::HostUpdated(address) => {
                        let Some(host) = scan.hosts.get(&address) else {
                            continue;
                        };
                        let Ok(document) = serde_json::to_string(&HostDto::new(&host, &options))
                        else {
                            continue;
                        };

                        if log.changed(&address, &document) {
                            log.push(proto::event::Body::Host(proto::HostChanged {
                                address: address.to_string(),
                                document,
                            }));
                        }
                    }
                    ScanEvent::StageChanged { stage } => {
                        log.push(proto::event::Body::Stage(proto::StageChanged {
                            stage: convert::stage(stage) as i32,
                        }));
                        log.push(proto::event::Body::Progress(scan.progress()));
                    }
                    ScanEvent::ScannerFailed { scanner, reason } => {
                        log.push(proto::event::Body::Failure(proto::ScannerFailed {
                            // The variant's own name, which is the only name the
                            // engine gives a scanner kind.
                            scanner: format!("{scanner:?}"),
                            reason,
                        }));
                    }
                    // The gap is the notice and not the finding: the host it
                    // named is in the store, and the next thing that touches it
                    // writes its whole current state down.
                    ScanEvent::EventsDropped { .. } => {}
                    _ => {}
                }
            }
        };

        let (_, outcome) = tokio::join!(draining, task.join());

        if let Ok(finished) = &outcome {
            *scan.report.lock().unwrap_or_else(|e| e.into_inner()) = Some(finished.clone());
        }

        // A scan that ran to the end names no cause, and the schema says so out
        // loud rather than leaving a client to read an absent field.
        let cause = match &outcome {
            Ok(_) => convert::stop_cause(scan.handle.stopped()),
            Err(_) => proto::StopCause::Aborted,
        };

        log.push(proto::event::Body::Finished(proto::Finished {
            cause: cause as i32,
        }));
        log.close();
    });
}

/// What `start` hands back: the scan, and the two halves only the follower
/// needs.
pub struct Started {
    pub scan: Scan,
    pub events: ScanEvents,
    pub task: ScanTask,
}

impl Scan {
    /// Builds one, for `start` to hand over.
    pub(crate) fn new(
        id: String,
        hosts: HostStore,
        progress: Progress,
        handle: ScanHandle,
        redaction: Redaction,
    ) -> Self {
        Self {
            id,
            hosts,
            progress,
            handle,
            log: Arc::new(Log::default()),
            redaction,
            report: Mutex::new(None),
        }
    }

    /// The stage the scan is in, for a caller that wants only that.
    pub fn stage(&self) -> Stage {
        self.progress.stage()
    }

    /// What the scan amounted to, once there is such a thing.
    pub fn report(&self) -> Option<ScanReport> {
        self.report
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }
}

// ╔════════════════════════════════════════════╗
// ║ ████████╗███████╗███████╗████████╗███████╗ ║
// ║ ╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝██╔════╝ ║
// ║    ██║   █████╗  ███████╗   ██║   ███████╗ ║
// ║    ██║   ██╔══╝  ╚════██║   ██║   ╚════██║ ║
// ║    ██║   ███████╗███████║   ██║   ███████║ ║
// ║    ╚═╝   ╚══════╝╚══════╝   ╚═╝   ╚══════╝ ║
// ╚════════════════════════════════════════════╝

#[cfg(test)]
mod tests {
    use super::*;

    /// A scan of this machine's own loopback and three ports of it.
    ///
    /// Small enough to be over in well under a second, and it reaches nothing
    /// that is not already this process's own. `assume_up` skips the liveness
    /// pass, which on loopback would only be asking whether this machine is
    /// there.
    fn loopback() -> proto::StartRequest {
        proto::StartRequest {
            targets: vec!["127.0.0.1".into()],
            ports: Some("9,22,80".into()),
            service_detection: Some(proto::ServiceDetection::Off as i32),
            assume_up: Some(true),
            ..Default::default()
        }
    }

    /// A directory nothing else in this suite is recording into.
    fn somewhere() -> PathBuf {
        std::env::temp_dir().join(format!("zondd-journal-{}", crate::id::mint()))
    }

    /// Follows a scan to its end, or gives up rather than hanging the suite.
    async fn finished(scan: &Scan) {
        tokio::time::timeout(std::time::Duration::from_secs(120), async {
            let mut cursor = 0;
            loop {
                let events = scan.after(cursor).await;
                if events.is_empty() {
                    return;
                }
                cursor = events.last().map(|last| last.seq).unwrap_or(cursor);
            }
        })
        .await
        .expect("a scan of three loopback ports finishes");
    }

    /// A scan that has been written down is one a client can find again without
    /// having kept its name.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_recorded_scan_is_in_the_listing_with_what_it_was() {
        let root = somewhere();
        let scans = Scans::recording_in(Some(root.clone()));

        let scan = scans.start(loopback()).await.expect("a recorded scan");
        finished(&scan).await;

        let listed = scans.list(None).expect("a listing");
        let entry = listed
            .iter()
            .find(|entry| entry.scan_id == scan.id)
            .unwrap_or_else(|| panic!("{} is not in {listed:?}", scan.id));

        assert_eq!(entry.kind, proto::ScanKind::PortScan as i32, "a port scan");
        assert!(entry.complete, "it reached the end of its plan");
        assert_eq!(entry.planned, Some(3), "three ports of one host");
        assert!(
            entry.started_at.starts_with("20"),
            "a time a person can read: {}",
            entry.started_at
        );
        assert!(!entry.summary.is_empty(), "and a word about what it was");

        std::fs::remove_dir_all(&root).ok();
    }

    /// Newest first, because the scan somebody is looking for is almost always
    /// the one they just ran.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_newest_scan_is_listed_first() {
        let root = somewhere();
        let scans = Scans::recording_in(Some(root.clone()));

        let first = scans.start(loopback()).await.expect("one scan");
        finished(&first).await;
        let second = scans.start(loopback()).await.expect("and a later one");
        finished(&second).await;

        let listed = scans.list(None).expect("a listing");
        assert_eq!(listed.len(), 2, "{listed:?}");
        assert_eq!(listed[0].scan_id, second.id, "the later one leads");

        let asked_for_one = scans.list(Some(1)).expect("a listing of one");
        assert_eq!(asked_for_one.len(), 1, "a limit is a limit");
        assert_eq!(asked_for_one[0].scan_id, second.id);

        std::fs::remove_dir_all(&root).ok();
    }

    /// A daemon recording nothing has nothing to list, and says so with an empty
    /// answer rather than going looking through somebody else's records.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_daemon_that_records_nothing_lists_nothing() {
        let scans = Scans::recording_in(None);
        let scan = scans.start(loopback()).await.expect("a scan all the same");

        assert!(scans.list(None).expect("an answer").is_empty());

        scan.stop();
    }

    /// A sweep of this machine's own loopback, which asks about addresses and
    /// never about ports.
    fn sweeping() -> proto::StartRequest {
        proto::StartRequest {
            targets: vec!["127.0.0.1".into()],
            kind: proto::ScanKind::Discovery as i32,
            ..Default::default()
        }
    }

    /// A sweep runs through the same registry, log and record a port scan does.
    ///
    /// The whole point of putting the kind on the request rather than writing a
    /// second daemon around it: everything downstream of the engine call is the
    /// same machinery, and this is the test that says so.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_sweep_runs_and_is_recorded_as_one() {
        let root = somewhere();
        let scans = Scans::recording_in(Some(root.clone()));

        let scan = scans.start(sweeping()).await.expect("a sweep");
        finished(&scan).await;

        let listed = scans.list(None).expect("a listing");
        let entry = listed
            .iter()
            .find(|entry| entry.scan_id == scan.id)
            .unwrap_or_else(|| panic!("{} is not in {listed:?}", scan.id));

        assert_eq!(
            entry.kind,
            proto::ScanKind::Discovery as i32,
            "recorded as the sweep it was, not as a port scan"
        );
        assert!(entry.summary.contains("address"), "{}", entry.summary);

        std::fs::remove_dir_all(&root).ok();
    }

    /// A sweep of nothing is refused before a packet leaves, exactly as a port
    /// scan of nothing is.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_sweep_of_nothing_is_refused() {
        let refused = Scans::recording_in(None)
            .start(proto::StartRequest {
                kind: proto::ScanKind::Discovery as i32,
                ..Default::default()
            })
            .await
            .expect_err("a sweep with nothing to sweep");

        assert_eq!(refused.code(), "request.no_targets");
    }

    /// A listen with no link named is refused, and told what it is missing.
    ///
    /// A listener asks nothing of anybody, so targets are not what it is short
    /// of and saying `no_targets` would send somebody looking in the wrong
    /// place.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_listen_with_no_link_is_refused_for_the_right_reason() {
        let refused = Scans::recording_in(None)
            .start(proto::StartRequest {
                kind: proto::ScanKind::Listen as i32,
                ..Default::default()
            })
            .await
            .expect_err("a listen on nothing");

        assert_eq!(refused.code(), "request.no_links");
        assert!(refused.message().contains("link"), "{refused}");
    }

    /// A link this host does not have is refused by name.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_link_this_host_does_not_have_is_refused() {
        let refused = Scans::recording_in(None)
            .start(proto::StartRequest {
                kind: proto::ScanKind::Listen as i32,
                links: vec!["not-an-interface".into()],
                ..Default::default()
            })
            .await
            .expect_err("a link nobody has");

        assert_eq!(refused.code(), "request.unknown_link");
    }

    /// Pruning with an age of nothing takes every finished record.
    #[tokio::test(flavor = "multi_thread")]
    async fn pruning_takes_the_records_it_was_told_to() {
        let root = somewhere();
        let scans = Scans::recording_in(Some(root.clone()));

        let scan = scans.start(loopback()).await.expect("a scan");
        finished(&scan).await;
        assert_eq!(scans.list(None).expect("a listing").len(), 1);

        // Nothing named, so nothing goes.
        let kept = scans
            .prune(proto::PruneRequest::default())
            .expect("a prune of nothing");
        assert!(kept.removed.is_empty(), "{kept:?}");
        assert_eq!(scans.list(None).expect("a listing").len(), 1);

        // Every finished record, however recent.
        let pruned = scans
            .prune(proto::PruneRequest {
                completed_after_seconds: Some(0),
                ..Default::default()
            })
            .expect("a prune");

        assert_eq!(pruned.removed, vec![scan.id.clone()], "{pruned:?}");
        assert!(
            scans.list(None).expect("a listing").is_empty(),
            "and the record is gone"
        );

        std::fs::remove_dir_all(&root).ok();
    }

    /// A whole scan, followed from a cursor to the end.
    ///
    /// What no smaller test can show: that a request starts a real scan, that
    /// the one reader numbers what the scan says, and that a follower is told
    /// the scan is over rather than waiting on it for ever.
    ///
    /// The bound is `tokio::time`, which reaches this build through the engine's
    /// own tokio. A scan that never finished would otherwise hang whoever ran
    /// the suite rather than failing in front of them.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_scan_runs_and_its_followers_are_told_when_it_ends() {
        let scans = Scans::default();
        let scan = scans
            .start(loopback())
            .await
            .expect("a scan of this machine's own loopback");

        assert_eq!(scan.id.len(), 13, "the scan is named: {}", scan.id);
        assert!(scan.state().running, "it has only just started");

        let followed = tokio::time::timeout(std::time::Duration::from_secs(120), async {
            let mut cursor = 0;
            let mut seen = Vec::new();

            loop {
                let events = scan.after(cursor).await;
                if events.is_empty() {
                    return seen;
                }

                for event in events {
                    assert!(event.seq > cursor, "the log only goes forwards");
                    cursor = event.seq;
                    seen.push(event);
                }
            }
        })
        .await
        .expect("a scan of three loopback ports finishes");

        assert!(
            matches!(
                followed.last().and_then(|last| last.body.as_ref()),
                Some(proto::event::Body::Finished(_))
            ),
            "the last thing a scan says is that it is over: {followed:?}"
        );

        let state = scan.state();
        assert!(!state.running, "and the state agrees");
        assert_eq!(
            state.cause,
            Some(proto::StopCause::Completed as i32),
            "it ran out of work rather than being stopped"
        );
        assert_eq!(state.seq, followed.len() as u64, "the log is what was read");
    }

    /// A follower that joins late is caught up rather than replayed to.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_late_follower_is_handed_what_is_true_now() {
        let scans = Scans::default();
        let scan = scans.start(loopback()).await.expect("a scan");

        // To the end, so there is a history to have missed.
        tokio::time::timeout(std::time::Duration::from_secs(120), async {
            let mut cursor = 0;
            while !scan.after(cursor).await.is_empty() {
                cursor = scan.state().seq;
            }
        })
        .await
        .expect("a scan of three loopback ports finishes");

        let snapshot = scan.snapshot();
        let mark = scan.state().seq;

        for event in &snapshot {
            assert_eq!(
                event.seq, mark,
                "a snapshot describes the scan as of one moment"
            );
        }

        assert!(
            matches!(
                snapshot.last().and_then(|last| last.body.as_ref()),
                Some(proto::event::Body::Progress(_))
            ),
            "a snapshot ends by saying where the scan is, so a client starting \
             here does not have to ask: {snapshot:?}"
        );

        assert!(
            scan.after(mark).await.is_empty(),
            "and there is nothing after it to catch up on"
        );
    }

    /// A scan outlives the process that ran it.
    ///
    /// The registry that reads it back knows nothing about it: a different
    /// instance over the same directory, which is what a daemon restarting is.
    /// What comes back is what the engine wrote down while the scan ran, so this
    /// covers the whole round trip rather than a cache.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_scan_is_read_back_after_the_process_that_ran_it_is_gone() {
        let root = std::env::temp_dir().join(format!("zondd-journal-{}", crate::id::mint()));
        let scans = Scans::recording_in(Some(root.clone()));

        let scan = scans.start(loopback()).await.expect("a recorded scan");
        let id = scan.id.clone();

        tokio::time::timeout(std::time::Duration::from_secs(120), async {
            let mut cursor = 0;
            loop {
                let events = scan.after(cursor).await;
                if events.is_empty() {
                    return;
                }
                cursor = events.last().map(|last| last.seq).unwrap_or(cursor);
            }
        })
        .await
        .expect("a scan of three loopback ports finishes");

        // Nothing of this scan in memory. Only what is on disk.
        let afterwards = Scans::recording_in(Some(root.clone()));
        let found = afterwards
            .get(&id)
            .unwrap_or_else(|refused| panic!("reading {id} back: {refused}"));

        let state = found.state();
        assert_eq!(state.scan_id, id);
        assert!(!state.running, "a scan read off disk is not running");
        assert!(
            !found.snapshot().is_empty(),
            "the hosts it found came back with it"
        );
        assert!(
            found.after(0).await.is_empty(),
            "and nothing further will ever happen to it"
        );

        std::fs::remove_dir_all(&root).ok();
    }

    /// A daemon told to record nothing says a scan it has forgotten is unknown,
    /// rather than going looking through somebody else's journals for it.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_daemon_that_records_nothing_has_nothing_to_read_back() {
        let scans = Scans::recording_in(None);
        let scan = scans.start(loopback()).await.expect("a scan all the same");

        assert!(
            Scans::recording_in(None).get(&scan.id).is_err(),
            "nothing was written down, so nothing is there"
        );

        scan.stop();
    }

    /// Two scans are two scans, each under its own name.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_scan_is_found_again_by_the_name_it_was_given() {
        let scans = Scans::default();
        let first = scans.start(loopback()).await.expect("one scan");
        let second = scans.start(loopback()).await.expect("and another");

        assert_ne!(first.id, second.id);
        assert_eq!(
            scans.get(&first.id).expect("filed").state().scan_id,
            first.id
        );
        assert!(scans.get("0000000000000").is_err(), "and no others");

        first.stop();
        second.stop();
    }
}
