// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Daemon, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # The protocol over a pipe
//!
//! One JSON object per line, both ways. No port, no TLS, nothing to authenticate
//! against: whoever started the process is who is talking to it, which is the
//! whole security model and is the right one for a transport a program reaches
//! by spawning another program.
//!
//! ```text
//! → {"id":1,"method":"start","params":{"targets":["10.0.0.0/24"],"ports":"22,80"}}
//! ← {"id":1,"result":{"scan_id":"0GBQK4W7M8001"}}
//! → {"id":2,"method":"watch","params":{"scan_id":"0GBQK4W7M8001"}}
//! ← {"id":2,"event":{"seq":1,"host":{"address":"10.0.0.1","document":"{…}"}}}
//! ← {"id":2,"event":{"seq":2,"stage":{"stage":"STAGE_PORTS"}}}
//! ← {"id":2,"event":{"seq":3,"progress":{"stage":"STAGE_PORTS","overall_done":1,"overall_total":8}}}
//! ← {"id":2,"end":true}
//! ```
//!
//! ## Why not JSON-RPC
//!
//! Following a scan is the point of this protocol, and JSON-RPC has no frame for
//! a call that answers more than once. Modelling it as notifications would put
//! the work of matching a notification back to the call that asked for it into
//! every client. An `id` on every frame and an `end` when there will be no more
//! is smaller to implement on both sides than the thing it replaces.
//!
//! ## What a client may assume
//!
//! Frames carrying one `id` arrive in order. Frames carrying different ids do
//! not, and must not be relied on to: every request is answered on a task of its
//! own, so a `watch` that runs for the length of a scan holds nothing else up
//! and two scans can be started without the second waiting on the first.

use std::sync::Arc;

use serde_json::{Value, json};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::sync::Mutex;

use crate::error::Error;
use crate::proto;
use crate::scans::{Found, Scans};

/// Wherever frames go, which every task writing one has to take a turn at.
type Out<W> = Arc<Mutex<W>>;

/// One request from a client.
#[derive(serde::Deserialize)]
struct Request {
    /// Whatever the client wants its answers labelled with, echoed untouched.
    #[serde(default)]
    id: Value,
    method: String,
    #[serde(default)]
    params: Value,
}

/// Reads requests until the pipe closes.
///
/// A request is answered on a task of its own, so a `watch` that runs for the
/// length of a scan does not stop anything else being asked in the meantime.
pub async fn serve(scans: Arc<Scans>) -> std::io::Result<()> {
    speak(
        scans,
        BufReader::new(tokio::io::stdin()),
        tokio::io::stdout(),
    )
    .await
}

/// The same, over any pair of streams.
///
/// What `serve` is once its two ends are named. Written this way so the
/// protocol can be driven end to end by a test holding both ends of a pipe,
/// rather than only by a client holding a process.
pub async fn speak<R, W>(scans: Arc<Scans>, input: R, output: W) -> std::io::Result<()>
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let mut lines = input.lines();
    let out: Out<W> = Arc::new(Mutex::new(output));

    while let Some(line) = lines.next_line().await? {
        if line.trim().is_empty() {
            continue;
        }

        let request: Request = match serde_json::from_str(&line) {
            Ok(request) => request,
            Err(refused) => {
                // Nothing to label the answer with, the label being part of what
                // could not be read.
                frame(&out, json!({"id": Value::Null, "error": proto::Error::from(&Error::malformed(refused))})).await?;
                continue;
            }
        };

        let scans = scans.clone();
        let out = out.clone();
        tokio::spawn(async move {
            let _ = answer(&scans, &out, request).await;
        });
    }

    Ok(())
}

/// Answers one request, whatever it turns out to be.
async fn answer<W: AsyncWrite + Unpin>(
    scans: &Scans,
    out: &Out<W>,
    request: Request,
) -> std::io::Result<()> {
    let id = request.id;

    match request.method.as_str() {
        "start" => match start(scans, request.params).await {
            Ok(result) => frame(out, json!({"id": id, "result": result})).await,
            Err(refused) => fail(out, id, &refused).await,
        },
        "get" => match named(scans, request.params).map(|scan| scan.state()) {
            Ok(state) => frame(out, json!({"id": id, "result": state})).await,
            Err(refused) => fail(out, id, &refused).await,
        },
        "stop" => match named(scans, request.params) {
            Ok(scan) => {
                scan.stop();
                frame(out, json!({"id": id, "result": scan.state()})).await
            }
            Err(refused) => fail(out, id, &refused).await,
        },
        "resume" => match resume(scans, request.params).await {
            Ok(started) => frame(out, json!({"id": id, "result": started})).await,
            Err(refused) => fail(out, id, &refused).await,
        },
        "diff" => match difference(scans, request.params) {
            Ok(compared) => frame(out, json!({"id": id, "result": compared})).await,
            Err(refused) => fail(out, id, &refused).await,
        },
        "merge" => match folded(scans, request.params) {
            Ok(written) => frame(out, json!({"id": id, "result": written})).await,
            Err(refused) => fail(out, id, &refused).await,
        },
        "prune" => match prune(scans, request.params) {
            Ok(pruned) => frame(out, json!({"id": id, "result": pruned})).await,
            Err(refused) => fail(out, id, &refused).await,
        },
        "list" => match list(scans, request.params) {
            Ok(listing) => frame(out, json!({"id": id, "result": listing})).await,
            Err(refused) => fail(out, id, &refused).await,
        },
        "export" => match export(scans, request.params) {
            Ok(written) => frame(out, json!({"id": id, "result": written})).await,
            Err(refused) => fail(out, id, &refused).await,
        },
        "watch" => watch(scans, out, id, request.params).await,
        other => {
            let refused = Error::no_such_method(other);
            fail(out, id, &refused).await
        }
    }
}

/// Starts a scan and answers with its name.
async fn start(scans: &Scans, params: Value) -> Result<proto::StartResponse, Error> {
    let request: proto::StartRequest = serde_json::from_value(params).map_err(Error::malformed)?;
    let scan = scans.start(request).await?;

    Ok(proto::StartResponse {
        scan_id: scan.id.clone(),
    })
}

/// Continues a scan that stopped part way.
async fn resume(scans: &Scans, params: Value) -> Result<proto::StartResponse, Error> {
    let asked: proto::ResumeRequest = serde_json::from_value(params).map_err(Error::malformed)?;
    let scan = scans.resume(&asked.scan_id).await?;

    Ok(proto::StartResponse {
        scan_id: scan.id.clone(),
    })
}

/// What changed between two scans.
fn difference(scans: &Scans, params: Value) -> Result<proto::DiffResponse, Error> {
    let asked: proto::DiffRequest = serde_json::from_value(params).map_err(Error::malformed)?;

    let baseline = finished(scans, &asked.baseline_id)?;
    let current = finished(scans, &asked.current_id)?;
    let format = crate::export::compared(asked.format);

    Ok(proto::DiffResponse {
        document: crate::export::comparison(&baseline, &current, format)?,
        format: format as i32,
    })
}

/// Several scans folded into one report.
fn folded(scans: &Scans, params: Value) -> Result<proto::ExportResponse, Error> {
    let asked: proto::MergeRequest = serde_json::from_value(params).map_err(Error::malformed)?;

    if asked.scan_ids.len() < 2 {
        return Err(Error::new(
            "request.too_few_scans",
            "folding takes two scans or more; one scan is already a report",
        ));
    }

    let mut reports = Vec::with_capacity(asked.scan_ids.len());
    for id in &asked.scan_ids {
        reports.push((id.clone(), finished(scans, id)?));
    }

    let one = crate::export::folded(reports);
    let format = crate::export::named(asked.format);

    let redaction = if asked.redact.unwrap_or_default() {
        zond_engine::export::Redaction::Standard
    } else {
        zond_engine::export::Redaction::None
    };

    Ok(proto::ExportResponse {
        document: crate::export::document(&one, format, redaction)?,
        format: format as i32,
    })
}

/// A scan's report, for the calls that only make sense once it is over.
fn finished(scans: &Scans, id: &str) -> Result<zond_engine::ScanReport, Error> {
    scans.get(id)?.report().ok_or_else(|| {
        Error::new(
            "scan.still_running",
            format!("{id} has not finished, so there is nothing to read from it yet."),
        )
    })
}

/// Throws away the records nobody asked to keep.
fn prune(scans: &Scans, params: Value) -> Result<proto::PruneResponse, Error> {
    let asked: proto::PruneRequest = serde_json::from_value(params).map_err(Error::malformed)?;

    scans.prune(asked)
}

/// The scans this daemon has a record of.
fn list(scans: &Scans, params: Value) -> Result<proto::ListResponse, Error> {
    let asked: proto::ListRequest = serde_json::from_value(params).map_err(Error::malformed)?;

    Ok(proto::ListResponse {
        scans: scans.list(asked.limit)?,
    })
}

/// Writes a finished scan down in whichever format was asked for.
fn export(scans: &Scans, params: Value) -> Result<proto::ExportResponse, Error> {
    let asked: proto::ExportRequest = serde_json::from_value(params).map_err(Error::malformed)?;
    let found = scans.get(&asked.scan_id)?;

    let report = found.report().ok_or_else(|| {
        Error::new(
            "scan.still_running",
            format!(
                "{} has not finished, so there is nothing to write down yet. Watch it instead.",
                asked.scan_id
            ),
        )
    })?;

    // Asked for here, or already decided for the scan. A caller that wants one
    // reader to see less than another says so per export rather than per scan.
    let redaction = if asked.redact.unwrap_or_default() {
        zond_engine::export::Redaction::Standard
    } else {
        found.redaction()
    };

    let format = crate::export::named(asked.format);

    Ok(proto::ExportResponse {
        document: crate::export::document(&report, format, redaction)?,
        format: format as i32,
    })
}

/// The scan a request named.
fn named(scans: &Scans, params: Value) -> Result<Found, Error> {
    let asked: proto::GetRequest = serde_json::from_value(params).map_err(Error::malformed)?;

    scans.get(&asked.scan_id)
}

/// Follows a scan until it ends or the client goes away.
///
/// A cursor of nothing is answered with every host as it now stands before the
/// tail begins, so a client that opened the scan late sees what it missed as one
/// frame per host rather than as the whole history of how each got that way.
async fn watch<W: AsyncWrite + Unpin>(
    scans: &Scans,
    out: &Out<W>,
    id: Value,
    params: Value,
) -> std::io::Result<()> {
    let asked: proto::WatchRequest = match serde_json::from_value(params) {
        Ok(asked) => asked,
        Err(refused) => return fail(out, id, &Error::malformed(refused)).await,
    };

    let scan = match scans.get(&asked.scan_id) {
        Ok(scan) => scan,
        Err(refused) => return fail(out, id, &refused).await,
    };

    let mut cursor = asked.from_seq;

    if cursor == 0 {
        let caught_up = scan.snapshot();

        // Forward to where the snapshot describes the scan as of, or the tail
        // below starts at the beginning of the log and says everything the
        // snapshot just said a second time.
        if let Some(last) = caught_up.last() {
            cursor = last.seq;
        }

        for event in caught_up {
            frame(out, json!({"id": id, "event": event})).await?;
        }
    }

    loop {
        let events = scan.after(cursor).await;
        if events.is_empty() {
            break;
        }

        for event in events {
            cursor = cursor.max(event.seq);
            frame(out, json!({"id": id, "event": event})).await?;
        }
    }

    frame(out, json!({"id": id, "end": true})).await
}

/// Writes one frame, whole, on a line of its own.
///
/// The lock is held across the write rather than around a buffer handed off,
/// because two tasks each writing half a line is a stream no reader can split.
async fn frame<W: AsyncWrite + Unpin>(out: &Out<W>, value: Value) -> std::io::Result<()> {
    let mut line = serde_json::to_vec(&value).unwrap_or_else(|_| b"{}".to_vec());
    line.push(b'\n');

    let mut out = out.lock().await;
    out.write_all(&line).await?;
    out.flush().await
}

/// Writes the frame that says why not.
async fn fail<W: AsyncWrite + Unpin>(
    out: &Out<W>,
    id: Value,
    refused: &Error,
) -> std::io::Result<()> {
    frame(out, json!({"id": id, "error": proto::Error::from(refused)})).await
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

    use tokio::io::AsyncBufReadExt;

    /// Drives the protocol over a pipe and collects every frame it writes.
    ///
    /// Two one-way pipes rather than one duplex split in half: splitting shares
    /// the stream, so dropping the writing end signals nothing and the server
    /// waits for input that will never come. Reading runs alongside the server
    /// rather than after it, so a server writing more than a buffer holds is not
    /// waiting on a reader that has not started.
    async fn exchange_raw(asked: &[u8]) -> Vec<Value> {
        let (mut to_server, server_reads) = tokio::io::duplex(64 * 1024);
        let (server_writes, from_server) = tokio::io::duplex(64 * 1024);

        to_server.write_all(asked).await.expect("the pipe takes it");
        // How a client says it has finished asking.
        drop(to_server);

        let collecting = async {
            let mut frames = Vec::new();
            let mut lines = BufReader::new(from_server).lines();

            while let Some(line) = lines.next_line().await.expect("frames are readable") {
                frames.push(serde_json::from_str(&line).expect("every frame is one object"));
            }

            frames
        };

        let serving = speak(
            Arc::new(Scans::default()),
            BufReader::new(server_reads),
            server_writes,
        );

        let (frames, served) = tokio::join!(collecting, serving);
        served.expect("the protocol runs to the end of its input");

        frames
    }

    /// The same, for requests that are requests.
    async fn exchange(asked: &[Value]) -> Vec<Value> {
        let mut bytes = Vec::new();

        for line in asked {
            bytes.extend(serde_json::to_vec(line).expect("a request is writable"));
            bytes.push(b'\n');
        }

        exchange_raw(&bytes).await
    }

    /// A client that keeps its connection open, so it can ask, read the answer,
    /// and ask again.
    ///
    /// What `exchange` cannot do: every request there is written before any
    /// answer is read, so nothing can name a scan the first request only just
    /// created.
    struct Client {
        writing: tokio::io::DuplexStream,
        lines: tokio::io::Lines<BufReader<tokio::io::DuplexStream>>,
    }

    impl Client {
        fn connect(scans: Arc<Scans>) -> Self {
            let (writing, server_reads) = tokio::io::duplex(1 << 20);
            let (server_writes, from_server) = tokio::io::duplex(1 << 20);

            tokio::spawn(speak(scans, BufReader::new(server_reads), server_writes));

            Self {
                writing,
                lines: BufReader::new(from_server).lines(),
            }
        }

        async fn send(&mut self, request: Value) {
            let mut bytes = serde_json::to_vec(&request).expect("a request is writable");
            bytes.push(b'\n');

            self.writing
                .write_all(&bytes)
                .await
                .expect("the pipe takes it");
        }

        async fn next(&mut self) -> Value {
            let line = self
                .lines
                .next_line()
                .await
                .expect("frames are readable")
                .expect("the daemon said something");

            serde_json::from_str(&line).expect("and it is a frame")
        }
    }

    /// Watching from the beginning says each host once, not twice.
    ///
    /// A watch from nothing answers with a snapshot and then the live tail, and
    /// the tail has to begin where the snapshot left off. Starting it at the top
    /// of the log instead says everything the snapshot just said a second time,
    /// which a client reading events as news would count as findings arriving
    /// twice.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_watch_from_the_beginning_does_not_say_everything_twice() {
        let mut client = Client::connect(Arc::new(Scans::recording_in(None)));

        client
            .send(json!({
                "id": 1,
                "method": "start",
                "params": {
                    "targets": ["127.0.0.1"],
                    "ports": "9,22",
                    "assume_up": true,
                    "service_detection": "SERVICE_DETECTION_OFF"
                }
            }))
            .await;

        let started = client.next().await;
        let id = started["result"]["scan_id"]
            .as_str()
            .unwrap_or_else(|| panic!("a scan was named: {started}"))
            .to_string();

        // Watched only once there is a history to have missed. A watch opened
        // before the scan has said anything has an empty snapshot, and an empty
        // snapshot cannot be repeated.
        loop {
            client
                .send(json!({"id": 9, "method": "get", "params": {"scan_id": id}}))
                .await;

            if client.next().await["result"]["running"] == json!(false) {
                break;
            }
        }

        client
            .send(json!({"id": 2, "method": "watch", "params": {"scan_id": id, "from_seq": 0}}))
            .await;

        // Never backwards. The snapshot is stamped with the mark it describes
        // the scan as of, and with the cursor left at nothing the tail would
        // start at the top of the log and step back behind it.
        let mut seen = Vec::new();
        let mut furthest = 0;

        loop {
            let frame = client.next().await;
            if frame["end"] == json!(true) {
                break;
            }

            let seq = frame["event"]["seq"]
                .as_u64()
                .unwrap_or_else(|| panic!("every event is numbered: {frame}"));

            assert!(
                seq >= furthest,
                "the tail went back to {seq} having already said {furthest}, so \
                 everything between them is said twice: {seen:?}"
            );

            furthest = seq;
            seen.push(seq);
        }

        assert!(!seen.is_empty(), "a scan that said nothing at all");
    }

    /// Runs one more scan of loopback to the end on a client already connected.
    async fn one_more(client: &mut Client, id: u32) -> String {
        client
            .send(json!({
                "id": id,
                "method": "start",
                "params": {
                    "targets": ["127.0.0.1"],
                    "ports": "9,22",
                    "assume_up": true,
                    "service_detection": "SERVICE_DETECTION_OFF"
                }
            }))
            .await;

        let started = client.next().await;
        let name = started["result"]["scan_id"]
            .as_str()
            .unwrap_or_else(|| panic!("a scan was named: {started}"))
            .to_string();

        loop {
            client
                .send(json!({"id": 99, "method": "get", "params": {"scan_id": name}}))
                .await;

            if client.next().await["result"]["running"] == json!(false) {
                return name;
            }
        }
    }

    /// What changed between two scans, in both the shapes a comparison has.
    #[tokio::test(flavor = "multi_thread")]
    async fn two_scans_are_compared_in_either_shape() {
        let mut client = Client::connect(Arc::new(Scans::recording_in(None)));
        let before = one_more(&mut client, 1).await;
        let after = one_more(&mut client, 2).await;

        for (format, mark) in [("DIFF_FORMAT_JSON", "{"), ("DIFF_FORMAT_HTML", "<")] {
            client
                .send(json!({
                    "id": 3,
                    "method": "diff",
                    "params": {"baseline_id": before, "current_id": after, "format": format}
                }))
                .await;

            let compared = client.next().await;
            let document = compared["result"]["document"]
                .as_str()
                .unwrap_or_else(|| panic!("{format} compared nothing: {compared}"));

            assert!(document.starts_with(mark), "{format}: {document:.80}");
            assert_eq!(compared["result"]["format"], format);
        }
    }

    /// Two scans folded into one report, which is a report and writes like one.
    #[tokio::test(flavor = "multi_thread")]
    async fn scans_are_folded_into_one_report() {
        let mut client = Client::connect(Arc::new(Scans::recording_in(None)));
        let first = one_more(&mut client, 1).await;
        let second = one_more(&mut client, 2).await;

        client
            .send(json!({
                "id": 3,
                "method": "merge",
                "params": {"scan_ids": [first, second], "format": "EXPORT_FORMAT_JSON"}
            }))
            .await;

        let folded = client.next().await;
        let document = folded["result"]["document"]
            .as_str()
            .unwrap_or_else(|| panic!("nothing was folded: {folded}"));

        let read: Value = serde_json::from_str(document).expect("a report");
        assert!(read["hosts"].is_array(), "and it is one: {document:.120}");
    }

    /// One scan is already a report, so folding asks for two.
    #[tokio::test(flavor = "multi_thread")]
    async fn folding_one_scan_is_refused() {
        let mut client = Client::connect(Arc::new(Scans::recording_in(None)));
        let only = one_more(&mut client, 1).await;

        client
            .send(json!({"id": 2, "method": "merge", "params": {"scan_ids": [only]}}))
            .await;

        let refused = client.next().await;
        assert_eq!(
            refused["error"]["code"], "request.too_few_scans",
            "{refused}"
        );
    }

    /// Runs a scan of loopback to the end and hands back a client and its name.
    async fn a_finished_scan() -> (Client, String) {
        let mut client = Client::connect(Arc::new(Scans::recording_in(None)));

        client
            .send(json!({
                "id": 1,
                "method": "start",
                "params": {
                    "targets": ["127.0.0.1"],
                    "ports": "9,22",
                    "assume_up": true,
                    "service_detection": "SERVICE_DETECTION_OFF"
                }
            }))
            .await;

        let started = client.next().await;
        let id = started["result"]["scan_id"]
            .as_str()
            .unwrap_or_else(|| panic!("a scan was named: {started}"))
            .to_string();

        loop {
            client
                .send(json!({"id": 9, "method": "get", "params": {"scan_id": id}}))
                .await;

            if client.next().await["result"]["running"] == json!(false) {
                return (client, id);
            }
        }
    }

    /// Every format the schema names writes something a reader of that format
    /// would recognise.
    ///
    /// Not a check that the documents are right, which is the engine's own
    /// conformance suite's job. A check that the name on the wire reaches the
    /// writer somebody meant, so asking for CSV cannot quietly hand back JSON.
    #[tokio::test(flavor = "multi_thread")]
    async fn every_format_the_schema_names_writes_that_format() {
        let (mut client, id) = a_finished_scan().await;

        let recognised = [
            ("EXPORT_FORMAT_JSON", "\"hosts\""),
            ("EXPORT_FORMAT_JSONL", "{"),
            ("EXPORT_FORMAT_CSV", ","),
            ("EXPORT_FORMAT_HTML", "<"),
            ("EXPORT_FORMAT_NMAP_XML", "<nmaprun"),
        ];

        for (format, mark) in recognised {
            client
                .send(json!({
                    "id": 2,
                    "method": "export",
                    "params": {"scan_id": id, "format": format}
                }))
                .await;

            let written = client.next().await;
            let document = written["result"]["document"]
                .as_str()
                .unwrap_or_else(|| panic!("{format} wrote nothing: {written}"));

            assert!(
                document.contains(mark),
                "{format} does not look like {format}: {}",
                &document[..document.len().min(120)]
            );
            assert_eq!(
                written["result"]["format"], format,
                "the answer says what it wrote"
            );
        }
    }

    /// A caller who named no format gets the one that carries everything.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_caller_who_names_no_format_is_written_json() {
        let (mut client, id) = a_finished_scan().await;

        client
            .send(json!({"id": 2, "method": "export", "params": {"scan_id": id}}))
            .await;

        let written = client.next().await;
        assert_eq!(
            written["result"]["format"], "EXPORT_FORMAT_JSON",
            "{written}"
        );

        let document = written["result"]["document"].as_str().expect("a document");
        serde_json::from_str::<Value>(document).expect("and it is JSON");
    }

    /// A scan still going has nothing written down yet, and is told so rather
    /// than handed half a report.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_scan_that_has_not_finished_has_nothing_to_write_down() {
        let scans = Scans::recording_in(None);
        let scan = scans
            .start(proto::StartRequest {
                targets: vec!["127.0.0.1".into()],
                ports: Some("9".into()),
                assume_up: Some(true),
                ..Default::default()
            })
            .await
            .expect("a scan");

        assert!(
            scans
                .get(&scan.id)
                .expect("it is running")
                .report()
                .is_none(),
            "a scan that has only just started has amounted to nothing yet"
        );

        scan.stop();
    }

    /// A method nobody wrote is refused by name, under the id that asked.
    #[tokio::test]
    async fn a_method_this_build_does_not_have_is_refused_by_name() {
        let frames = exchange(&[json!({"id": 7, "method": "teleport"})]).await;

        assert_eq!(frames.len(), 1, "{frames:?}");
        assert_eq!(
            frames[0]["id"],
            json!(7),
            "the answer carries the question's id"
        );
        assert_eq!(frames[0]["error"]["code"], json!("rpc.unknown_method"));
        assert!(
            frames[0]["error"]["message"]
                .as_str()
                .is_some_and(|message| message.contains("teleport")),
            "{frames:?}"
        );
    }

    /// A line that is not a request at all is answered rather than dropped.
    ///
    /// Nothing to label the answer with, the label being part of what could not
    /// be read, so the id is null and the code says where the trouble was.
    #[tokio::test]
    async fn a_line_that_is_not_a_request_is_still_answered() {
        let frames = exchange_raw(b"not json at all\n").await;

        assert_eq!(frames[0]["id"], Value::Null, "{frames:?}");
        assert_eq!(frames[0]["error"]["code"], json!("rpc.malformed"));
    }

    /// Blank lines are nothing at all, not malformed requests.
    #[tokio::test]
    async fn a_blank_line_is_not_an_error() {
        let frames = exchange_raw(b"\n   \n").await;

        assert!(frames.is_empty(), "{frames:?}");
    }

    /// Asking about a scan nobody started says so.
    #[tokio::test]
    async fn a_name_no_scan_answers_to_is_refused() {
        let frames = exchange(&[json!({
            "id": "a",
            "method": "get",
            "params": {"scan_id": "0000000000000"}
        })])
        .await;

        assert_eq!(
            frames[0]["error"]["code"],
            json!("scan.unknown"),
            "{frames:?}"
        );
    }

    /// A request with no targets is refused before anything is sent.
    #[tokio::test]
    async fn a_scan_of_nothing_is_refused_before_a_packet_leaves() {
        let frames = exchange(&[json!({"id": 1, "method": "start", "params": {}})]).await;

        assert_eq!(
            frames[0]["error"]["code"],
            json!("request.no_targets"),
            "{frames:?}"
        );
    }

    /// A level the schema does not name is refused, and the message names it.
    ///
    /// A client built against a newer schema than this build knows has made a
    /// mistake it can act on, where a field quietly ignored would be a scan
    /// doing something other than what was asked.
    #[tokio::test]
    async fn a_level_the_schema_does_not_name_is_refused() {
        let frames = exchange(&[json!({
            "id": 1,
            "method": "start",
            "params": {"targets": ["127.0.0.1"], "service_detection": "SERVICE_DETECTION_PARANOID"}
        })])
        .await;

        assert_eq!(
            frames[0]["error"]["code"],
            json!("rpc.malformed"),
            "{frames:?}"
        );
        assert!(
            frames[0]["error"]["message"]
                .as_str()
                .is_some_and(|m| m.contains("SERVICE_DETECTION_PARANOID")),
            "{frames:?}"
        );
    }
}
