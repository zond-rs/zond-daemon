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
use crate::scans::Scans;

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

/// The scan a request named.
fn named(scans: &Scans, params: Value) -> Result<Arc<crate::scans::Scan>, Error> {
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
        for event in scan.snapshot() {
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
