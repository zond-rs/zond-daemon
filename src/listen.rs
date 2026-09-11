// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Daemon, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # The same protocol, over a socket in the filesystem
//!
//! A pipe serves a client that can spawn the process. A container cannot: the
//! scanner needs the host's own network namespace and raw-socket capabilities,
//! and whatever serves a web page should have neither, so the two are separate
//! processes with a socket between them.
//!
//! A unix socket rather than a TCP port, and not by default. A scanner listening
//! on a network is a scanner anybody on that network can point at anything; a
//! socket in the filesystem is reached by whoever the filesystem says may reach
//! it, which is a question the operating system already answers well.
//!
//! ## Who may talk to it
//!
//! The socket is created readable and writable by its owner and nobody else.
//! That is the right default for a process that can put arbitrary packets on the
//! wire, and it is deliberately inconvenient: sharing it with another container
//! is something an operator does on purpose, by running both as the same user or
//! by widening the mode on the directory it sits in.
//!
//! Every connection is served by the same [`Scans`], so a scan started on one is
//! watched from another, and a client that drops its connection leaves the scan
//! running to be picked up again by name.

use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use tokio::io::BufReader;
use tokio::net::{UnixListener, UnixStream};

use crate::scans::Scans;
use crate::stdio::speak;

/// Only the user running the daemon.
const SOCKET_MODE: u32 = 0o600;

/// Serves the protocol on `path` until the process is told to stop.
pub async fn serve(scans: Arc<Scans>, path: &Path) -> io::Result<()> {
    let listener = bind(path)?;
    let _cleanup = Socket(path.to_path_buf());

    loop {
        let (stream, _) = listener.accept().await?;
        let scans = scans.clone();

        tokio::spawn(async move {
            let _ = converse(scans, stream).await;
        });
    }
}

/// One client, for as long as it stays.
async fn converse(scans: Arc<Scans>, stream: UnixStream) -> io::Result<()> {
    let (reading, writing) = stream.into_split();

    speak(scans, BufReader::new(reading), writing).await
}

/// Opens the socket, clearing one a dead process left behind.
///
/// A file already there is either a daemon that is running, which is a mistake
/// worth refusing, or one that is not, which is litter. Connecting to it is how
/// the two are told apart: a refused connection means nobody is listening, and
/// only then is the file removed.
fn bind(path: &Path) -> io::Result<UnixListener> {
    if path.exists() {
        match std::os::unix::net::UnixStream::connect(path) {
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::AddrInUse,
                    format!(
                        "{} is already being served by another zondd",
                        path.display()
                    ),
                ));
            }
            Err(_) => std::fs::remove_file(path)?,
        }
    }

    let listener = UnixListener::bind(path)?;

    // After the bind, because the path does not exist before it. A moment of a
    // wider mode, which is why the directory the socket sits in is the thing to
    // get right rather than this.
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(SOCKET_MODE))?;

    Ok(listener)
}

/// Takes the socket file away when the daemon stops holding it.
struct Socket(PathBuf);

impl Drop for Socket {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
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

    use std::time::Duration;

    use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
    use tokio::task::JoinHandle;

    /// A path nothing else in this suite is using.
    fn somewhere() -> PathBuf {
        std::env::temp_dir().join(format!("zondd-{}.sock", crate::id::mint()))
    }

    /// Starts a daemon and waits until it answers.
    ///
    /// Waits for a connection rather than for the path to exist. A socket a dead
    /// daemon left behind exists too, and so does the ordinary file one of these
    /// tests puts there on purpose, so the path appearing says nothing about
    /// whether anybody is listening on it yet.
    async fn listening(path: &Path) -> JoinHandle<io::Result<()>> {
        let serving = tokio::spawn({
            let path = path.to_path_buf();
            async move { serve(Arc::new(Scans::default()), &path).await }
        });

        for _ in 0..500 {
            if UnixStream::connect(path).await.is_ok() {
                return serving;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        panic!("the daemon never answered on {}", path.display());
    }

    /// Asks one question over a connection and reads the one answer.
    async fn ask(path: &Path, request: &str) -> serde_json::Value {
        let (reading, mut writing) = UnixStream::connect(path)
            .await
            .expect("the daemon is listening")
            .into_split();

        writing
            .write_all(format!("{request}\n").as_bytes())
            .await
            .expect("the socket takes it");

        let line = BufReader::new(reading)
            .lines()
            .next_line()
            .await
            .expect("readable")
            .expect("something was said");

        serde_json::from_str(&line).expect("and it is a frame")
    }

    /// A client on a socket is served what a client on a pipe is served.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_socket_carries_the_same_protocol_a_pipe_does() {
        let path = somewhere();
        let serving = listening(&path).await;

        let frame = ask(&path, r#"{"id":1,"method":"teleport"}"#).await;
        assert_eq!(frame["error"]["code"], "rpc.unknown_method", "{frame}");

        serving.abort();
    }

    /// Two clients, one registry: a scan started on one connection is found from
    /// another.
    ///
    /// The point of a socket rather than a pipe. A web tier with more than one
    /// request in flight is several connections, and a scan is not the property
    /// of whichever one happened to start it.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_scan_started_on_one_connection_is_found_from_another() {
        let path = somewhere();
        let serving = listening(&path).await;

        let started = ask(
            &path,
            r#"{"id":1,"method":"start","params":{"targets":["127.0.0.1"],"ports":"9","assume_up":true,"service_detection":"SERVICE_DETECTION_OFF"}}"#,
        )
        .await;
        let id = started["result"]["scan_id"]
            .as_str()
            .unwrap_or_else(|| panic!("a scan was named: {started}"));

        let found = ask(
            &path,
            &format!(r#"{{"id":2,"method":"get","params":{{"scan_id":"{id}"}}}}"#),
        )
        .await;
        assert_eq!(found["result"]["scan_id"], id, "{found}");

        serving.abort();
    }

    /// The socket is the daemon's own and nobody else's.
    ///
    /// This process can put arbitrary packets on the wire. A socket anybody
    /// local could open would hand that to every account on the machine, so
    /// sharing it is something an operator does on purpose rather than something
    /// that happens by default.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_socket_is_not_open_to_everybody_on_the_machine() {
        let path = somewhere();
        let serving = listening(&path).await;

        let mode = std::fs::metadata(&path)
            .expect("the socket is there")
            .permissions()
            .mode()
            & 0o777;

        assert_eq!(
            mode, SOCKET_MODE,
            "the socket is {mode:o}, not {SOCKET_MODE:o}"
        );

        serving.abort();
    }

    /// A socket a dead daemon left behind is litter, and is cleared.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_socket_nobody_is_listening_on_is_cleared_away() {
        let path = somewhere();
        std::fs::write(&path, b"").expect("something in the way");

        let serving = listening(&path).await;
        let frame = ask(&path, r#"{"id":1,"method":"teleport"}"#).await;

        assert_eq!(frame["error"]["code"], "rpc.unknown_method", "{frame}");

        serving.abort();
    }

    /// A socket somebody *is* listening on is not.
    ///
    /// Two daemons on one socket is one of them quietly answering half the
    /// requests, which is worse than the second refusing to start.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_socket_already_being_served_is_refused() {
        let path = somewhere();
        let serving = listening(&path).await;

        let refused = serve(Arc::new(Scans::default()), &path)
            .await
            .expect_err("a second daemon on one socket");

        assert_eq!(refused.kind(), io::ErrorKind::AddrInUse, "{refused}");
        assert!(
            refused.to_string().contains(&path.display().to_string()),
            "the refusal names the socket: {refused}"
        );

        serving.abort();
    }
}
