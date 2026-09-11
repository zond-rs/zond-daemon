// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Daemon, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # The daemon as a program somebody pipes into
//!
//! Everything else tests the protocol in this process, where the streams are
//! pipes held open by the test itself. That misses the thing a client actually
//! does: start the program, write, close its end, and read.
//!
//! It missed it for real. Answers were written on a task of their own, and when
//! standard input closed the read loop returned, `main` returned after it, and
//! the process ended before the task had written anything. Every in-process test
//! passed, because in-process nothing was holding the writer but the task, and
//! the reader simply waited for it. A shell pipeline got silence.

use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};

/// Runs the daemon over a pipe, writing `requests` and closing the input.
fn piped(requests: &[&str]) -> Vec<String> {
    let mut child = Command::new(env!("CARGO_BIN_EXE_zondd"))
        .arg("--stdio")
        .arg("--no-journal")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("the daemon starts");

    {
        let asking = child.stdin.as_mut().expect("an input to write to");
        for request in requests {
            writeln!(asking, "{request}").expect("the pipe takes it");
        }
    }
    // Closed before a single frame is read, which is the whole point.
    drop(child.stdin.take());

    let frames = BufReader::new(child.stdout.take().expect("an output to read"))
        .lines()
        .map(|line| line.expect("frames are readable"))
        .collect();

    child.wait().expect("and it finishes");

    frames
}

/// A client that writes, closes its end and reads is answered.
///
/// Closing the input says there is nothing more to ask. It does not say the
/// answer to what was already asked should be thrown away, and a client with
/// nothing to hold a conversation about has no other way to behave.
#[test]
fn a_request_written_before_the_pipe_closes_is_still_answered() {
    let frames = piped(&[r#"{"id":1,"method":"detections"}"#]);

    assert_eq!(frames.len(), 1, "one question, one answer: {frames:?}");
    assert!(frames[0].contains("\"id\":1"), "{}", frames[0]);
    assert!(
        frames[0].contains("DETECTION_TIER_"),
        "and the corpus came with it: {:.120}",
        frames[0]
    );
}

/// Several questions asked at once are all answered.
#[test]
fn every_request_written_before_the_pipe_closes_is_answered() {
    let frames = piped(&[
        r#"{"id":1,"method":"detections"}"#,
        r#"{"id":2,"method":"list","params":{}}"#,
        r#"{"id":3,"method":"teleport"}"#,
    ]);

    assert_eq!(
        frames.len(),
        3,
        "three questions, three answers: {frames:?}"
    );

    for id in 1..=3 {
        assert!(
            frames
                .iter()
                .any(|frame| frame.contains(&format!("\"id\":{id}"))),
            "nothing answered {id}: {frames:?}"
        );
    }
}

/// Running it with neither transport says so and stops, rather than sitting
/// there having opened nothing.
#[test]
fn a_daemon_told_to_serve_nothing_says_so() {
    let ran = Command::new(env!("CARGO_BIN_EXE_zondd"))
        .output()
        .expect("the daemon starts");

    assert_eq!(ran.status.code(), Some(2), "it stops, and says it stopped");

    let said = String::from_utf8_lossy(&ran.stderr);
    assert!(said.contains("--stdio"), "{said}");
    assert!(said.contains("--listen"), "{said}");
}
