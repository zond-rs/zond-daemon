// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Daemon, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # A record of what was asked for, and what was allowed
//!
//! A scan is a thing done to somebody else's machine. An operator running this
//! for other people needs to be able to say afterwards what was asked for, what
//! ran, and what was turned down, and that record is worth nothing if the thing
//! it records can decide not to write it.
//!
//! So it fails closed. Where an audit log is configured and cannot be written,
//! the scan is refused. A scan that happened with no record of it is the one
//! outcome an audit exists to prevent, and a disk that filled is a thing an
//! operator can fix, where a scan nobody can account for is not.
//!
//! Not configured is not an audit. A daemon told nothing writes nothing and
//! refuses nothing, which is what somebody running one on their own machine
//! wants and what every other scanner does.
//!
//! One JSON object per line, so a line is complete or absent and a file cut off
//! part way through is still every entry before the cut.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::sync::Mutex;
use std::time::SystemTime;

use serde_json::json;
use zond_engine::format::time;

use crate::error::Error;

/// Where decisions are written down, if anywhere.
#[derive(Debug, Default)]
pub struct Audit {
    to: Option<Mutex<File>>,
}

impl Audit {
    /// An audit that records nothing and permits everything.
    pub fn none() -> Self {
        Self::default()
    }

    /// Appends to the file at `path`, making it if it is not there.
    ///
    /// Opened once, when the daemon starts, so a path nobody can write to is a
    /// mistake found before a single scan rather than at the first one.
    pub fn appending_to(path: &Path) -> std::io::Result<Self> {
        let file = OpenOptions::new().create(true).append(true).open(path)?;

        Ok(Self {
            to: Some(Mutex::new(file)),
        })
    }

    /// Records that a scan started.
    pub fn started(&self, id: &str, kind: &str, targets: &[String]) -> Result<(), Error> {
        self.write(json!({
            "at": now(),
            "event": "started",
            "scan_id": id,
            "kind": kind,
            "targets": targets,
        }))
    }

    /// Records that a request was turned down, and why.
    ///
    /// Written before the refusal reaches the caller, so a client that keeps
    /// asking for something it is not allowed leaves a trail of having asked.
    pub fn refused(&self, refusal: &Error, kind: &str, targets: &[String]) -> Result<(), Error> {
        self.write(json!({
            "at": now(),
            "event": "refused",
            "kind": kind,
            "targets": targets,
            "code": refusal.code(),
            "detail": refusal.message(),
        }))
    }

    /// One line, flushed before the call returns.
    ///
    /// Flushed rather than left to the operating system, because the entry that
    /// matters most is the last one before something went wrong, and that is
    /// exactly the one a buffer loses.
    fn write(&self, entry: serde_json::Value) -> Result<(), Error> {
        let Some(to) = &self.to else {
            return Ok(());
        };

        let mut line = serde_json::to_vec(&entry).unwrap_or_default();
        line.push(b'\n');

        let mut file = to.lock().unwrap_or_else(|poisoned| poisoned.into_inner());

        file.write_all(&line)
            .and_then(|()| file.flush())
            .map_err(|broken| {
                Error::new(
                    "audit.unwritable",
                    format!("this scan was refused because it could not be written down: {broken}"),
                )
            })
    }
}

fn now() -> String {
    time::rfc3339(SystemTime::now())
}
