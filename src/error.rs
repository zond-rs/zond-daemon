// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Daemon, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Telling a client why it did not get what it asked for
//!
//! A code it branches on and a message a person reads, which is the split the
//! engine already makes: every error it hands back carries a stable name under
//! [`Coded`](zond_engine::Coded), and the wording of the message is free to
//! improve without breaking anybody.
//!
//! So almost nothing here is written by hand. An engine error keeps the engine's
//! own code, because a caller who asked for an impossible port range wants to
//! read `ports.invalid_range` rather than something this crate invented for it.

use std::fmt;

use zond_engine::Coded;

use crate::proto;

/// Why a call could not be answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error {
    code: String,
    message: String,
}

impl Error {
    /// An error this crate is the author of.
    ///
    /// The codes it makes up are the few the engine has no opinion about, being
    /// about the protocol rather than about scanning.
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
        }
    }

    /// An engine error, keeping the engine's own name for it.
    pub fn engine<E: Coded + fmt::Display>(error: E) -> Self {
        Self::new(error.code(), error.to_string())
    }

    /// A name no scan answers to.
    pub fn no_such_scan(id: &str) -> Self {
        Self::new("scan.unknown", format!("no scan is named {id}"))
    }

    /// A method this build does not have.
    pub fn no_such_method(method: &str) -> Self {
        Self::new("rpc.unknown_method", format!("no method named {method}"))
    }

    /// A frame that was not the shape the schema says.
    pub fn malformed(detail: impl fmt::Display) -> Self {
        Self::new("rpc.malformed", detail.to_string())
    }

    /// The stable name for what went wrong.
    pub fn code(&self) -> &str {
        &self.code
    }

    /// What to show a person.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl From<&Error> for proto::Error {
    fn from(error: &Error) -> Self {
        proto::Error {
            code: error.code.clone(),
            message: error.message.clone(),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for Error {}
