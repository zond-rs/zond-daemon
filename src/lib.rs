// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Daemon, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Zond Engine, reachable from something that is not Rust
//!
//! The engine is a Rust library, so a front end written in anything else can
//! only reach it by going around it: spawning the command line tool and reading
//! output built for a person, or reading a journal off the filesystem of
//! whichever machine did the scanning. Neither shows a scan in progress, stops
//! one cleanly, or survives a page reload.
//!
//! This crate is the wire. One schema, and a process that speaks it.
//!
//! ## The schema is the product
//!
//! What makes a scanner turn up inside other people's software is not its
//! library, which only its own language can call. Nmap is everywhere because
//! its XML is read by tools nobody at nmap has heard of. So the artefact here
//! is `proto/zond/v1/scan.proto` rather than any of the Rust below it: the Rust
//! is one implementation of a contract, and a TypeScript or Go client generated
//! from the same file is another consumer of it on equal terms.
//!
//! `StartRequest` is the wire form of the engine's own
//! `import::request::ScanRequest`, field for field, so a request document
//! written for the engine's reader is a valid body here.
//!
//! ## One contract per thing
//!
//! Hosts and reports travel as the JSON that `zond-report-v1` already describes,
//! not as a second description of the same documents written in proto. That
//! schema is published, versioned, and held to the engine's output by a
//! conformance test. A proto mirror of it would be a second contract for one
//! document, and the two would disagree the first time either moved. A consumer
//! that wants types for a host generates them from that schema, the same way it
//! generates these messages from the proto.

pub mod convert;

/// The protocol, compiled from `proto/zond/v1/scan.proto`.
///
/// Generated at build time, so what is here is whatever the schema says. Read
/// the schema rather than this module: the comments that explain each field live
/// there, where every language's generated client can see them.
pub mod proto {
    #![allow(missing_docs)]

    include!(concat!(env!("OUT_DIR"), "/zond.v1.rs"));
}
