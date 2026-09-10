// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Daemon, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Compiles the protocol into Rust types.
//!
//! Through `protox` rather than `protoc`, so `cargo build` needs nothing
//! installed that cargo did not install. A build that depends on a system
//! protobuf compiler is a build that works on the machine it was written on;
//! `protox` is a compiler in the dependency tree like any other crate.
//!
//! Only the messages are generated here. The service is declared in the schema
//! and nothing generates stubs for it yet, because the first transport frames
//! the same messages over a pipe and has no use for them.

use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // The whole directory, so adding a file to the schema rebuilds without
    // anybody having to remember to name it here.
    println!("cargo:rerun-if-changed=proto");

    let descriptors = protox::compile(["zond/v1/scan.proto"], ["proto"])?;

    let out = PathBuf::from(std::env::var("OUT_DIR")?);
    prost_build::Config::new()
        .out_dir(&out)
        .compile_fds(descriptors)?;

    Ok(())
}
