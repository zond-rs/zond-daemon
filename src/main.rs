// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Daemon, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The `zondd` binary.
//!
//! One transport so far, over a pipe. See `stdio` for what it speaks.

use std::process::ExitCode;
use std::sync::Arc;

use clap::Parser;

use zond_daemon::scans::Scans;

/// Drives Zond Engine scans over a wire protocol.
#[derive(Debug, Parser)]
#[command(name = "zondd", version, about, long_about = None)]
struct Args {
    /// Speak the protocol over standard input and output, one JSON object per
    /// line. The only transport this build has.
    #[arg(long)]
    stdio: bool,
}

#[tokio::main]
async fn main() -> ExitCode {
    let args = Args::parse();

    if !args.stdio {
        eprintln!(
            "zondd has one transport so far, and it is not the default because a \
             daemon that listens unasked is a daemon nobody asked for.\n\
             Run it as: zondd --stdio"
        );
        return ExitCode::from(2);
    }

    match zond_daemon::stdio::serve(Arc::new(Scans::default())).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(broken) => {
            eprintln!("zondd: {broken}");
            ExitCode::FAILURE
        }
    }
}
