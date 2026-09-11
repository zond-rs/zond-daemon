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

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use clap::Parser;

use zond_daemon::scans::Scans;

/// Drives Zond Engine scans over a wire protocol.
#[derive(Debug, Parser)]
#[command(name = "zondd", version, about, long_about = None)]
struct Args {
    /// Speak the protocol over standard input and output, one JSON object per
    /// line. For a client that starts the daemon itself.
    #[arg(long, conflicts_with = "listen")]
    stdio: bool,

    /// Serve the protocol on a unix socket at this path, for clients that
    /// cannot start the daemon themselves. Created readable and writable by the
    /// user running the daemon and by nobody else.
    #[arg(long, value_name = "PATH")]
    listen: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> ExitCode {
    let args = Args::parse();

    let scans = Arc::new(Scans::default());

    // Neither, rather than a default: a daemon that opens something unasked is a
    // daemon nobody asked for, and which of the two a caller wants is not
    // something to guess at.
    let served = match (&args.listen, args.stdio) {
        (Some(path), _) => zond_daemon::listen::serve(scans, path).await,
        (None, true) => zond_daemon::stdio::serve(scans).await,
        (None, false) => {
            eprintln!(
                "zondd serves the protocol one of two ways, and does neither until told which.\n\
                 \n\
                 \x20 zondd --stdio                  for a client that started this process\n\
                 \x20 zondd --listen /run/zond.sock  for a client that could not"
            );
            return ExitCode::from(2);
        }
    };

    match served {
        Ok(()) => ExitCode::SUCCESS,
        Err(broken) => {
            eprintln!("zondd: {broken}");
            ExitCode::FAILURE
        }
    }
}
