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

    /// Write scans down under this directory, so they outlive the process and
    /// can be read back by name. Defaults to this user's own journal directory.
    #[arg(long, value_name = "PATH")]
    journal_dir: Option<PathBuf>,

    /// Keep no record of the scans this daemon runs. They are then readable
    /// only for as long as it is running.
    #[arg(long, conflicts_with = "journal_dir")]
    no_journal: bool,

    /// Where scans may reach. Repeatable, in the engine's own address grammar:
    /// `10.0.0.0/8`, `192.0.2.1-50`, a single address. Naming none permits
    /// anywhere.
    #[arg(long, value_name = "RANGE")]
    allow: Vec<String>,

    /// Where scans may not reach, whatever `--allow` says. Repeatable, in the
    /// same grammar.
    #[arg(long, value_name = "RANGE")]
    deny: Vec<String>,

    /// Write every scan started and every request refused to this file, one
    /// JSON object per line. A scan that cannot be written down is refused.
    #[arg(long, value_name = "PATH")]
    audit: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> ExitCode {
    let args = Args::parse();

    let root = if args.no_journal {
        None
    } else {
        args.journal_dir
            .clone()
            .or_else(zond_engine::journal::paths::root)
    };

    if root.is_none() && !args.no_journal {
        eprintln!(
            "zondd: nowhere to write scans down, so none will outlive this process.\n\
             Name a directory with --journal-dir, or say --no-journal to mean it."
        );
    }

    let scope = match zond_daemon::scope::Scope::read(&args.allow, &args.deny) {
        Ok(scope) => scope,
        Err(refused) => {
            eprintln!("zondd: {refused}");
            return ExitCode::from(2);
        }
    };

    // Opened before a single scan runs, so a path nobody can write to is a
    // mistake found now rather than at the first thing worth recording.
    let audit = match &args.audit {
        None => zond_daemon::audit::Audit::none(),
        Some(path) => match zond_daemon::audit::Audit::appending_to(path) {
            Ok(audit) => audit,
            Err(broken) => {
                eprintln!("zondd: {} cannot be written to: {broken}", path.display());
                return ExitCode::from(2);
            }
        },
    };

    if scope.is_bounded() {
        eprintln!("zondd: scans are bounded by the ranges named on the command line");
    }

    let scans = Arc::new(Scans::recording_in(root).within(scope).auditing(audit));

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
