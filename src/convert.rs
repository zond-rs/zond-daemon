// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Daemon, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Between the engine's vocabulary and the schema's
//!
//! One function per thing both sides name, written by hand rather than derived.
//! The schema outlives any one build of the engine, and a derived mapping would
//! rename a protocol field the day somebody renamed a Rust variant. This is the
//! same boundary the engine draws for its own settings file, drawn from the
//! other side.
//!
//! Every mapping here is covered by a test that walks the engine's own list of
//! values, so a variant added upstream fails the build here rather than reaching
//! a client as a number nothing can name.

use zond_engine::Stage;
use zond_engine::scanner::handle::StopCause;

use crate::proto;

/// The schema's name for an engine stage.
pub fn stage(stage: Stage) -> proto::Stage {
    match stage {
        Stage::Discovery => proto::Stage::Discovery,
        Stage::Ports => proto::Stage::Ports,
        Stage::Services => proto::Stage::Services,
        Stage::Detections => proto::Stage::Detections,
        Stage::Tls => proto::Stage::Tls,
        Stage::Os => proto::Stage::Os,
        Stage::Traceroute => proto::Stage::Traceroute,
        Stage::Listening => proto::Stage::Listening,
        Stage::Finishing => proto::Stage::Finishing,
        // The engine's enum is non-exhaustive, so a build against a newer one
        // than this schema knows compiles. The conformance test below is what
        // keeps that from being how a new stage ships.
        _ => proto::Stage::Unspecified,
    }
}

/// The schema's name for why a scan stopped.
///
/// The engine reports nothing at all for a scan that ran out of work, since
/// there is no cause to name. The schema says so out loud instead, because a
/// client reading an absent field cannot tell "finished" from "the server did
/// not say".
pub fn stop_cause(cause: Option<StopCause>) -> proto::StopCause {
    match cause {
        None => proto::StopCause::Completed,
        Some(StopCause::Aborted) => proto::StopCause::Aborted,
        Some(StopCause::TimedOut) => proto::StopCause::TimedOut,
        _ => proto::StopCause::Unspecified,
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

    /// Every stage the engine can report has a name in the schema.
    ///
    /// This is the test the whole repository exists to make possible. A stage
    /// added to the engine and not to the schema would reach a client as
    /// `STAGE_UNSPECIFIED`, which says the server knows something it cannot tell
    /// anybody. Failing here means somebody has to open the schema, which is
    /// exactly where the decision belongs.
    #[test]
    fn every_stage_the_engine_reports_has_a_name_in_the_schema() {
        for known in Stage::ALL {
            assert_ne!(
                stage(known),
                proto::Stage::Unspecified,
                "the engine reports {known} and the schema has no name for it"
            );
        }
    }

    /// No two stages share a name.
    ///
    /// A mapping that sent two stages to one value would pass the test above
    /// while telling a client that detections and traceroute are the same work.
    #[test]
    fn no_two_stages_answer_to_the_same_name() {
        let mut named: Vec<i32> = Stage::ALL.iter().map(|s| stage(*s) as i32).collect();
        let before = named.len();
        named.sort_unstable();
        named.dedup();

        assert_eq!(
            named.len(),
            before,
            "two stages share one name in the schema"
        );
    }

    /// A scan that simply finished says so, rather than saying nothing.
    #[test]
    fn a_scan_that_ran_out_of_work_is_named_completed() {
        assert_eq!(stop_cause(None), proto::StopCause::Completed);
        assert_eq!(
            stop_cause(Some(StopCause::Aborted)),
            proto::StopCause::Aborted
        );
        assert_eq!(
            stop_cause(Some(StopCause::TimedOut)),
            proto::StopCause::TimedOut
        );
    }
}
