// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Daemon, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # The one gate every scan goes through
//!
//! Where a scan may reach, and where that decision is written down. Both are
//! settings of the daemon rather than of a request, which is the point of them:
//! a client that has been taken over can ask for anything, and what it gets is
//! still what the operator allowed.
//!
//! ## The order matters and is the whole design
//!
//! 1. A slot is claimed among however many scans the daemon runs at once. A
//!    request arriving when there is none ends here, having read nothing.
//! 2. The targets are resolved, so what follows is judged on addresses rather
//!    than on the words a request named them with.
//! 3. The policy is applied to those addresses. A refusal is written down and
//!    the request ends here.
//! 4. The scan is recorded, which is what gives it a name.
//! 5. The start is written down, under that name.
//! 6. Only then does anything reach the wire.
//!
//! Five before six is what makes the audit worth having: a scan that could not
//! be written down does not happen. Three before four is what keeps a refused
//! request from leaving a record of a scan that never ran.
//!
//! Resolving once and judging that same answer is what keeps the check honest.
//! Resolving a second time to scan would leave a gap between the addresses that
//! were allowed and the addresses that were reached, and a name whose owner
//! changes what it points at in between is all it would take to walk through it.

use std::path::Path;

use zond_engine::model::ip::set::IpSet;
use zond_engine::model::target::TargetMap;

use crate::audit::Audit;
use crate::error::Error;
use crate::scope::Scope;

/// What bounds a scan, and where the bounding is written down.
#[derive(Debug, Clone, Copy)]
pub struct Policy<'a> {
    /// Where scans are written down, and `None` for a daemon recording none.
    pub root: Option<&'a Path>,
    pub scope: &'a Scope,
    pub audit: &'a Audit,
    /// Whether the daemon found room for this scan among however many it runs
    /// at once. Already true or false before the request was read.
    pub has_room: bool,
}

impl Policy<'_> {
    /// Refuses a scan this daemon has no room to run.
    ///
    /// A scan is work on somebody else's network and on this machine's
    /// interfaces, and a caller that asks for a thousand of them gets a
    /// thousand. That is the right answer for a person at a terminal, who is
    /// both the one asking and the one who pays for it, and the wrong one for a
    /// daemon behind a web page, where those are different people. So it is the
    /// operator's setting, like the scope, rather than the request's.
    ///
    /// The room was taken before the request was read, rather than counted when
    /// it was. Counting is what a client defeats by asking twice at once: two
    /// requests read together would both find the daemon idle and both start,
    /// and a client sending a hundred would start a hundred. So the slot is
    /// claimed first and given back when the scan it was claimed for ends, and
    /// what arrives here is the answer rather than the question.
    pub fn room(&self, kind: &str, targets: &[String]) -> Result<(), Error> {
        if self.has_room {
            return Ok(());
        }

        let refused = Error::at_capacity();
        self.audit.refused(&refused, kind, targets)?;

        Err(refused)
    }

    /// Judges a scan's addresses, and writes down a refusal.
    ///
    /// `targets` is what the request said rather than what it resolved to,
    /// because that is what somebody reading the log later will recognise: an
    /// entry naming three hundred addresses says less about what was attempted
    /// than one naming `internal.example`.
    pub fn permit(&self, reaching: &IpSet, kind: &str, targets: &[String]) -> Result<(), Error> {
        if let Err(refused) = self.scope.permits(reaching) {
            // Written first, so a client that keeps asking for what it may not
            // have leaves a trail of having asked. A log that cannot be written
            // is itself a refusal, and the one the caller is told about, since
            // it is the one the operator has to fix.
            self.audit.refused(&refused, kind, targets)?;

            return Err(refused);
        }

        Ok(())
    }

    /// Writes down that a scan is about to start.
    ///
    /// Before it starts. A scan that could not be written down does not happen,
    /// which is the whole of what an audit log promises.
    pub fn record(&self, id: &str, kind: &str, targets: &[String]) -> Result<(), Error> {
        self.audit.started(id, kind, targets)
    }
}

/// Every address a port scan will reach.
///
/// The union of its units' addresses, in ranges, so a plan of a `/8` costs what
/// a plan of one host does. Walking the targets to find this out is the one
/// thing a check standing in front of a scan must not do.
pub fn reached_by(map: &TargetMap) -> IpSet {
    let mut whole = IpSet::new();

    for unit in &map.units {
        for range in unit.ips().v4() {
            whole.push_v4_range(*range);
        }
        for range in unit.ips().v6() {
            whole.push_v6_range(*range);
        }
    }

    whole.canonicalize();
    whole
}
