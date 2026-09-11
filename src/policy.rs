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
//! 1. The targets are resolved, so what follows is judged on addresses rather
//!    than on the words a request named them with.
//! 2. The policy is applied to those addresses. A refusal is written down and
//!    the request ends here.
//! 3. The scan is recorded, which is what gives it a name.
//! 4. The start is written down, under that name.
//! 5. Only then does anything reach the wire.
//!
//! Four before five is what makes the audit worth having: a scan that could not
//! be written down does not happen. Two before three is what keeps a refused
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
}

impl Policy<'_> {
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
