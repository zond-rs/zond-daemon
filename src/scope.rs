// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Daemon, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # What this daemon may be pointed at
//!
//! A scanner reached over a socket is a scanner whoever holds that socket can
//! aim. That is the whole of what makes the arrangement worth having and the
//! whole of what makes it worth bounding: the process with the raw sockets
//! should be the one deciding where they may be sent, not the web tier in front
//! of it, which is the part that gets compromised.
//!
//! So the policy lives here rather than in any client. A client that is taken
//! over can ask for anything; what it gets is still what the operator allowed.
//!
//! ## Refused, not narrowed
//!
//! A request reaching outside the policy is turned down rather than quietly
//! trimmed to fit. Narrowing is the friendlier behaviour and the wrong one: a
//! caller who asked to scan a range and got a scan of part of it has a report
//! that says less than they think it does, and nothing told them so.
//!
//! ## Checked on the addresses, not on the words
//!
//! A policy is compared against the addresses a request resolved to, never
//! against the text it named them with. A hostname resolves to whatever its
//! owner points it at, so a policy read off the words would be one an attacker
//! writes the other half of.
//!
//! ## No policy is no policy
//!
//! A daemon told nothing permits everything, which is what every scanner does
//! and what somebody running one on their own machine expects. Bounding it is
//! something an operator does on purpose, and the two ways of doing it compose:
//! an allow list says where a scan may reach, a deny list says where it may not
//! whatever the allow list says, and either may be given on its own.

use std::fmt;

use zond_engine::model::ip::set::IpSet;

use crate::error::Error;

/// Where this daemon may send probes.
#[derive(Debug, Clone, Default)]
pub struct Scope {
    /// Where a scan may reach. `None` is anywhere.
    allowed: Option<IpSet>,
    /// Where it may not, whatever [`allowed`](Self::allowed) says.
    denied: IpSet,
}

impl Scope {
    /// A daemon that may be pointed anywhere.
    pub fn anywhere() -> Self {
        Self::default()
    }

    /// Reads a policy off the words an operator wrote it in.
    ///
    /// Each is the engine's own address grammar, so a range, a CIDR block or a
    /// single address all read the same way they do in a scan request.
    pub fn read(allowed: &[String], denied: &[String]) -> Result<Self, Error> {
        Ok(Self {
            allowed: match allowed.is_empty() {
                true => None,
                false => Some(set(allowed, "allowed")?),
            },
            denied: set(denied, "denied")?,
        })
    }

    /// Whether this policy bounds anything at all.
    pub fn is_bounded(&self) -> bool {
        self.allowed.is_some() || !self.denied.is_empty()
    }

    /// Refuses `asked` unless every address in it is permitted.
    ///
    /// The refusal names what it refused rather than only that it refused: an
    /// operator reading an audit log wants to know which addresses somebody
    /// reached for, and a caller wants to know which part of their request to
    /// take out.
    pub fn permits(&self, asked: &IpSet) -> Result<(), Error> {
        let refused = self.outside(asked);

        if refused.is_empty() {
            return Ok(());
        }

        Err(Error::new(
            "scope.refused",
            format!(
                "this daemon may not scan {}; {} addresses of the request are outside what it is allowed",
                Ranges(&refused),
                refused.len()
            ),
        ))
    }

    /// The addresses of `asked` this policy does not permit.
    fn outside(&self, asked: &IpSet) -> IpSet {
        // Outside the allow list, where there is one.
        let mut beyond = match &self.allowed {
            Some(allowed) => {
                let mut beyond = asked.clone();
                beyond.subtract(allowed);
                beyond
            }
            None => IpSet::new(),
        };

        // And inside the deny list, which is `asked` minus everything not
        // denied. Written as two subtractions because that is the arithmetic
        // `IpSet` offers, and it never walks an address: a deny list of a `/8`
        // costs the same as one of a single host.
        let mut permitted = asked.clone();
        permitted.subtract(&self.denied);

        let mut denied = asked.clone();
        denied.subtract(&permitted);

        beyond.extend_ranges(&denied);
        beyond
    }
}

/// Reads one side of a policy.
fn set(written: &[String], side: &'static str) -> Result<IpSet, Error> {
    let mut whole = IpSet::new();

    for expression in written {
        let one: IpSet = expression.parse().map_err(|refused| {
            Error::new(
                "scope.malformed",
                format!("{expression} is not an address range for the {side} list: {refused}"),
            )
        })?;

        whole.extend_ranges(&one);
    }

    Ok(whole)
}

/// Adding one set of ranges to another without walking a single address.
trait ExtendRanges {
    fn extend_ranges(&mut self, other: &IpSet);
}

impl ExtendRanges for IpSet {
    fn extend_ranges(&mut self, other: &IpSet) {
        for range in other.v4() {
            self.push_v4_range(*range);
        }
        for range in other.v6() {
            self.push_v6_range(*range);
        }
        self.canonicalize();
    }
}

/// A set written out as the ranges it holds, shortened where there are many.
///
/// Three at the outside. An operator reading a refusal wants to recognise what
/// was asked for, and a policy refusing a `/8` would otherwise answer with more
/// ranges than anybody reads.
struct Ranges<'a>(&'a IpSet);

impl fmt::Display for Ranges<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let v4 = self
            .0
            .v4()
            .iter()
            .map(|range| span(range.start_addr().into(), range.end_addr().into()));
        let v6 = self
            .0
            .v6()
            .iter()
            .map(|range| span(range.start_addr().into(), range.end_addr().into()));

        for (written, range) in v4.chain(v6).enumerate() {
            if written == 3 {
                return f.write_str(" and more");
            }
            if written > 0 {
                f.write_str(", ")?;
            }
            f.write_str(&range)?;
        }

        Ok(())
    }
}

/// One range, written as a person would write it.
///
/// IPv6 addresses are bracketed, so a reader never has to decide whether the
/// last group is part of the address or something after it.
fn span(start: std::net::IpAddr, end: std::net::IpAddr) -> String {
    let bracket = |address: std::net::IpAddr| match address {
        std::net::IpAddr::V4(address) => address.to_string(),
        std::net::IpAddr::V6(address) => format!("[{address}]"),
    };

    match start == end {
        true => bracket(start),
        false => format!("{}-{}", bracket(start), bracket(end)),
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

    /// The addresses an expression stands for.
    fn asking(expression: &str) -> IpSet {
        expression.parse().expect("a range this test wrote")
    }

    fn bounded(allowed: &[&str], denied: &[&str]) -> Scope {
        Scope::read(
            &allowed.iter().map(|s| (*s).to_string()).collect::<Vec<_>>(),
            &denied.iter().map(|s| (*s).to_string()).collect::<Vec<_>>(),
        )
        .expect("a policy this test wrote")
    }

    /// A daemon told nothing may be pointed anywhere.
    ///
    /// The status quo, and what somebody running a scanner on their own machine
    /// expects. Bounding one is something an operator does on purpose.
    #[test]
    fn a_daemon_told_nothing_permits_anything() {
        let anywhere = Scope::anywhere();

        assert!(!anywhere.is_bounded());
        assert!(anywhere.permits(&asking("0.0.0.0/0")).is_ok());
        assert!(anywhere.permits(&asking("::/0")).is_ok());
    }

    /// An allow list is the only place a scan may reach.
    #[test]
    fn an_allow_list_is_the_whole_of_where_a_scan_may_reach() {
        let inside = bounded(&["10.0.0.0/8"], &[]);

        assert!(inside.is_bounded());
        assert!(inside.permits(&asking("10.1.2.0/24")).is_ok());
        assert!(inside.permits(&asking("10.0.0.1")).is_ok());

        let refused = inside
            .permits(&asking("192.0.2.0/24"))
            .expect_err("outside the allow list");

        assert_eq!(refused.code(), "scope.refused");
        assert!(refused.message().contains("192.0.2.0"), "{refused}");
    }

    /// A request reaching partly outside is refused whole, rather than trimmed
    /// to the part that fits.
    ///
    /// Narrowing is the friendlier behaviour and the wrong one. A caller who
    /// asked for a range and got a scan of half of it has a report saying less
    /// than they think, and nothing told them so.
    #[test]
    fn a_request_reaching_partly_outside_is_refused_whole() {
        let inside = bounded(&["10.0.0.0/8"], &[]);

        let refused = inside
            .permits(&asking("10.0.0.0-11.0.0.0"))
            .expect_err("half in, half out");

        assert_eq!(refused.code(), "scope.refused");
        assert!(
            refused.message().contains("11.0.0.0") || refused.message().contains("10.255"),
            "the refusal names the part that was outside: {refused}"
        );
    }

    /// A deny list wins, whatever the allow list said.
    #[test]
    fn a_deny_list_overrides_an_allow_list() {
        let policy = bounded(&["10.0.0.0/8"], &["10.5.0.0/16"]);

        assert!(policy.permits(&asking("10.1.0.0/16")).is_ok());

        let refused = policy
            .permits(&asking("10.5.0.1"))
            .expect_err("allowed by one list and denied by the other");

        assert_eq!(refused.code(), "scope.refused");
        assert!(refused.message().contains("10.5.0.1"), "{refused}");
    }

    /// A deny list on its own bounds an otherwise open daemon.
    #[test]
    fn a_deny_list_alone_still_bounds() {
        let policy = bounded(&[], &["169.254.169.254"]);

        assert!(policy.is_bounded());
        assert!(policy.permits(&asking("10.0.0.0/8")).is_ok());
        assert!(policy.permits(&asking("169.254.169.254")).is_err());
    }

    /// Both families are bounded, and an address of one says nothing about the
    /// other.
    ///
    /// A policy written in IPv4 that quietly let every IPv6 address through
    /// would be a policy somebody thought they had.
    #[test]
    fn a_policy_written_in_one_family_does_not_open_the_other() {
        let policy = bounded(&["10.0.0.0/8"], &[]);

        let refused = policy
            .permits(&asking("2001:db8::/64"))
            .expect_err("no v6 was allowed");

        assert_eq!(refused.code(), "scope.refused");
        assert!(
            refused.message().contains('['),
            "a v6 range is bracketed so a reader can see where it ends: {refused}"
        );
    }

    /// A range nobody could parse is a mistake in the policy, named as one.
    ///
    /// Refused at startup rather than treated as an empty list, which would be a
    /// daemon running with a policy its operator thought said something.
    #[test]
    fn a_policy_nobody_could_parse_is_refused_rather_than_read_as_empty() {
        let refused =
            Scope::read(&["not a range".to_string()], &[]).expect_err("a range that is not one");

        assert_eq!(refused.code(), "scope.malformed");
        assert!(refused.message().contains("not a range"), "{refused}");
        assert!(refused.message().contains("allowed"), "{refused}");
    }
}
