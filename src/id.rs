// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Daemon, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Naming a scan
//!
//! A name a person can read aloud, write down, and type back. Crockford base32,
//! which is the alphabet the engine names a journal in, so the two read alike
//! and a scan that later gains a journal can keep the name it already had.
//!
//! The name is a millisecond and a counter, most significant first, so names
//! sort into the order the scans started. That ordering is worth more than
//! unguessability here: a name is not a capability, and anything that decides
//! who may look at a scan decides it from who is asking rather than from whether
//! they knew the name.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// Crockford base32: no `I`, `L`, `O` or `U`, so nothing reads as a digit and
/// nothing spells anything.
const ALPHABET: [u8; 32] = *b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// How many names one millisecond can hold before the counter wraps into it.
const PER_MILLISECOND: u64 = 1 << 16;

/// Tells apart two scans started in the same millisecond.
static COUNTER: AtomicU64 = AtomicU64::new(0);

/// A name for a scan, unique on this host for as long as anybody is looking.
pub fn mint() -> String {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|since| since.as_millis() as u64)
        .unwrap_or(0);

    let counter = COUNTER.fetch_add(1, Ordering::Relaxed) % PER_MILLISECOND;

    encode(millis.wrapping_mul(PER_MILLISECOND).wrapping_add(counter))
}

/// Thirteen characters, most significant first, zero padded so every name is
/// the same width and they sort as the numbers they are.
fn encode(mut value: u64) -> String {
    let mut out = [b'0'; 13];

    for slot in out.iter_mut().rev() {
        *slot = ALPHABET[(value % 32) as usize];
        value /= 32;
    }

    String::from_utf8(out.to_vec()).expect("the alphabet is ASCII")
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

    /// Two scans started together are still two scans.
    #[test]
    fn no_two_names_are_the_same() {
        let names: std::collections::HashSet<String> = (0..10_000).map(|_| mint()).collect();

        assert_eq!(names.len(), 10_000, "a name was handed out twice");
    }

    /// Every name is the same width, so a column of them lines up and a reader
    /// can tell at a glance that they are the same kind of thing.
    #[test]
    fn every_name_is_thirteen_characters_of_the_alphabet() {
        for _ in 0..100 {
            let name = mint();

            assert_eq!(name.len(), 13, "{name}");
            assert!(
                name.bytes().all(|c| ALPHABET.contains(&c)),
                "{name} is not in the alphabet"
            );
        }
    }

    /// Names sort into the order the scans started.
    #[test]
    fn a_later_name_sorts_after_an_earlier_one() {
        let first = mint();
        let second = mint();

        assert!(first < second, "{first} should sort before {second}");
    }
}
