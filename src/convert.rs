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
use zond_engine::config::{OsDetection, ScanEffort, ServiceDetection};
use zond_engine::journal::lock::LockState;
use zond_engine::model::finding::DetectionClass;
use zond_engine::model::technique::{SctpScanTechnique, TcpScanTechnique};
use zond_engine::report::ScanKind;
use zond_engine::scanner::handle::StopCause;
use zond_engine::transport::probe::SendMode;

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

/// The schema's name for how hard the engine looks at a service.
pub fn service_detection(level: ServiceDetection) -> proto::ServiceDetection {
    match level {
        ServiceDetection::Off => proto::ServiceDetection::Off,
        ServiceDetection::Banner => proto::ServiceDetection::Banner,
        ServiceDetection::Probe => proto::ServiceDetection::Probe,
        ServiceDetection::Thorough => proto::ServiceDetection::Thorough,
        _ => proto::ServiceDetection::Unspecified,
    }
}

/// What the engine reads the schema's name as. `None` where the field was left
/// unset, which leaves the engine's own default standing.
pub fn service_detection_of(named: proto::ServiceDetection) -> Option<ServiceDetection> {
    match named {
        proto::ServiceDetection::Unspecified => None,
        proto::ServiceDetection::Off => Some(ServiceDetection::Off),
        proto::ServiceDetection::Banner => Some(ServiceDetection::Banner),
        proto::ServiceDetection::Probe => Some(ServiceDetection::Probe),
        proto::ServiceDetection::Thorough => Some(ServiceDetection::Thorough),
    }
}

/// The schema's name for whether a host is asked what it runs.
pub fn os_detection(level: OsDetection) -> proto::OsDetection {
    match level {
        OsDetection::Off => proto::OsDetection::Off,
        OsDetection::Passive => proto::OsDetection::Passive,
        OsDetection::Active => proto::OsDetection::Active,
        OsDetection::Aggressive => proto::OsDetection::Aggressive,
        _ => proto::OsDetection::Unspecified,
    }
}

/// What the engine reads the schema's name as.
pub fn os_detection_of(named: proto::OsDetection) -> Option<OsDetection> {
    match named {
        proto::OsDetection::Unspecified => None,
        proto::OsDetection::Off => Some(OsDetection::Off),
        proto::OsDetection::Passive => Some(OsDetection::Passive),
        proto::OsDetection::Active => Some(OsDetection::Active),
        proto::OsDetection::Aggressive => Some(OsDetection::Aggressive),
    }
}

/// The schema's name for what a detection does to its target.
pub fn detection_class(class: DetectionClass) -> proto::DetectionClass {
    match class {
        DetectionClass::Passive => proto::DetectionClass::Passive,
        DetectionClass::ActiveBenign => proto::DetectionClass::ActiveBenign,
        DetectionClass::ActiveMutating => proto::DetectionClass::ActiveMutating,
        DetectionClass::Exploit => proto::DetectionClass::Exploit,
        DetectionClass::Dos => proto::DetectionClass::Dos,
        _ => proto::DetectionClass::Unspecified,
    }
}

/// What the engine reads the schema's name as.
///
/// `None` is a request that named no ceiling, which runs no detections. That is
/// the reason the schema has no value meaning none: an absent field already says
/// it, and a second way to say the same thing is a second thing to get wrong.
pub fn detection_class_of(named: proto::DetectionClass) -> Option<DetectionClass> {
    match named {
        proto::DetectionClass::Unspecified => None,
        proto::DetectionClass::Passive => Some(DetectionClass::Passive),
        proto::DetectionClass::ActiveBenign => Some(DetectionClass::ActiveBenign),
        proto::DetectionClass::ActiveMutating => Some(DetectionClass::ActiveMutating),
        proto::DetectionClass::Exploit => Some(DetectionClass::Exploit),
        proto::DetectionClass::Dos => Some(DetectionClass::Dos),
    }
}

/// The schema's name for how much a scan spends on being sure.
pub fn scan_effort(effort: ScanEffort) -> proto::ScanEffort {
    match effort {
        ScanEffort::Single => proto::ScanEffort::Single,
        ScanEffort::Fast => proto::ScanEffort::Fast,
        ScanEffort::Balanced => proto::ScanEffort::Balanced,
        ScanEffort::Thorough => proto::ScanEffort::Thorough,
        _ => proto::ScanEffort::Unspecified,
    }
}

/// What the engine reads the schema's name as.
pub fn scan_effort_of(named: proto::ScanEffort) -> Option<ScanEffort> {
    match named {
        proto::ScanEffort::Unspecified => None,
        proto::ScanEffort::Single => Some(ScanEffort::Single),
        proto::ScanEffort::Fast => Some(ScanEffort::Fast),
        proto::ScanEffort::Balanced => Some(ScanEffort::Balanced),
        proto::ScanEffort::Thorough => Some(ScanEffort::Thorough),
    }
}

/// The schema's name for which TCP probe a scan sends.
pub fn tcp_technique(technique: TcpScanTechnique) -> proto::TcpScanTechnique {
    match technique {
        TcpScanTechnique::Syn => proto::TcpScanTechnique::Syn,
        TcpScanTechnique::Ack => proto::TcpScanTechnique::Ack,
        TcpScanTechnique::Fin => proto::TcpScanTechnique::Fin,
        TcpScanTechnique::Null => proto::TcpScanTechnique::Null,
        TcpScanTechnique::Xmas => proto::TcpScanTechnique::Xmas,
        TcpScanTechnique::Maimon => proto::TcpScanTechnique::Maimon,
        TcpScanTechnique::Window => proto::TcpScanTechnique::Window,
        _ => proto::TcpScanTechnique::Unspecified,
    }
}

/// What the engine reads the schema's name as.
pub fn tcp_technique_of(named: proto::TcpScanTechnique) -> Option<TcpScanTechnique> {
    match named {
        proto::TcpScanTechnique::Unspecified => None,
        proto::TcpScanTechnique::Syn => Some(TcpScanTechnique::Syn),
        proto::TcpScanTechnique::Ack => Some(TcpScanTechnique::Ack),
        proto::TcpScanTechnique::Fin => Some(TcpScanTechnique::Fin),
        proto::TcpScanTechnique::Null => Some(TcpScanTechnique::Null),
        proto::TcpScanTechnique::Xmas => Some(TcpScanTechnique::Xmas),
        proto::TcpScanTechnique::Maimon => Some(TcpScanTechnique::Maimon),
        proto::TcpScanTechnique::Window => Some(TcpScanTechnique::Window),
    }
}

/// The schema's name for which SCTP probe a scan sends.
pub fn sctp_technique(technique: SctpScanTechnique) -> proto::SctpScanTechnique {
    match technique {
        SctpScanTechnique::Init => proto::SctpScanTechnique::Init,
        SctpScanTechnique::CookieEcho => proto::SctpScanTechnique::CookieEcho,
        _ => proto::SctpScanTechnique::Unspecified,
    }
}

/// What the engine reads the schema's name as.
pub fn sctp_technique_of(named: proto::SctpScanTechnique) -> Option<SctpScanTechnique> {
    match named {
        proto::SctpScanTechnique::Unspecified => None,
        proto::SctpScanTechnique::Init => Some(SctpScanTechnique::Init),
        proto::SctpScanTechnique::CookieEcho => Some(SctpScanTechnique::CookieEcho),
    }
}

/// The schema's name for how a probe reaches the wire.
pub fn send_mode(mode: SendMode) -> proto::SendMode {
    match mode {
        SendMode::Auto => proto::SendMode::Auto,
        SendMode::Ethernet => proto::SendMode::Ethernet,
        SendMode::RawSocket => proto::SendMode::RawSocket,
        _ => proto::SendMode::Unspecified,
    }
}

/// What the engine reads the schema's name as.
pub fn send_mode_of(named: proto::SendMode) -> Option<SendMode> {
    match named {
        proto::SendMode::Unspecified => None,
        proto::SendMode::Auto => Some(SendMode::Auto),
        proto::SendMode::Ethernet => Some(SendMode::Ethernet),
        proto::SendMode::RawSocket => Some(SendMode::RawSocket),
    }
}

/// The schema's name for what a scan was asking.
pub fn scan_kind(kind: ScanKind) -> proto::ScanKind {
    match kind {
        ScanKind::Discovery => proto::ScanKind::Discovery,
        ScanKind::PortScan => proto::ScanKind::PortScan,
        ScanKind::Listen => proto::ScanKind::Listen,
        _ => proto::ScanKind::Unspecified,
    }
}

/// What the engine reads the schema's name as.
pub fn scan_kind_of(named: proto::ScanKind) -> Option<ScanKind> {
    match named {
        proto::ScanKind::Unspecified => None,
        proto::ScanKind::Discovery => Some(ScanKind::Discovery),
        proto::ScanKind::PortScan => Some(ScanKind::PortScan),
        proto::ScanKind::Listen => Some(ScanKind::Listen),
    }
}

/// The schema's name for who is running a scan.
///
/// One way only, and with no list to check itself against: the engine's states
/// carry a heartbeat and a process id, so there is no array of them to walk the
/// way [`scan_kind`] walks `ScanKind::ALL`. A state added upstream arrives here
/// as unspecified, which is the one place in this module that can happen
/// quietly.
pub fn scan_hold(lock: &LockState) -> proto::ScanHold {
    match lock {
        LockState::Free => proto::ScanHold::Free,
        LockState::Held { .. } => proto::ScanHold::Held,
        LockState::Crashed { .. } => proto::ScanHold::Crashed,
        _ => proto::ScanHold::Unspecified,
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

    /// Every level the engine accepts survives the trip to the schema and back.
    ///
    /// The round trip is what makes this worth writing. A value with no name in
    /// the schema fails the first assertion, and a value that answers to the
    /// wrong name fails the second, and the second is the one nothing else in
    /// either repository would have noticed: `SERVICE_DETECTION_BALANCED`
    /// reaching the engine as `Thorough` is a scan that quietly does more than
    /// it was asked to.
    #[test]
    fn every_service_detection_level_survives_the_round_trip() {
        for level in ServiceDetection::ALL {
            let named = service_detection(level);

            assert_ne!(
                named,
                proto::ServiceDetection::Unspecified,
                "the engine accepts {level:?} and the schema has no name for it"
            );
            assert_eq!(
                service_detection_of(named),
                Some(level),
                "{level:?} came back as something else"
            );
        }
    }

    #[test]
    fn every_os_detection_level_survives_the_round_trip() {
        for level in OsDetection::ALL {
            let named = os_detection(level);

            assert_ne!(
                named,
                proto::OsDetection::Unspecified,
                "the engine accepts {level:?} and the schema has no name for it"
            );
            assert_eq!(
                os_detection_of(named),
                Some(level),
                "{level:?} came back as something else"
            );
        }
    }

    /// Every class survives, which is the one of these four where being wrong
    /// costs more than a slow scan.
    ///
    /// The classes are a ceiling on what a detection may do to somebody else's
    /// machine. A caller authorising up to `ACTIVE_BENIGN` and having it read as
    /// `EXPLOIT` is the engine doing something nobody permitted.
    #[test]
    fn every_detection_class_survives_the_round_trip() {
        for class in DetectionClass::ALL {
            let named = detection_class(class);

            assert_ne!(
                named,
                proto::DetectionClass::Unspecified,
                "the engine accepts {class:?} and the schema has no name for it"
            );
            assert_eq!(
                detection_class_of(named),
                Some(class),
                "{class:?} came back as something else"
            );
        }
    }

    #[test]
    fn every_scan_effort_survives_the_round_trip() {
        for effort in ScanEffort::ALL {
            let named = scan_effort(effort);

            assert_ne!(
                named,
                proto::ScanEffort::Unspecified,
                "the engine accepts {effort:?} and the schema has no name for it"
            );
            assert_eq!(
                scan_effort_of(named),
                Some(effort),
                "{effort:?} came back as something else"
            );
        }
    }

    #[test]
    fn every_tcp_technique_survives_the_round_trip() {
        for technique in TcpScanTechnique::ALL {
            let named = tcp_technique(technique);

            assert_ne!(
                named,
                proto::TcpScanTechnique::Unspecified,
                "the engine sends {technique:?} and the schema has no name for it"
            );
            assert_eq!(tcp_technique_of(named), Some(technique));
        }
    }

    #[test]
    fn every_sctp_technique_survives_the_round_trip() {
        for technique in SctpScanTechnique::ALL {
            let named = sctp_technique(technique);

            assert_ne!(
                named,
                proto::SctpScanTechnique::Unspecified,
                "{technique:?}"
            );
            assert_eq!(sctp_technique_of(named), Some(technique));
        }
    }

    #[test]
    fn every_send_mode_survives_the_round_trip() {
        for mode in SendMode::ALL {
            let named = send_mode(mode);

            assert_ne!(named, proto::SendMode::Unspecified, "{mode:?}");
            assert_eq!(send_mode_of(named), Some(mode));
        }
    }

    #[test]
    fn every_scan_kind_survives_the_round_trip() {
        for kind in ScanKind::ALL {
            let named = scan_kind(kind);

            assert_ne!(
                named,
                proto::ScanKind::Unspecified,
                "the engine records {kind:?} and the schema has no name for it"
            );
            assert_eq!(scan_kind_of(named), Some(kind));
        }
    }

    /// Each lock state has a name of its own, so a scan whose process died is
    /// not filed beside one that finished.
    ///
    /// The difference is what a person acts on: one is done and the other is
    /// waiting to be continued.
    #[test]
    fn a_crashed_scan_is_not_a_free_one() {
        use std::time::Duration;

        assert_eq!(scan_hold(&LockState::Free), proto::ScanHold::Free);
        assert_eq!(
            scan_hold(&LockState::Held {
                last_beat: Duration::from_secs(1),
                pid: 1234,
            }),
            proto::ScanHold::Held
        );
        assert_eq!(
            scan_hold(&LockState::Crashed { pid: 4321 }),
            proto::ScanHold::Crashed
        );
    }

    /// An unset field leaves the engine's own default standing, rather than
    /// being read as the first value the schema happens to declare.
    #[test]
    fn an_unset_level_is_not_a_level() {
        assert_eq!(
            service_detection_of(proto::ServiceDetection::Unspecified),
            None
        );
        assert_eq!(os_detection_of(proto::OsDetection::Unspecified), None);
        assert_eq!(detection_class_of(proto::DetectionClass::Unspecified), None);
        assert_eq!(scan_effort_of(proto::ScanEffort::Unspecified), None);
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
