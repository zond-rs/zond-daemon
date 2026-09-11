// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Daemon, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Enums on the wire, as the names the schema gives them
//!
//! Protobuf carries an enum as a number, and the generated Rust carries it as an
//! `i32`. Serialised as it stands, a request would say `service_detection: 3`,
//! which is a number whose meaning lives in a file the reader may not have. The
//! schema already gives every value a name, so the wire uses the name.
//!
//! ```text
//! {"service_detection": "SERVICE_DETECTION_PROBE"}   rather than   {"service_detection": 3}
//! ```
//!
//! That is also what protobuf's own JSON mapping does, so a transport added
//! later that speaks canonical protobuf JSON says the same thing as this one.
//!
//! The generated code already knows both directions, as `as_str_name` and
//! `from_str_name`. All this module adds is the pair of serde functions that
//! call them, once per enum, through [`named`].

use serde::de::{Deserializer, Error as _};
use serde::ser::Serializer;

/// Writes a generated enum to the wire by name and reads it back.
///
/// One invocation per enum in the schema. The module it makes is named in a
/// `#[serde(with = ...)]` attribute that `build.rs` attaches to each field of
/// that enum's type, so a field added to the schema is wired up by naming it
/// there rather than by writing any of this again.
///
/// `optional` inside it is the same pair for a field the schema marked
/// `optional`, which the generated code carries as an `Option<i32>`.
macro_rules! named {
    ($module:ident, $ty:ty, $what:literal) => {
        #[doc = concat!("`", $what, "` on the wire, written as the name the schema gives it.")]
        pub mod $module {
            use super::*;

            /// Writes the value as its name.
            ///
            /// A number the schema has no name for is a value this build should
            /// not be holding, and saying so is better than writing a number
            /// nothing can read back.
            pub fn serialize<S: Serializer>(value: &i32, out: S) -> Result<S::Ok, S::Error> {
                match <$ty>::try_from(*value) {
                    Ok(named) => out.serialize_str(named.as_str_name()),
                    Err(_) => Err(serde::ser::Error::custom(format!(
                        "{value} is not a {}",
                        $what
                    ))),
                }
            }

            /// Reads a name back.
            pub fn deserialize<'de, D: Deserializer<'de>>(input: D) -> Result<i32, D::Error> {
                let name = <alloc_string::String as serde::Deserialize>::deserialize(input)?;

                <$ty>::from_str_name(&name)
                    .map(|named| named as i32)
                    .ok_or_else(|| D::Error::custom(format!("{name} is not a {}", $what)))
            }

            #[doc = concat!("The same, for a field the schema marked `optional`.")]
            pub mod optional {
                use super::*;

                /// Writes the value as its name, or nothing at all.
                pub fn serialize<S: Serializer>(
                    value: &Option<i32>,
                    out: S,
                ) -> Result<S::Ok, S::Error> {
                    match value {
                        Some(value) => super::serialize(value, out),
                        None => out.serialize_none(),
                    }
                }

                /// Reads a name back, treating an absent field and a null alike.
                pub fn deserialize<'de, D: Deserializer<'de>>(
                    input: D,
                ) -> Result<Option<i32>, D::Error> {
                    let name =
                        <Option<alloc_string::String> as serde::Deserialize>::deserialize(input)?;

                    match name {
                        None => Ok(None),
                        Some(name) => <$ty>::from_str_name(&name)
                            .map(|named| Some(named as i32))
                            .ok_or_else(|| D::Error::custom(format!("{name} is not a {}", $what))),
                    }
                }
            }
        }
    };
}

/// `String` under a name the macro can reach from inside the modules it makes.
use std::string as alloc_string;

use crate::proto;

named!(stage, proto::Stage, "stage");
named!(stop_cause, proto::StopCause, "stop cause");
named!(
    service_detection,
    proto::ServiceDetection,
    "service detection level"
);
named!(os_detection, proto::OsDetection, "OS detection level");
named!(detection_class, proto::DetectionClass, "detection class");
named!(scan_effort, proto::ScanEffort, "scan effort");
named!(tcp_technique, proto::TcpScanTechnique, "TCP scan technique");
named!(
    sctp_technique,
    proto::SctpScanTechnique,
    "SCTP scan technique"
);
named!(send_mode, proto::SendMode, "send mode");
named!(export_format, proto::ExportFormat, "export format");
named!(scan_kind, proto::ScanKind, "scan kind");
named!(scan_hold, proto::ScanHold, "scan hold");
named!(diff_format, proto::DiffFormat, "diff format");

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
    use crate::proto;

    /// A level goes out under the name the schema gives it, not the number
    /// protobuf stores.
    ///
    /// The number is the thing a reader cannot check without the schema in front
    /// of them, and the whole reason a wire format is worth hand-writing is that
    /// somebody can read it.
    #[test]
    fn a_level_travels_as_its_name() {
        let request = proto::StartRequest {
            targets: vec!["10.0.0.1".into()],
            service_detection: Some(proto::ServiceDetection::Probe as i32),
            detection: Some(proto::DetectionClass::ActiveBenign as i32),
            ..Default::default()
        };

        let written = serde_json::to_string(&request).expect("a request is writable");

        assert!(written.contains("\"SERVICE_DETECTION_PROBE\""), "{written}");
        assert!(
            written.contains("\"DETECTION_CLASS_ACTIVE_BENIGN\""),
            "{written}"
        );
        assert!(!written.contains(": 3"), "a number leaked out: {written}");
    }

    /// What went out comes back as the same request.
    #[test]
    fn a_request_survives_the_round_trip() {
        let request = proto::StartRequest {
            targets: vec!["10.0.0.0/24".into()],
            exclude: vec!["10.0.0.7".into()],
            ports: Some("22,80,443".into()),
            service_detection: Some(proto::ServiceDetection::Thorough as i32),
            os_detection: Some(proto::OsDetection::Active as i32),
            detection: Some(proto::DetectionClass::Exploit as i32),
            traceroute: Some(true),
            settings: Some(proto::Settings {
                effort: Some(proto::ScanEffort::Fast as i32),
                host_timeout: Some(60),
                ..Default::default()
            }),
            ..Default::default()
        };

        let written = serde_json::to_string(&request).expect("a request is writable");
        let read: proto::StartRequest = serde_json::from_str(&written).expect("and readable again");

        assert_eq!(read, request);
    }

    /// A request may say only what it has to say.
    ///
    /// Everything the schema marks optional is optional here too, so a client
    /// naming one target sends one field rather than a form with every blank
    /// filled in.
    #[test]
    fn a_request_may_name_only_its_targets() {
        let read: proto::StartRequest =
            serde_json::from_str(r#"{"targets":["lan"]}"#).expect("the shortest useful request");

        assert_eq!(read.targets, vec!["lan".to_string()]);
        assert_eq!(read.service_detection, None, "the engine's default stands");
        assert_eq!(read.detection, None, "and no detections run");
    }

    /// A name the schema does not know is refused, and the message says which.
    ///
    /// A client sending a level from a newer schema than this build knows has
    /// made a mistake it can act on, where a silently ignored field is a scan
    /// that quietly did something other than what was asked.
    #[test]
    fn a_name_the_schema_does_not_know_is_refused_by_name() {
        let refused = serde_json::from_str::<proto::StartRequest>(
            r#"{"targets":["lan"],"service_detection":"SERVICE_DETECTION_PARANOID"}"#,
        )
        .expect_err("a level nobody declared");

        assert!(
            refused.to_string().contains("SERVICE_DETECTION_PARANOID"),
            "the error names what it refused: {refused}"
        );
    }

    /// An event carries one thing that happened, and says which.
    #[test]
    fn an_event_names_the_thing_that_happened() {
        let event = proto::Event {
            seq: 1841,
            body: Some(proto::event::Body::Stage(proto::StageChanged {
                stage: proto::Stage::Detections as i32,
            })),
        };

        let written = serde_json::to_string(&event).expect("an event is writable");
        assert!(written.contains("\"STAGE_DETECTIONS\""), "{written}");

        let read: proto::Event = serde_json::from_str(&written).expect("and readable again");
        assert_eq!(read, event);
    }
}
