// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Daemon, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Compiles the protocol into Rust types.
//!
//! Through `protox` rather than `protoc`, so `cargo build` needs nothing
//! installed that cargo did not install. A build that depends on a system
//! protobuf compiler is a build that works on the machine it was written on;
//! `protox` is a compiler in the dependency tree like any other crate.
//!
//! Only the messages are generated here. The service is declared in the schema
//! and nothing generates stubs for it yet, because the first transport frames
//! the same messages over a pipe and has no use for them.
//!
//! The generated types carry serde derives, since the first transport writes
//! them as JSON. Every field whose type is an enum is pointed at the matching
//! module in `src/codec.rs`, so it travels as the name the schema gives it
//! rather than as the number protobuf stores. A field added to the schema in an
//! enum's type needs a line here; nothing else about it needs writing twice.

use std::path::PathBuf;

/// Every field whose type is an enum, and the codec module that writes it by
/// name. `optional` in the path is the variant for a field the schema marked
/// `optional`, which the generated code carries as an `Option<i32>`.
/// Every message whose fields may be left out of a request or a frame.
///
/// `Event` is not among them. It is written by this process rather than read
/// from a client, so no field of it is ever absent, and a path naming it reaches
/// the variants of its oneof, which serde will not take a `default` on.
const DEFAULTED: &[&str] = &[
    "zond.v1.StartRequest",
    "zond.v1.StartResponse",
    "zond.v1.Evasion",
    "zond.v1.Settings",
    "zond.v1.WatchRequest",
    "zond.v1.HostChanged",
    "zond.v1.StageChanged",
    "zond.v1.Progress",
    "zond.v1.ScannerFailed",
    "zond.v1.Finished",
    "zond.v1.GetRequest",
    "zond.v1.StopRequest",
    "zond.v1.ScanState",
    "zond.v1.Error",
    "zond.v1.ExportRequest",
    "zond.v1.ExportResponse",
    "zond.v1.ListRequest",
    "zond.v1.ListResponse",
    "zond.v1.ScanListing",
    "zond.v1.PruneRequest",
    "zond.v1.PruneResponse",
    "zond.v1.HeldRecord",
];

const ENUM_FIELDS: &[(&str, &str)] = &[
    (
        "zond.v1.StartRequest.service_detection",
        "service_detection::optional",
    ),
    (
        "zond.v1.StartRequest.os_detection",
        "os_detection::optional",
    ),
    (
        "zond.v1.StartRequest.detection",
        "detection_class::optional",
    ),
    ("zond.v1.Settings.effort", "scan_effort::optional"),
    ("zond.v1.Settings.tcp_technique", "tcp_technique::optional"),
    (
        "zond.v1.Settings.sctp_technique",
        "sctp_technique::optional",
    ),
    ("zond.v1.Settings.send_mode", "send_mode::optional"),
    ("zond.v1.StageChanged.stage", "stage"),
    ("zond.v1.Progress.stage", "stage"),
    ("zond.v1.Finished.cause", "stop_cause"),
    ("zond.v1.ScanState.cause", "stop_cause::optional"),
    ("zond.v1.ExportRequest.format", "export_format"),
    ("zond.v1.ExportResponse.format", "export_format"),
    ("zond.v1.ScanListing.kind", "scan_kind"),
    ("zond.v1.StartRequest.kind", "scan_kind"),
    ("zond.v1.ScanListing.hold", "scan_hold"),
];

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // The whole directory, so adding a file to the schema rebuilds without
    // anybody having to remember to name it here.
    println!("cargo:rerun-if-changed=proto");

    let descriptors = protox::compile(["zond/v1/scan.proto"], ["proto"])?;

    let out = PathBuf::from(std::env::var("OUT_DIR")?);
    let mut config = prost_build::Config::new();

    config
        .out_dir(&out)
        .type_attribute(".", "#[derive(serde::Serialize, serde::Deserialize)]");

    // A field a client left out is a field it had nothing to say about, not a
    // malformed request, so the schema's own defaults stand. Set on the message
    // rather than on each of its fields: one attribute covers every field, where
    // a field path has to name each one and would be a second list to keep.
    //
    // Named per message rather than globally, because a blanket rule reaches the
    // variants inside `Event`'s oneof and serde has no `default` for a variant.
    for message in DEFAULTED {
        config.type_attribute(message, "#[serde(default)]");
    }

    // What happened, said the way the schema says it.
    //
    // The generated oneof is a Rust enum, and serde writes one as a map keyed by
    // the variant's Rust name, so an event would arrive as
    // `{"body":{"StageChanged":…}}`. Flattened and renamed it arrives as
    // `{"seq":3,"stage":…}`, which is the name the schema gives that arm and the
    // one a reader of the schema goes looking for.
    config
        .type_attribute(
            "zond.v1.Event.body",
            "#[serde(rename_all = \"snake_case\")]",
        )
        .field_attribute("zond.v1.Event.body", "#[serde(flatten)]");

    for (field, module) in ENUM_FIELDS {
        config.field_attribute(
            field,
            format!("#[serde(with = \"crate::codec::{module}\")]"),
        );
    }

    config.compile_fds(descriptors)?;

    Ok(())
}
