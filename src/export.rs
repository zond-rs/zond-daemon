// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Daemon, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Writing a finished scan down
//!
//! Five formats, all of them the engine's own work. What this adds is the name
//! the schema gives each one and the decision that a caller who named none gets
//! JSON, that being the only format carrying everything a scan found.
//!
//! Every one of them is text, so a document crosses the wire as a string rather
//! than as something a client has to decode first.

use zond_engine::diff::ScanDiff;
use zond_engine::export::diff::{DiffExporter, HtmlDiffExporter, JsonDiffExporter};
use zond_engine::export::{
    CsvExporter, ExportOptions, Exporter, HtmlExporter, JsonExporter, JsonLinesExporter,
    NmapXmlExporter, Redaction,
};
use zond_engine::merge::{Merge, MergeOptions};
use zond_engine::report::ScanReport;

use crate::error::Error;
use crate::proto;

/// Writes `report` out in the format the schema names.
///
/// A caller who named no format gets JSON. It is the only one that carries
/// everything a scan found, so it is the answer least likely to lose something
/// somebody wanted.
pub fn document(
    report: &ScanReport,
    format: proto::ExportFormat,
    redaction: Redaction,
) -> Result<String, Error> {
    let options = ExportOptions::new().with_redaction(redaction);

    let writer: Box<dyn Exporter> = match format {
        proto::ExportFormat::Unspecified | proto::ExportFormat::Json => {
            Box::new(JsonExporter::new(options).pretty())
        }
        proto::ExportFormat::Jsonl => Box::new(JsonLinesExporter::new(options)),
        proto::ExportFormat::Csv => Box::new(CsvExporter::new(options)),
        proto::ExportFormat::Html => Box::new(HtmlExporter::new(options)),
        proto::ExportFormat::NmapXml => Box::new(NmapXmlExporter::new(options)),
    };

    let mut written = Vec::new();
    writer.export(report, &mut written).map_err(Error::engine)?;

    String::from_utf8(written).map_err(|_| {
        Error::new(
            "export.not_text",
            "the engine wrote a document that is not text, which should not happen",
        )
    })
}

/// The format a caller asked for, resolved to the one that will actually be
/// written.
///
/// A request naming none is answered in JSON, so this says JSON. Leaving it
/// unresolved would have the answer echo `UNSPECIFIED` beside a document that is
/// definitely something, which is the answer lying about itself.
pub fn named(raw: i32) -> proto::ExportFormat {
    match proto::ExportFormat::try_from(raw) {
        Ok(proto::ExportFormat::Unspecified) | Err(_) => proto::ExportFormat::Json,
        Ok(format) => format,
    }
}

/// Writes what changed between two scans.
///
/// Its own two formats rather than the report's five: a comparison is a
/// different shape, and there is no sensible row of a table or line of nmap XML
/// for "this port closed".
pub fn comparison(
    baseline: &ScanReport,
    current: &ScanReport,
    format: proto::DiffFormat,
) -> Result<String, Error> {
    let difference = ScanDiff::between(baseline, current);

    let writer: Box<dyn DiffExporter> = match format {
        proto::DiffFormat::Unspecified | proto::DiffFormat::Json => {
            Box::new(JsonDiffExporter::default())
        }
        proto::DiffFormat::Html => Box::new(HtmlDiffExporter::default()),
    };

    let mut written = Vec::new();
    writer
        .export(&difference, &mut written)
        .map_err(Error::engine)?;

    String::from_utf8(written).map_err(|_| {
        Error::new(
            "export.not_text",
            "the engine wrote a comparison that is not text, which should not happen",
        )
    })
}

/// The comparison format a caller asked for, resolved to the one that will be
/// written.
pub fn compared(raw: i32) -> proto::DiffFormat {
    match proto::DiffFormat::try_from(raw) {
        Ok(proto::DiffFormat::Unspecified) | Err(_) => proto::DiffFormat::Json,
        Ok(format) => format,
    }
}

/// Folds several scans into one report.
///
/// Named as it folds, so the folded report says which documents it was made of
/// rather than presenting itself as a single run that covered all of them.
pub fn folded(reports: Vec<(String, ScanReport)>) -> ScanReport {
    let mut fold = Merge::new(MergeOptions::default());

    for (name, report) in reports {
        fold.add_from(name, report);
    }

    fold.finish()
}
