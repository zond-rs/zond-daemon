// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Daemon, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # From a request on the wire to a scan on the network
//!
//! A `StartRequest` is the wire form of the engine's own `ScanRequest`, so most
//! of this is moving fields across and letting the engine do the reading. What
//! it adds is the two things a document cannot carry: the host's own resolver,
//! for a target named rather than numbered, and the corpus of detections the
//! scan runs.

use std::path::Path;

use zond_engine::config::ZondConfig;
use zond_engine::detect::Detections;
use zond_engine::export::Redaction;
use zond_engine::import::request::ScanRequest;
use zond_engine::journal::manifest::Plan;
use zond_engine::journal::store::{self, Journal};
use zond_engine::model::parse::target::TargetContext;
use zond_engine::model::port::PortSet;
use zond_engine::model::target::TargetMap;
use zond_engine::resolve::{self, Resolver};
use zond_engine::system::privilege::Privilege;

use crate::error::Error;
use crate::proto;
use crate::scans::{Scan, Started};

/// How many ports a request that named none asks about.
///
/// The same figure `zond scan` falls back to, so a request that says nothing
/// about ports gets the scan somebody would have got by typing the command.
const DEFAULT_TOP_PORTS: usize = 1000;

/// Starts the scan a request describes.
pub async fn scan(wire: proto::StartRequest, root: Option<&Path>) -> Result<Started, Error> {
    let asked = request(wire)?;

    if asked.targets.is_empty() {
        return Err(Error::new(
            "request.no_targets",
            "a scan has to be given something to scan",
        ));
    }

    let mut config = ZondConfig::default();
    asked.apply_to(&mut config);

    let ports = match asked.ports() {
        Some(Ok(ports)) => ports,
        Some(Err(refused)) => return Err(Error::engine(refused)),
        None => PortSet::top_tcp(DEFAULT_TOP_PORTS),
    };

    // The host's own resolver, unless the request asked for a run that generates
    // no DNS traffic at all.
    let resolver = (!config.no_dns).then(Resolver::from_system);
    let context = TargetContext::new();

    let map = match &resolver {
        Some(resolver) => resolve::to_target_map(&asked.targets, ports, &context, resolver)
            .await
            .map_err(Error::engine)?,
        None => zond_engine::model::parse::target::to_target_map(&asked.targets, ports, &context)
            .map_err(Error::engine)?,
    };

    config.exclusions = resolve::for_exclusion(&asked.exclude, resolver.as_ref())
        .await
        .map_err(Error::engine)?;

    let redaction = if config.redact {
        Redaction::Standard
    } else {
        Redaction::None
    };

    // Recorded before it starts, so a scan outlives the process running it and
    // can be read back by name afterwards. The journal names it; only a run that
    // could not be recorded falls back to a name of this process's own, and that
    // name dies with the process exactly as the scan does.
    let journal = root.and_then(|root| record(root, &map, &config));
    let id = match &journal {
        Some(journal) => journal.manifest().id.clone(),
        None => crate::id::mint(),
    };

    let (session, task) = match journal {
        Some(journal) => {
            zond_engine::scan_with_journal(map, &config, Detections::embedded(), journal).await
        }
        None => zond_engine::scan(map, &config, Detections::embedded()).await,
    }
    .map_err(Error::engine)?;

    let (hosts, events, handle, progress) = session.into_parts();

    Ok(Started {
        scan: Scan::new(id, hosts, progress, handle, redaction),
        events,
        task,
    })
}

/// Opens a journal for this scan, or none where the machine will not have one.
///
/// A run that cannot be recorded is still a run. The engine draws the same line
/// for its own callers: journalling is the front end's choice, and a front end
/// that cannot make it this time should not refuse the scan over it. What is
/// lost is only that the scan cannot be read back once this process is gone,
/// and the client is told which kind it got by the shape of the name.
fn record(root: &Path, map: &TargetMap, config: &ZondConfig) -> Option<Journal> {
    // Not `create_dir_all`: under `sudo` that leaves the directory owned by
    // root, and every later unprivileged run then finds a journal directory it
    // cannot write to. The engine creates it and gives it away.
    if let Err(refused) = store::prepare_root(root) {
        tracing::warn!("not recording this scan: {} ({refused})", root.display());
        return None;
    }

    let plan = Plan::port_scan(map, &config.exclusions, config.tcp_technique);

    match Journal::create(root, &plan, Privilege::current(), summarise(map)) {
        Ok(journal) => Some(journal),
        Err(refused) => {
            tracing::warn!("not recording this scan: {refused}");
            None
        }
    }
}

/// What a person listing their scans sees beside the name.
fn summarise(map: &TargetMap) -> String {
    match map.gross_targets() {
        Ok(1) => "1 probe".to_string(),
        Ok(probes) => format!("{probes} probes"),
        Err(_) => "a plan too large to count".to_string(),
    }
}

/// Reads a wire request as the engine's own.
///
/// Field for field, which is the whole point of the two being the same shape.
/// The levels come back through `convert`, where an unset field is `None` and
/// the engine's own default stands.
fn request(wire: proto::StartRequest) -> Result<ScanRequest, Error> {
    let mut asked = ScanRequest::new();

    asked.targets = wire.targets;
    asked.exclude = wire.exclude;
    asked.ports = wire.ports;
    asked.traceroute = wire.traceroute;
    asked.characterise = wire.characterise;
    asked.icmp_evidence = wire.icmp_evidence;
    asked.assume_up = wire.assume_up;

    asked.service_detection =
        named(wire.service_detection).and_then(crate::convert::service_detection_of);
    asked.os_detection = named(wire.os_detection).and_then(crate::convert::os_detection_of);
    asked.detection = named(wire.detection)
        .and_then(crate::convert::detection_class_of)
        .map(zond_engine::config::envelope::DetectionEnvelope::up_to);

    if !wire.ip_protocols.is_empty() {
        asked.ip_protocols = Some(
            wire.ip_protocols
                .into_iter()
                .map(|number| {
                    u8::try_from(number).map_err(|_| {
                        Error::new(
                            "request.bad_ip_protocol",
                            format!("{number} is not an IP protocol number"),
                        )
                    })
                })
                .collect::<Result<_, _>>()?,
        );
    }

    if !wire.send_source.is_empty() {
        asked.send_source = Some(
            wire.send_source
                .into_iter()
                .map(|address| {
                    address.parse().map_err(|_| {
                        Error::new(
                            "request.bad_send_source",
                            format!("{address} is not an address to send from"),
                        )
                    })
                })
                .collect::<Result<_, _>>()?,
        );
    }

    Ok(asked)
}

/// The schema's name for a field, where the field was set at all.
fn named<T: TryFrom<i32>>(raw: Option<i32>) -> Option<T> {
    raw.and_then(|value| T::try_from(value).ok())
}
