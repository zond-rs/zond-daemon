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

use std::num::{NonZeroU8, NonZeroU32};
use std::path::Path;
use std::time::Duration;

use zond_engine::config::{TimeoutScale, ZondConfig};
use zond_engine::detect::Detections;
use zond_engine::evasion::EvasionProfile;
use zond_engine::export::Redaction;
use zond_engine::import::request::ScanRequest;
use zond_engine::import::settings::Settings;
use zond_engine::journal::manifest::Plan;
use zond_engine::journal::store::{self, Journal};
use zond_engine::model::ip::set::IpSet;
use zond_engine::model::parse::target::TargetContext;
use zond_engine::model::port::PortSet;
use zond_engine::model::target::TargetMap;
use zond_engine::report::ScanKind;
use zond_engine::resolve::{self, Resolver};
use zond_engine::scanner::ListenScope;
use zond_engine::system::privilege::Privilege;

use crate::error::Error;
use crate::policy::{self, Policy};
use crate::proto;
use crate::scans::{Scan, Started};

/// How many ports a request that named none asks about.
///
/// The same figure `zond scan` falls back to, so a request that says nothing
/// about ports gets the scan somebody would have got by typing the command.
const DEFAULT_TOP_PORTS: usize = 1000;

/// Starts the scan a request describes, of whichever kind it asks for.
pub async fn scan(wire: proto::StartRequest, under: Policy<'_>) -> Result<Started, Error> {
    let kind = proto::ScanKind::try_from(wire.kind)
        .ok()
        .and_then(crate::convert::scan_kind_of)
        .unwrap_or(ScanKind::PortScan);

    // Before the request is read, let alone resolved: a daemon with no room for
    // another scan has none whatever the rest of the document turns out to say.
    let asked_about = match kind {
        ScanKind::Listen => &wire.links,
        _ => &wire.targets,
    };
    under.room(audited_as(kind), asked_about)?;

    match kind {
        ScanKind::Discovery => sweep(wire, under).await,
        ScanKind::Listen => watch(wire, under).await,
        // Every other kind, which today is the port scan and tomorrow is
        // whatever the engine learns next. Asking for one this build has no
        // name for is the same as asking for nothing.
        _ => ports(wire, under).await,
    }
}

/// What the audit calls a kind of scan.
fn audited_as(kind: ScanKind) -> &'static str {
    match kind {
        ScanKind::Discovery => "discovery",
        ScanKind::Listen => "listen",
        _ => "port_scan",
    }
}

/// Which of a host's ports are open, and what is behind them.
async fn ports(wire: proto::StartRequest, under: Policy<'_>) -> Result<Started, Error> {
    let asked = request(wire)?;
    let mut config = ZondConfig::default();
    asked.apply_to(&mut config);

    if asked.targets.is_empty() {
        return Err(nothing_to_scan());
    }

    let ports = match asked.ports() {
        Some(Ok(ports)) => ports,
        Some(Err(refused)) => return Err(Error::engine(refused)),
        None => PortSet::top_tcp(DEFAULT_TOP_PORTS),
    };

    let resolver = resolver(&config);
    let context = TargetContext::new();

    let map = match &resolver {
        Some(resolver) => resolve::to_target_map(&asked.targets, ports, &context, resolver)
            .await
            .map_err(Error::engine)?,
        None => zond_engine::model::parse::target::to_target_map(&asked.targets, ports, &context)
            .map_err(Error::engine)?,
    };

    config.exclusions = exclusions(&asked.exclude, resolver.as_ref()).await?;

    under.permit(&policy::reached_by(&map), "port_scan", &asked.targets)?;

    let journal = under.root.and_then(|root| {
        let plan = Plan::port_scan(&map, &config.exclusions, config.tcp_technique);
        record(root, &plan, probes(&map))
    });
    let id = named_by(&journal);
    under.record(&id, "port_scan", &asked.targets)?;

    let (session, task) = match journal {
        Some(journal) => {
            zond_engine::scan_with_journal(map, &config, Detections::embedded(), journal).await
        }
        None => zond_engine::scan(map, &config, Detections::embedded()).await,
    }
    .map_err(Error::engine)?;

    Ok(started(id, session, task, &config))
}

/// Which addresses are alive.
///
/// A sweep asks about addresses and never about ports, so a request's `ports`
/// is not read here. Everything else it carries applies: the same exclusions,
/// the same evasion, the same settings.
async fn sweep(wire: proto::StartRequest, under: Policy<'_>) -> Result<Started, Error> {
    let asked = request(wire)?;
    let mut config = ZondConfig::default();
    asked.apply_to(&mut config);

    if asked.targets.is_empty() {
        return Err(nothing_to_scan());
    }

    let resolver = resolver(&config);
    let targets = resolve::for_discovery(&asked.targets, resolver.as_ref())
        .await
        .map_err(Error::engine)?;

    // Before the exclusions, because a sweep's own targets decide whether the
    // scan sweeps a segment and the plan has to record that.
    targets.apply_to(&mut config);
    config.exclusions = exclusions(&asked.exclude, resolver.as_ref()).await?;

    let addresses: IpSet = targets.into_ips();

    under.permit(&addresses, "discovery", &asked.targets)?;

    let journal = under.root.and_then(|root| {
        let plan = Plan::discovery(&addresses, &config.exclusions, config.segment_sweep);
        record(root, &plan, addresses_in(&addresses))
    });
    let id = named_by(&journal);
    under.record(&id, "discovery", &asked.targets)?;

    let (session, task) = match journal {
        Some(journal) => zond_engine::discover_with_journal(addresses, &config, journal).await,
        None => zond_engine::discover(addresses, &config).await,
    }
    .map_err(Error::engine)?;

    Ok(started(id, session, task, &config))
}

/// What a link carries, having sent nothing.
///
/// The one kind that asks nothing of anybody, so it names links rather than
/// targets and ends when it is told to rather than when the work runs out.
async fn watch(wire: proto::StartRequest, under: Policy<'_>) -> Result<Started, Error> {
    let links = wire.links.clone();
    let listen_for = wire.listen_for_seconds;

    let asked = request(wire)?;
    let mut config = ZondConfig::default();
    asked.apply_to(&mut config);

    if links.is_empty() {
        return Err(Error::new(
            "request.no_links",
            "a listen has to be given a link to listen on",
        ));
    }

    let zones = resolve::for_listening(&links)
        .map_err(|refused| Error::new("request.unknown_link", refused.to_string()))?;

    let mut scope = ListenScope::on(zones.clone()).recording_everything();
    if let Some(seconds) = listen_for {
        scope = scope.for_at_most(Duration::from_secs(u64::from(seconds)));
    }

    // No scope check: a listener puts nothing on the wire, so there is no reach
    // for a policy to bound. What it can see is decided by which link an
    // operator let this process open, which the operating system already
    // answers.
    let journal = under.root.and_then(|root| {
        let plan = Plan::listen(zones.clone());
        record(root, &plan, watching(&links))
    });
    let id = named_by(&journal);
    under.record(&id, "listen", &links)?;

    let (session, task) = match journal {
        Some(journal) => zond_engine::listen_with_journal(scope, &config, journal).await,
        None => zond_engine::listen(scope, &config).await,
    }
    .map_err(Error::engine)?;

    Ok(started(id, session, task, &config))
}

/// The pieces every kind hands back the same way.
fn started(
    id: String,
    session: zond_engine::ScanSession,
    task: zond_engine::ScanTask,
    config: &ZondConfig,
) -> Started {
    let redaction = if config.redact {
        Redaction::Standard
    } else {
        Redaction::None
    };

    let (hosts, events, handle, progress) = session.into_parts();

    Started {
        scan: Scan::new(id, hosts, progress, handle, redaction),
        events,
        task,
    }
}

/// The name the journal gave the scan, or one of this process's own where there
/// is no journal to give it one.
fn named_by(journal: &Option<Journal>) -> String {
    match journal {
        Some(journal) => journal.manifest().id.clone(),
        None => crate::id::mint(),
    }
}

/// This host's own resolver, unless the run must generate no DNS traffic.
fn resolver(config: &ZondConfig) -> Option<Resolver> {
    (!config.no_dns).then(Resolver::from_system)
}

/// The addresses a scan may not record a finding against.
async fn exclusions(
    excluded: &[String],
    resolver: Option<&Resolver>,
) -> Result<zond_engine::Exclusions, Error> {
    resolve::for_exclusion(excluded, resolver)
        .await
        .map_err(Error::engine)
}

/// A scan with nothing to scan.
fn nothing_to_scan() -> Error {
    Error::new(
        "request.no_targets",
        "a scan has to be given something to scan",
    )
}

/// What a person listing their scans sees beside the name.
fn probes(map: &TargetMap) -> String {
    match map.gross_targets() {
        Ok(1) => "1 probe".to_string(),
        Ok(probes) => format!("{probes} probes"),
        Err(_) => "a plan too large to count".to_string(),
    }
}

/// The same, for a sweep, which is counted in addresses.
fn addresses_in(addresses: &IpSet) -> String {
    match addresses.len() {
        1 => "1 address".to_string(),
        count => format!("{count} addresses"),
    }
}

/// And for a listen, which is counted in neither.
fn watching(links: &[String]) -> String {
    format!("listening on {}", links.join(", "))
}

/// Continues a scan that stopped part way.
///
/// The plan comes from the record rather than from the caller, which is what
/// makes it the same job rather than a new one that looks like it: the targets,
/// the ports and the order are the first sitting's, and what that sitting
/// settled is not asked again. The engine holds it to that, refusing a resume
/// whose plan has moved.
pub async fn resume(id: &str, root: &Path, under: Policy<'_>) -> Result<Started, Error> {
    let entry = store::list(root)
        .map_err(Error::engine)?
        .into_iter()
        .find(|entry| entry.manifest.id == id)
        .ok_or_else(|| Error::no_such_scan(id))?;

    let (journal, _settled, plan) =
        Journal::reopen(&entry.directory, Privilege::current()).map_err(Error::engine)?;

    // The technique the first sitting used, not this build's default. A resume
    // that switched from SYN to FIN half way through would be two scans wearing
    // one name.
    let mut config = ZondConfig::default();
    config.tcp_technique = journal.manifest().technique();

    let id = journal.manifest().id.clone();

    under.room(audited_as(plan.kind()), std::slice::from_ref(&id))?;

    match plan.kind() {
        ScanKind::PortScan => {
            let map = plan
                .targets()
                .cloned()
                .ok_or_else(|| holds_no(&id, "targets"))?;

            // Judged again rather than trusted because it was allowed once. A
            // policy that has narrowed since is a decision somebody made after
            // this scan started, and continuing it would be the daemon reaching
            // somewhere it is no longer allowed to.
            under.permit(
                &policy::reached_by(&map),
                "port_scan",
                std::slice::from_ref(&id),
            )?;
            under.record(&id, "port_scan", std::slice::from_ref(&id))?;

            let (session, task) =
                zond_engine::scan_with_journal(map, &config, Detections::embedded(), journal)
                    .await
                    .map_err(Error::engine)?;

            Ok(started(id, session, task, &config))
        }
        ScanKind::Discovery => {
            let addresses = plan
                .addresses()
                .cloned()
                .ok_or_else(|| holds_no(&id, "addresses"))?;

            under.permit(&addresses, "discovery", std::slice::from_ref(&id))?;
            under.record(&id, "discovery", std::slice::from_ref(&id))?;

            let (session, task) = zond_engine::discover_with_journal(addresses, &config, journal)
                .await
                .map_err(Error::engine)?;

            Ok(started(id, session, task, &config))
        }
        ScanKind::Listen => {
            let zones = plan
                .links()
                .map(<[_]>::to_vec)
                .ok_or_else(|| holds_no(&id, "links"))?;

            under.record(&id, "listen", std::slice::from_ref(&id))?;

            let scope = ListenScope::on(zones).recording_everything();
            let (session, task) = zond_engine::listen_with_journal(scope, &config, journal)
                .await
                .map_err(Error::engine)?;

            Ok(started(id, session, task, &config))
        }
        other => Err(Error::new(
            "scan.wrong_phase",
            format!("{id} is a {other} and this build cannot continue one"),
        )),
    }
}

/// A record whose plan does not hold what continuing it would need.
fn holds_no(id: &str, wanted: &'static str) -> Error {
    Error::new(
        "scan.wrong_phase",
        format!("the record of {id} holds no {wanted} to continue from"),
    )
}

/// Opens a journal for this scan, or none where the machine will not have one.
///
/// A run that cannot be recorded is still a run. The engine draws the same line
/// for its own callers: journalling is the front end's choice, and a front end
/// that cannot make it this time should not refuse the scan over it. What is
/// lost is only that the scan cannot be read back once this process is gone,
/// and the client is told which kind it got by the shape of the name.
fn record(root: &Path, plan: &Plan, summary: String) -> Option<Journal> {
    // Not `create_dir_all`: under `sudo` that leaves the directory owned by
    // root, and every later unprivileged run then finds a journal directory it
    // cannot write to. The engine creates it and gives it away.
    if let Err(refused) = store::prepare_root(root) {
        tracing::warn!("not recording this scan: {} ({refused})", root.display());
        return None;
    }

    match Journal::create(root, plan, Privilege::current(), summary) {
        Ok(journal) => Some(journal),
        Err(refused) => {
            tracing::warn!("not recording this scan: {refused}");
            None
        }
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
    asked.detection = match named::<proto::DetectionClass>(wire.detection) {
        None => None,
        // The one class a caller can name and mean something by that is still
        // not a ceiling. Refused rather than read as "no detections", which is
        // what it would otherwise quietly become.
        Some(class) if !crate::convert::is_a_ceiling(class) => {
            return Err(Error::new(
                "request.not_a_ceiling",
                format!(
                    "{} says what a detection does, not the most one may do; \
                     anything at all already permits it",
                    class.as_str_name()
                ),
            ));
        }
        Some(class) => crate::convert::detection_class_of(class)
            .map(zond_engine::config::envelope::DetectionEnvelope::up_to),
    };

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

    asked.evasion = wire.evasion.map(evasion).transpose()?;

    if let Some(named) = wire.settings {
        asked.settings = settings(named)?;
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

/// What a probe should look like on the wire.
fn evasion(wire: proto::Evasion) -> Result<EvasionProfile, Error> {
    let decoys = wire
        .decoys
        .iter()
        .map(|decoy| {
            decoy.parse().map_err(|_| {
                Error::new(
                    "request.bad_decoy",
                    format!("{decoy} is not an address to send from"),
                )
            })
        })
        .collect::<Result<_, _>>()?;

    let spoof_mac = wire
        .spoof_mac
        .as_deref()
        .map(|mac| {
            mac.parse().map_err(|_| {
                Error::new(
                    "request.bad_spoof_mac",
                    format!("{mac} is not a hardware address"),
                )
            })
        })
        .transpose()?;

    Ok(EvasionProfile {
        source_port: narrow(wire.source_port, "source port")?,
        ttl: narrow(wire.ttl, "TTL")?,
        fragment: narrow(wire.fragment_mtu, "fragment size")?,
        padding: narrow(wire.padding, "padding")?,
        flags: narrow(wire.flags, "TCP flag byte")?,
        bad_tcp_checksum: wire.bad_tcp_checksum.unwrap_or_default(),
        decoys,
        spoof_mac,
    })
}

/// The knobs a request may set for its own run.
fn settings(wire: proto::Settings) -> Result<Settings, Error> {
    let mut settings = Settings::new();

    settings.effort = named(wire.effort).and_then(crate::convert::scan_effort_of);
    settings.tcp_technique = named(wire.tcp_technique).and_then(crate::convert::tcp_technique_of);
    settings.sctp_technique =
        named(wire.sctp_technique).and_then(crate::convert::sctp_technique_of);
    settings.send_mode = named(wire.send_mode).and_then(crate::convert::send_mode_of);

    settings.host_timeout = wire.host_timeout.map(|s| Duration::from_secs(u64::from(s)));
    settings.scan_timeout = wire.scan_timeout.map(|s| Duration::from_secs(u64::from(s)));
    settings.host_probe_interval = wire
        .host_probe_interval_ms
        .map(|ms| Duration::from_millis(u64::from(ms)));

    settings.max_probe_rate = positive(wire.max_probe_rate, "maximum probe rate")?;
    settings.min_probe_rate = positive(wire.min_probe_rate, "minimum probe rate")?;
    settings.max_attempts = attempts(wire.max_attempts)?;

    settings.no_dns = wire.no_dns;
    settings.redact = wire.redact;
    settings.tls_enumeration = wire.tls_enumeration;
    settings.dampen_silent_hosts = wire.dampen_silent_hosts;
    settings.default_ports = wire.default_ports;

    settings.timeout_scale = wire
        .timeout_scale
        .map(|scale| {
            TimeoutScale::new(scale).ok_or_else(|| {
                Error::new(
                    "request.out_of_range",
                    format!("{scale} is not a timeout scale; it has to be greater than zero"),
                )
            })
        })
        .transpose()?;

    Ok(settings)
}

/// A number the schema carries wide and the engine wants narrow.
///
/// Refused rather than clamped. A caller that asked for a TTL of three hundred
/// meant something, and silently sending forty-four instead is a scan that did
/// not do what it was told.
fn narrow<T: TryFrom<u32>>(value: Option<u32>, what: &'static str) -> Result<Option<T>, Error> {
    value
        .map(|value| {
            T::try_from(value).map_err(|_| {
                Error::new(
                    "request.out_of_range",
                    format!("{value} is out of range for a {what}"),
                )
            })
        })
        .transpose()
}

/// A rate, which is meaningless at zero.
fn positive(value: Option<u32>, what: &'static str) -> Result<Option<NonZeroU32>, Error> {
    value
        .map(|value| {
            NonZeroU32::new(value)
                .ok_or_else(|| Error::new("request.out_of_range", format!("a {what} of none")))
        })
        .transpose()
}

/// How many times a target is asked, which is meaningless at zero and capped at
/// what one byte holds.
fn attempts(value: Option<u32>) -> Result<Option<NonZeroU8>, Error> {
    let Some(value) = narrow::<u8>(value, "attempt count")? else {
        return Ok(None);
    };

    NonZeroU8::new(value)
        .ok_or_else(|| {
            Error::new(
                "request.out_of_range",
                "an attempt count of none".to_string(),
            )
        })
        .map(Some)
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

    /// A request naming one target and whatever else a test cares about.
    fn asking(fill: impl FnOnce(&mut proto::StartRequest)) -> proto::StartRequest {
        let mut wire = proto::StartRequest {
            targets: vec!["127.0.0.1".into()],
            ..Default::default()
        };

        fill(&mut wire);
        wire
    }

    /// Everything an evasion profile carries reaches the engine.
    ///
    /// It did not: the schema named these and the conversion dropped them, so a
    /// caller asking for a source port of 53 got a scan from an ephemeral one and
    /// nothing said otherwise. A field the schema offers and the engine never
    /// sees is worse than one the schema does not offer.
    #[test]
    fn an_evasion_profile_reaches_the_engine() {
        let asked = request(asking(|wire| {
            wire.evasion = Some(proto::Evasion {
                source_port: Some(53),
                ttl: Some(12),
                fragment_mtu: Some(24),
                padding: Some(8),
                decoys: vec!["192.0.2.7".into(), "192.0.2.8".into()],
                flags: Some(0b0000_0010),
                spoof_mac: Some("00:00:5e:00:53:01".into()),
                bad_tcp_checksum: Some(true),
            });
        }))
        .expect("a profile the engine can use");

        let profile = asked.evasion.expect("the profile came through");
        assert_eq!(profile.source_port, Some(53));
        assert_eq!(profile.ttl, Some(12));
        assert_eq!(profile.fragment, Some(24));
        assert_eq!(profile.padding, Some(8));
        assert_eq!(profile.flags, Some(0b0000_0010));
        assert_eq!(profile.decoys.len(), 2);
        assert!(profile.spoof_mac.is_some());
        assert!(profile.bad_tcp_checksum);
    }

    /// And everything a settings table carries.
    #[test]
    fn a_settings_table_reaches_the_engine() {
        let asked = request(asking(|wire| {
            wire.settings = Some(proto::Settings {
                effort: Some(proto::ScanEffort::Thorough as i32),
                host_timeout: Some(60),
                scan_timeout: Some(600),
                host_probe_interval_ms: Some(250),
                max_probe_rate: Some(500),
                min_probe_rate: Some(10),
                max_attempts: Some(3),
                no_dns: Some(true),
                redact: Some(true),
                tls_enumeration: Some(true),
                dampen_silent_hosts: Some(true),
                default_ports: Some("22,80".into()),
                tcp_technique: Some(proto::TcpScanTechnique::Fin as i32),
                sctp_technique: Some(proto::SctpScanTechnique::CookieEcho as i32),
                send_mode: Some(proto::SendMode::Ethernet as i32),
                timeout_scale: Some(1.5),
            });
        }))
        .expect("settings the engine can use");

        let settings = asked.settings;
        assert_eq!(settings.host_timeout, Some(Duration::from_secs(60)));
        assert_eq!(settings.scan_timeout, Some(Duration::from_secs(600)));
        assert_eq!(
            settings.host_probe_interval,
            Some(Duration::from_millis(250))
        );
        assert_eq!(settings.max_probe_rate.map(NonZeroU32::get), Some(500));
        assert_eq!(settings.max_attempts.map(NonZeroU8::get), Some(3));
        assert_eq!(settings.no_dns, Some(true));
        assert_eq!(settings.redact, Some(true));
        assert_eq!(settings.default_ports.as_deref(), Some("22,80"));
        assert!(settings.effort.is_some());
        assert!(settings.tcp_technique.is_some());
        assert!(settings.sctp_technique.is_some());
        assert!(settings.send_mode.is_some());
        assert!(settings.timeout_scale.is_some());
    }

    /// A number too big for what it names is refused, not quietly cut down.
    ///
    /// A caller asking for a TTL of three hundred meant something. Sending
    /// forty-four instead is a scan that did not do what it was told and said so
    /// nowhere.
    #[test]
    fn a_value_that_will_not_fit_is_refused_rather_than_clamped() {
        let refused = request(asking(|wire| {
            wire.evasion = Some(proto::Evasion {
                ttl: Some(300),
                ..Default::default()
            });
        }))
        .expect_err("a TTL that is not one");

        assert_eq!(refused.code(), "request.out_of_range");
        assert!(refused.message().contains("300"), "{refused}");
        assert!(refused.message().contains("TTL"), "{refused}");
    }

    /// A rate of none is not a rate.
    #[test]
    fn a_probe_rate_of_none_is_refused() {
        let refused = request(asking(|wire| {
            wire.settings = Some(proto::Settings {
                max_probe_rate: Some(0),
                ..Default::default()
            });
        }))
        .expect_err("a rate of nothing per second");

        assert_eq!(refused.code(), "request.out_of_range");
        assert!(
            refused.message().contains("maximum probe rate"),
            "{refused}"
        );
    }

    /// A hardware address that is not one is refused, and the message says which.
    #[test]
    fn a_hardware_address_that_is_not_one_is_refused_by_name() {
        let refused = request(asking(|wire| {
            wire.evasion = Some(proto::Evasion {
                spoof_mac: Some("not a mac".into()),
                ..Default::default()
            });
        }))
        .expect_err("an address that is not one");

        assert_eq!(refused.code(), "request.bad_spoof_mac");
        assert!(refused.message().contains("not a mac"), "{refused}");
    }

    /// A request that says nothing about either leaves the engine's own defaults
    /// standing, rather than writing an empty profile over them.
    #[test]
    fn a_request_that_asks_for_neither_changes_neither() {
        let asked = request(asking(|_| {})).expect("the shortest useful request");

        assert!(asked.evasion.is_none(), "no profile was asked for");
        assert_eq!(asked.settings.effort, None, "and no effort named");
    }
}
