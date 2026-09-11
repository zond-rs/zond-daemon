<h1 align="center">Zond Daemon</h1>

<p align="center">
  <a href="https://www.gnu.org/licenses/agpl-3.0"><img src="https://img.shields.io/badge/License-AGPL_v3-blue.svg" alt="License: AGPL v3"></a>
  <img src="https://img.shields.io/badge/rustc-1.93+-blue.svg" alt="Rust Version">
</p>

<p align="center">
  Drives <a href="https://github.com/zond-rs/zond-engine">Zond Engine</a> over a wire protocol, so a front end
  written in anything can start a scan, follow it while it runs, and stop it.<br>
  The engine is a Rust library. This is how everything else reaches it.
</p>

## The schema is the product

What makes a scanner turn up inside other people's software is not its library,
which only its own language can call. The artefact here is
[`proto/zond/v1/scan.proto`](proto/zond/v1/scan.proto). The Rust in `src/` is one
implementation of it, and a TypeScript or Go client generated from the same file
is another consumer on equal terms.

Four calls: start a scan, follow it from a cursor, ask where it got to, stop it.

Hosts and reports travel as the JSON that `zond-report-v1` already describes,
rather than as a second description of the same documents written in proto. That
schema is published, versioned, and held to the engine's output by a conformance
test. One contract per thing, each in the form that thing is already written in.

## Running it

```bash
zondd --stdio                  # for a client that started this process
zondd --listen /run/zond.sock  # for a client that could not
```

Both speak the same protocol: one JSON object per line, in and out.

```text
→ {"id":1,"method":"start","params":{"targets":["10.0.0.0/24"],"ports":"22,80"}}
← {"id":1,"result":{"scan_id":"0GBQK4W7M8001"}}
→ {"id":2,"method":"watch","params":{"scan_id":"0GBQK4W7M8001"}}
← {"id":2,"event":{"seq":1,"stage":{"stage":"STAGE_PORTS"}}}
← {"id":2,"event":{"seq":2,"host":{"address":"10.0.0.1","document":"{…}"}}}
← {"id":2,"end":true}
```

| | |
|---|---|
| `start` | a port scan, a discovery sweep or a listen, by the `kind` on the request |
| `watch` | follow one from a cursor: what it has found, then what it finds next |
| `get` | where it got to, as one answer |
| `stop` | wind it down, keeping what it already found |
| `export` | write a finished one down as JSON, JSONL, CSV, HTML or nmap XML |
| `list` | the scans this daemon has a record of, newest first |
| `prune` | throw away the records nobody asked to keep |
| `resume` | continue one that stopped part way, from the plan in its record |
| `diff` | what changed between two of them |
| `merge` | several folded into one report |
| `detections` | what a scan would check for, without scanning |

`watch` takes a cursor rather than being a subscription that only runs forward
from now, so a client that went away and came back passes the sequence number it
reached and misses nothing. From zero it gets every host as it stands before the
live tail begins.

A scan is written down as it runs, so it outlives the process and `list`, `get`,
`watch` and `export` all answer for one some earlier daemon ran. `--journal-dir`
says where; `--no-journal` means scans that die with the process.

The socket is created readable and writable by the user running the daemon and
nobody else. A process that can put arbitrary packets on the wire is not one to
hand to every account on the machine, so sharing it with another container is
something an operator does on purpose.

## Status

Pre-release. The schema is pinned and linted, and the conversion between the
engine's vocabulary and the schema's is covered by tests that walk the engine's
own lists, so a value added upstream fails a build here rather than reaching a
client as a number nothing can name.

A scan's log lives in memory and goes when the process does. Its durable form is
the journal the engine already writes, which is what will make watching a scan
that finished last week the same call as watching one still running.

## Building

```bash
cargo build
```

Nothing else to install. The protocol is compiled by `protox`, a protobuf
compiler in the dependency tree, so no system `protoc` is involved. The engine is
expected in `../zond-engine`.
