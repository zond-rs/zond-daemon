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

## Status

Pre-release. The schema is pinned and linted, and the conversion between the
engine's vocabulary and the schema's is covered by tests that walk the engine's
own lists, so a value added upstream fails a build here rather than reaching a
client as a number nothing can name.

No transport yet. The first will be newline-delimited JSON over a pipe, which
needs no port, no TLS and no authentication, and can be driven from a shell.

## Building

```bash
cargo build
```

Nothing else to install. The protocol is compiled by `protox`, a protobuf
compiler in the dependency tree, so no system `protoc` is involved. The engine is
expected in `../zond-engine`.
