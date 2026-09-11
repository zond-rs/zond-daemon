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
something an operator does on purpose — which is what `--socket-group` is. Named
a numeric group id, the socket is given to that group and opened to it, and the
front end joins the group instead of being run as this process's user. That is
the difference between an unprivileged front end and one running as root to open
a socket, since a daemon holding `NET_RAW` usually is root.

## Bounding it

```bash
zondd --listen /run/zond.sock --allow 10.0.0.0/8 --audit /var/lib/zond/audit.jsonl
```

A scanner reached over a socket is a scanner whoever holds that socket can aim,
so where it may be pointed is a setting of the daemon rather than of a request.
A client that has been taken over can ask for anything; what it gets is still
what the operator allowed.

`--allow` says where scans may reach and `--deny` says where they may not
whatever `--allow` said. Either may be given on its own, both are repeatable, and
a daemon given neither may be pointed anywhere, which is what every scanner does.

The policy is applied to the addresses a request resolved to, never to the words
it named them with: a hostname resolves to whatever its owner points it at, so a
policy compared against the text would be one somebody else writes the other half
of. A request reaching partly outside is refused whole rather than trimmed to
fit, because a caller who asked for a range and got a scan of part of it has a
report that says less than they think.

`--audit` writes every scan started and every request refused as one JSON object
per line. It fails closed: where a log is named and cannot be written, the scan is
refused, a scan nobody can account for being the one outcome an audit exists to
prevent.

`--max-concurrent` is how many scans it will run at once, and a request arriving
when that many are running is refused rather than queued. A person at a terminal
is their own ceiling: they ask for one scan because they are waiting for it. A
front end serving other people is not, and whoever asks it for a hundred scans is
not the one who pays for them.

```json
{"at":"2026-09-11T17:17:49Z","event":"started","kind":"port_scan","scan_id":"0384HF6YZY000","targets":["127.0.0.1"]}
{"at":"2026-09-11T17:17:49Z","event":"refused","code":"scope.refused","targets":["192.0.2.0/24"],"detail":"…"}
```

## In a container

```bash
docker run --network host --cap-drop ALL --cap-add NET_RAW --cap-add NET_ADMIN \
  -v zond:/run/zond ghcr.io/zond-rs/zond-daemon:0.1.0 --listen /run/zond/zond.sock
```

[`deploy/compose.yaml`](deploy/compose.yaml) has the shape, and the three things
people get wrong. The scanner needs the host's own network, because a container
on a bridge network has no layer 2 to the LAN and resolves `lan` to its own
subnet. It needs raw sockets, which nothing else does: whatever a person talks to
holds no capabilities at all and reaches the daemon through a socket in a shared
volume, which is where the policy is enforced. And those two make the daemon
root, so the socket goes to a group the front end is in rather than to the user
the front end would then have to be.

Building the image rather than pulling it is a build whose context holds both
repositories, this crate naming the engine at `../zond-engine`:

```bash
docker build -f zond-daemon/Dockerfile -t zond-daemon:0.1.0 .
```

## Examples

Three clients, in three languages, none of them needing a library. There is
nothing for one to do: the protocol is one JSON object per line.

**[`examples/scan.ts`](examples/scan.ts)** — TypeScript, no build step. Starts a
daemon, port-scans a host with detections, and prints what it finds as it finds
it.

```bash
cargo build
ZONDD=./target/debug/zondd node examples/scan.ts 127.0.0.1
```

```text
127.0.0.1 (localhost)
     22/tcp  ssh OpenSSH 10.3
         ! openssh 10.3 has 11 known vulnerabilities
   8080/tcp  http
         ! CouchDB served its database list without authentication
```

**[`examples/scan.py`](examples/scan.py)** — Python, standard library only. The
other half: a discovery sweep, followed to the end, then exported. It reaches the
daemon either way, as a program it starts or as a socket somebody else is serving.

```bash
ZONDD=./target/debug/zondd python3 examples/scan.py 127.0.0.1
ZOND_SOCKET=/run/zond/zond.sock python3 examples/scan.py 10.0.0.0/24
```

```text
sweeping 127.0.0.1 as 06G93A052D9P33GN

127.0.0.1                               localhost

1 host, written to 06G93A052D9P33GN.json
```

**[`examples/detections.sh`](examples/detections.sh)** — a line of JSON and `jq`.
What a scan would check for, grouped by what running it does to the target, which
is the thing `--detection` sets a ceiling on.

```bash
ZONDD=./target/debug/zondd sh examples/detections.sh DETECTION_CLASS_ACTIVE_BENIGN
```

```text
DERIVED  (18)
    ad-dns-server  Active Directory server (Kerberos + DNS)
    …
```

Nothing in any of them is particular to its language beyond the types. Anything
that can start a program, or open a socket, and read lines from it does this in
about as much code.

## Status

Pre-release, and complete against what `zond` itself does: every one of its
commands is reachable here.

The schema is pinned and linted, and the conversion between the engine's
vocabulary and the schema's is covered by tests that walk the engine's own lists,
so a value added upstream fails a build here rather than reaching a client as a
number nothing can name.

## Building

```bash
cargo build
```

Nothing else to install. The protocol is compiled by `protox`, a protobuf
compiler in the dependency tree, so no system `protoc` is involved. The engine is
expected in `../zond-engine`.
