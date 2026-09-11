<h1 align="center">Zond Daemon</h1>

<p align="center">
  <a href="https://www.gnu.org/licenses/agpl-3.0"><img src="https://img.shields.io/badge/License-AGPL_v3-blue.svg" alt="License: AGPL v3"></a>
  <img src="https://img.shields.io/badge/rustc-1.93+-blue.svg" alt="Rust Version">
</p>

<p align="center">
  Runs <a href="https://github.com/zond-rs/zond-engine">Zond Engine</a> scans for programs that are not Rust.<br>
  One JSON object per line, over a pipe or a unix socket.
</p>

## Running it

```bash
zondd --stdio                       # the client starts the daemon itself
zondd --listen /run/zond/zond.sock  # the daemon is already running
```

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
| `start` | a port scan, a sweep or a listen, by the `kind` on the request |
| `watch` | follow one: what it has found, then what it finds next |
| `get` | where it got to |
| `stop` | wind it down, keeping what it found |
| `export` | JSON, JSONL, CSV, HTML or nmap XML |
| `list` | the scans on record, newest first |
| `prune` | throw records away |
| `resume` | continue one that stopped |
| `diff` | what changed between two |
| `merge` | several folded into one report |
| `detections` | what a scan would check for, without scanning |

`watch` takes a cursor, so a client that drops and reconnects passes the sequence
number it reached and misses nothing.

Scans are written down as they run, so `list`, `get`, `watch` and `export` all
answer for one an earlier daemon started. `--journal-dir` says where,
`--no-journal` turns it off.

## Bounding it

```bash
zondd --listen /run/zond/zond.sock --allow 10.0.0.0/8 --audit /var/lib/zond/audit.jsonl
```

| | |
|---|---|
| `--allow` | where scans may reach. Repeatable. None named permits anywhere |
| `--deny` | where they may not, whatever `--allow` said |
| `--audit` | every scan and every refusal, one JSON object per line |
| `--max-concurrent` | how many at once. A request over the limit is refused |
| `--socket-group` | a numeric gid the socket is opened to as well |

The policy is checked against the addresses a request resolves to, not the names
it used, so a hostname cannot point somewhere the policy forbids. A request
reaching partly outside is refused whole rather than trimmed. `--audit` fails
closed: if the log cannot be written, the scan does not run.

```json
{"at":"2026-09-11T17:17:49Z","event":"started","kind":"port_scan","scan_id":"0384HF6YZY000","targets":["127.0.0.1"]}
{"at":"2026-09-11T17:17:49Z","event":"refused","code":"scope.refused","targets":["192.0.2.0/24"],"detail":"…"}
```

## In a container

```bash
docker run --network host --cap-drop ALL --cap-add NET_RAW --cap-add NET_ADMIN \
  -v zond:/run/zond ghcr.io/zond-rs/zond-daemon:0.1.0 --listen /run/zond/zond.sock
```

Host networking, because a container on a bridge network has no layer 2 to the
LAN and resolves `lan` to its own subnet. `NET_RAW` on the scanner and nowhere
else: the front end joins `--socket-group`, holds no capabilities, and reaches
the daemon through the shared volume. [`deploy/compose.yaml`](deploy/compose.yaml)
runs both.

Building the image instead of pulling it needs a context holding both
repositories, since this crate names the engine at `../zond-engine`:

```bash
docker build -f zond-daemon/Dockerfile -t zond-daemon:0.1.0 .
```

## Examples

Three clients in three languages, none of them using a library.

[`examples/scan.ts`](examples/scan.ts) starts a daemon, port-scans a host with
detections, and prints findings as they arrive.

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

[`examples/scan.py`](examples/scan.py) sweeps a range, follows it to the end and
exports the report. Standard library only, over a pipe or a socket.

```bash
ZONDD=./target/debug/zondd python3 examples/scan.py 127.0.0.1
ZOND_SOCKET=/run/zond/zond.sock python3 examples/scan.py 10.0.0.0/24
```

[`examples/detections.sh`](examples/detections.sh) is one line of JSON and `jq`:
what a scan would check for, grouped by what it does to the target.

```bash
ZONDD=./target/debug/zondd sh examples/detections.sh DETECTION_CLASS_ACTIVE_BENIGN
```

## Building

```bash
cargo build
```

Nothing to install first. The schema is compiled by `protox` rather than a system
`protoc`, and the engine is expected at `../zond-engine`.

The protocol is [`proto/zond/v1/scan.proto`](proto/zond/v1/scan.proto). Clients
in other languages generate from it; the Rust here is one implementation of it,
not the definition.
