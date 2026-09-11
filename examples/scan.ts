// Scanning a network from TypeScript, by spawning zondd and talking to it.
//
// No port, no TLS, no client library and no build step: one process, two pipes
// and JSON. Nothing here is TypeScript-specific either, beyond the types. Any
// language that can start a program and read lines from it can do this in about
// as much code.
//
//   cargo build
//   ZONDD=./target/debug/zondd node examples/scan.ts 127.0.0.1
//
// Needs Node 23 or newer, which runs TypeScript without compiling it first.
// A daemon already listening on a socket is reached the same way, by connecting
// to it instead of spawning one; everything below the constructor is unchanged.

import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { createInterface } from "node:readline";

/** One thing that happened during a scan. Exactly one field below is set. */
type ScanEvent = {
  seq: number;
  host?: { address: string; document: string };
  stage?: { stage: Stage };
  progress?: Progress;
  failure?: { scanner: string; reason: string };
  finished?: { cause: "STOP_CAUSE_COMPLETED" | "STOP_CAUSE_ABORTED" | "STOP_CAUSE_TIMED_OUT" };
};

type Stage =
  | "STAGE_DISCOVERY" | "STAGE_PORTS" | "STAGE_SERVICES" | "STAGE_DETECTIONS"
  | "STAGE_TLS" | "STAGE_OS" | "STAGE_TRACEROUTE" | "STAGE_FINISHING";

type Progress = {
  stage: Stage;
  stage_done?: number;
  stage_total?: number;
  overall_done?: number;
  overall_total?: number;
};

/** One frame back from the daemon, labelled with the id that asked for it. */
type Frame = {
  id: number | null;
  result?: unknown;
  event?: ScanEvent;
  end?: true;
  error?: { code: string; message: string };
};

/** A scan daemon, held open for as long as you need it. */
class Zond {
  #child: ChildProcessWithoutNullStreams;
  #next = 1;
  #answers = new Map<number, (frame: Frame) => void>();
  #streams = new Map<number, (event: ScanEvent) => void>();

  constructor(binary = "zondd") {
    this.#child = spawn(binary, ["--stdio"], { stdio: ["pipe", "pipe", "inherit"] });

    createInterface({ input: this.#child.stdout }).on("line", (line) => {
      const frame: Frame = JSON.parse(line);
      if (frame.id === null) return;

      if (frame.event) this.#streams.get(frame.id)?.(frame.event);
      else this.#answers.get(frame.id)?.(frame);
    });
  }

  close() {
    this.#child.stdin.end();
  }

  /** Asks one question and waits for its one answer. */
  #call<T>(method: string, params: unknown): Promise<T> {
    const id = this.#next++;

    return new Promise<T>((resolve, reject) => {
      this.#answers.set(id, (frame) => {
        this.#answers.delete(id);
        // The code is stable and the message is for a person, so branch on one
        // and show the other.
        if (frame.error) reject(new ScanRefused(frame.error.code, frame.error.message));
        else resolve(frame.result as T);
      });

      this.#child.stdin.write(JSON.stringify({ id, method, params }) + "\n");
    });
  }

  /** Starts a scan and answers with its name. */
  async start(request: Record<string, unknown>): Promise<string> {
    const { scan_id } = await this.#call<{ scan_id: string }>("start", request);
    return scan_id;
  }

  /** Winds a scan down. What it already found is kept. */
  stop(scanId: string) {
    return this.#call("stop", { scan_id: scanId });
  }

  /**
   * Follows a scan to its end.
   *
   * `from` is a cursor rather than a subscription, so a client that went away
   * and came back passes the sequence number it got to and misses nothing. From
   * zero it gets every host as it now stands before the live tail begins.
   */
  watch(scanId: string, from: number, onEvent: (event: ScanEvent) => void): Promise<void> {
    const id = this.#next++;

    return new Promise((resolve, reject) => {
      this.#streams.set(id, onEvent);
      this.#answers.set(id, (frame) => {
        this.#streams.delete(id);
        this.#answers.delete(id);
        if (frame.error) reject(new ScanRefused(frame.error.code, frame.error.message));
        else resolve();
      });

      this.#child.stdin.write(
        JSON.stringify({ id, method: "watch", params: { scan_id: scanId, from_seq: from } }) + "\n",
      );
    });
  }
}

class ScanRefused extends Error {
  code: string;

  constructor(code: string, message: string) {
    super(`${code}: ${message}`);
    this.code = code;
  }
}

// ── Using it ────────────────────────────────────────────────────────────────

/** As much of a host as this example reads. The rest is in `zond-report-v1`. */
type Host = {
  primary_ip: string;
  hostname: string | null;
  ports: Array<{
    port: number;
    protocol: string;
    state: string;
    service: { name: string; product?: string; version?: string } | null;
    findings: Array<{ title: string; severity?: string }>;
  }>;
  findings: Array<{ title: string; severity?: string }>;
};

const target = process.argv[2] ?? "127.0.0.1";
const zond = new Zond(process.env.ZONDD ?? "zondd");

const id = await zond.start({
  targets: [target],
  ports: "22,80,443,8080",
  service_detection: "SERVICE_DETECTION_BANNER",
  detection: "DETECTION_CLASS_ACTIVE_BENIGN",
});

console.log(`scanning ${target} as ${id}\n`);

// A host event says this host changed, and carries the whole of it as it now
// stands. So keep the latest of each rather than treating them as a log: two
// events about one host are not two findings.
const hosts = new Map<string, Host>();
const failures: string[] = [];

await zond.watch(id, 0, (event) => {
  if (event.host) hosts.set(event.host.address, JSON.parse(event.host.document));

  if (event.stage) {
    process.stdout.write(`\r${event.stage.stage.replace("STAGE_", "").toLowerCase().padEnd(12)}`);
  }

  if (event.progress?.overall_total) {
    const { overall_done = 0, overall_total } = event.progress;
    process.stdout.write(`\r${" ".repeat(12)}${Math.floor((overall_done * 100) / overall_total)}%   `);
  }

  // Kept rather than printed, so they do not land in the middle of the line the
  // progress is being written to.
  if (event.failure) failures.push(`${event.failure.scanner}: ${event.failure.reason}`);
});

process.stdout.write("\r" + " ".repeat(20) + "\r");

for (const host of hosts.values()) {
  console.log(host.hostname ? `${host.primary_ip} (${host.hostname})` : host.primary_ip);

  for (const port of host.ports.filter((port) => port.state === "open")) {
    const named = [port.service?.name, port.service?.product, port.service?.version]
      .filter(Boolean)
      .join(" ");
    console.log(`  ${String(port.port).padStart(5)}/${port.protocol}  ${named}`);

    for (const finding of port.findings) {
      console.log(`         ! ${finding.title}`);
    }
  }

  for (const finding of host.findings) {
    console.log(`  ! ${finding.title}`);
  }
}

for (const failure of failures) console.error(`\n${failure}`);

zond.close();
