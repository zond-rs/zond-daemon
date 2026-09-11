#!/usr/bin/env python3
"""Sweeping a network from Python, and writing the result down.

The other half of what `scan.ts` shows. That one starts the daemon itself and
port-scans a host; this one does a discovery sweep, follows it, and exports the
report, and it reaches the daemon either way: as a program it starts, or as a
socket somebody else is already serving.

    cargo build
    ZONDD=./target/debug/zondd python3 examples/scan.py 127.0.0.1

    # or, against a daemon already listening
    ZOND_SOCKET=/run/zond/zond.sock python3 examples/scan.py 10.0.0.0/24

Standard library only. There is no client package to install because there is
nothing for one to do: the protocol is one JSON object per line.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
from typing import Any, Iterator


class Refused(Exception):
    """The daemon turned a request down.

    `code` is stable and worth branching on; the message is written for a person
    and may be reworded between releases.
    """

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


class Zond:
    """A daemon, held open for as long as you need it.

    One request is outstanding at a time, which keeps this short and is all a
    script needs. Nothing in the protocol requires it: every frame carries the
    id of the request it answers, so a client that wants several at once reads
    frames in one place and hands each to whoever asked.
    """

    def __init__(self, reading, writing, closing=None) -> None:
        self._reading = reading
        self._writing = writing
        self._closing = closing
        self._next = 1

    @classmethod
    def spawn(cls, binary: str | None = None) -> Zond:
        """Starts a daemon of our own, talking to it over its pipes."""
        child = subprocess.Popen(
            [binary or os.environ.get("ZONDD", "zondd"), "--stdio"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            text=True,
        )

        return cls(child.stdout, child.stdin, child.stdin.close)

    @classmethod
    def connect(cls, path: str) -> Zond:
        """Reaches a daemon somebody else is already running."""
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        connection.connect(path)

        return cls(
            connection.makefile("r", encoding="utf-8"),
            connection.makefile("w", encoding="utf-8"),
            connection.close,
        )

    def close(self) -> None:
        if self._closing:
            self._closing()

    def _send(self, method: str, params: dict[str, Any]) -> int:
        asked = self._next
        self._next += 1

        self._writing.write(json.dumps({"id": asked, "method": method, "params": params}) + "\n")
        self._writing.flush()

        return asked

    def _frame(self) -> dict[str, Any]:
        line = self._reading.readline()
        if not line:
            raise Refused("rpc.gone", "the daemon closed without answering")

        frame = json.loads(line)
        if "error" in frame:
            raise Refused(frame["error"]["code"], frame["error"]["message"])

        return frame

    def call(self, method: str, **params: Any) -> Any:
        """Asks one question and waits for its one answer."""
        self._send(method, params)

        return self._frame()["result"]

    def watch(self, scan_id: str, from_seq: int = 0) -> Iterator[dict[str, Any]]:
        """Follows a scan to its end, yielding what happens.

        `from_seq` is a cursor rather than a subscription that only runs forward
        from now: a client that went away passes the number it reached and
        misses nothing. From zero it gets every host as it stands before the
        live tail begins.
        """
        self._send("watch", {"scan_id": scan_id, "from_seq": from_seq})

        while True:
            frame = self._frame()
            if frame.get("end"):
                return

            yield frame["event"]


def main(target: str) -> int:
    socket_path = os.environ.get("ZOND_SOCKET")
    zond = Zond.connect(socket_path) if socket_path else Zond.spawn()

    try:
        started = zond.call(
            "start",
            kind="SCAN_KIND_DISCOVERY",
            targets=[target],
            os_detection="OS_DETECTION_PASSIVE",
        )
        scan = started["scan_id"]
        print(f"sweeping {target} as {scan}\n", flush=True)

        # A host event says this host changed and carries the whole of it as it
        # now stands, so keep the latest of each rather than treating them as a
        # log. Two events about one host are not two findings.
        hosts: dict[str, Any] = {}

        for event in zond.watch(scan):
            if "host" in event:
                hosts[event["host"]["address"]] = json.loads(event["host"]["document"])

            if "progress" in event and event["progress"].get("overall_total"):
                done = event["progress"].get("overall_done", 0)
                whole = event["progress"]["overall_total"]
                print(f"\r{done * 100 // whole:3d}%", end="", file=sys.stderr)

        print("\r    \r", end="", file=sys.stderr)

        for address, host in sorted(hosts.items()):
            if not host.get("alive"):
                continue

            name = host.get("hostname") or ""
            system = (host.get("os") or {}).get("name", "")
            print(f"{address:39} {name:24} {system}".rstrip())

        # The report the engine writes, in any of five shapes. JSON is the only
        # one carrying everything the scan found.
        written = zond.call("export", scan_id=scan, format="EXPORT_FORMAT_JSON")
        with open(f"{scan}.json", "w", encoding="utf-8") as out:
            out.write(written["document"])

        found = len(hosts)
        print(f"\n{found} host{'' if found == 1 else 's'}, written to {scan}.json")

    except Refused as refused:
        print(f"refused: {refused}", file=sys.stderr)
        return 1
    finally:
        zond.close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"))
