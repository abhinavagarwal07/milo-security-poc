# UASC pre-authentication direct-memory leak (unauthenticated remote DoS)

> **On identifiers.** A CVE ID has been reserved for this finding by the Eclipse Foundation (CNA) but
> is not yet published. Per the CNA's terms a reserved identifier must not be used in public
> communication before publication, so none is cited here; this file will be updated once it is public.
**Component:** `opc-ua-stack/transport/.../server/uasc/UascServerAsymmetricHandler.java`
**Class:** CWE-401 Missing Release of Memory after Effective Lifetime
**Impact:** Denial of service — unauthenticated remote attacker permanently leaks pooled
DIRECT (off-heap) memory; on a container/cgroup-memory-limited deployment (the common
Docker/Kubernetes shape) this crashes the process (`OOMKilled`, `ExitCode 137`) within
seconds.
**CVSS 3.1:** 7.5 (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`)
**CVSS 4.0:** 8.7 High (`CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N`)
**Auth:** none — the attack never gets past `OpenSecureChannel`, i.e. before any session,
identity token, or application authentication exists.
**Affected:** Eclipse Milo 0.6.0 – 1.1.4
**Fixed:** 1.1.5, commit [`459715793ec54b0f33367a14f94264500a0d872b`](https://github.com/eclipse-milo/milo/commit/459715793ec54b0f33367a14f94264500a0d872b) ("Release pending UASC chunks on teardown", PR #1800)

## Root cause

`UascServerAsymmetricHandler` (and its symmetric-channel sibling) accumulates partial
`OpenSecureChannel` chunks in a `List<ByteBuf> chunkBuffers` while a multi-chunk message
is still being assembled. Each `ByteBuf` is a pooled **direct** (off-heap) buffer,
allocated by `ChunkDecoder` before the server has authenticated the peer, checked the
final chunk flag, or created any channel/session state.

Pre-fix (≤ 1.1.4), release of that list was inconsistent across the ways a partial
sequence can be interrupted:

```java
// exceptionCaught() DID release the buffers:
public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) throws Exception {
  chunkBuffers.forEach(ReferenceCountUtil::safeRelease);
  chunkBuffers.clear();
  ...
}

// channelInactive() did NOT:
public void channelInactive(ChannelHandlerContext ctx) throws Exception {
  if (secureChannelTimeout != null) {
    secureChannelTimeout.cancel();
    secureChannelTimeout = null;
  }
  super.channelInactive(ctx);   // chunkBuffers never released
}
```

An attacker who opens a TCP connection, sends a valid `HELLO`, then sends
`OpenSecureChannel` chunks that are always marked **intermediate** (chunk type `'C'`,
never the final `'F'`) and simply closes the socket (TCP FIN / RST) drives
`channelInactive` — not `exceptionCaught` — and every buffer accumulated for that
connection is leaked permanently. Staying at or below the server's default
`maxChunkCount` (64) also avoids the "max chunk count exceeded" exception path, which
*would* have released them even pre-fix.

The fix (1.1.5, PR #1800) centralizes lifecycle cleanup so `channelInactive`,
`handlerRemoved0`, and `exceptionCaught` all release pending chunk buffers, and makes
`ChunkDecoder` ownership transfer exception-safe across malformed final messages.

## Reachability

One TCP connection, no certificate, no security policy beyond `None`, no identity, no
prior traffic: `HELLO` → `ACK` → N × intermediate `OpenSecureChannel` chunks → close
socket. Every accepted connection like this leaks `chunksPerConn × chunkSize` bytes of
pooled direct memory that no GC, `System.gc()`, or `jcmd GC.run` can reclaim — only a
process restart clears it, because the buffers are still (falsely) considered live.

## What this PoC demonstrates, and what it honestly does not

Two scenarios, both attacking a **default-configuration** Milo server (default
`RateLimitingHandler`, default chunk/connection limits — nothing was loosened to make
the attack easier), from a **non-loopback** attacker (Milo's rate limiter exempts only
loopback peers, so this is required for the limiter to be genuinely active — not a bypass
of it):

- **Scenario A** — `-XX:MaxDirectMemorySize=64m` (a deployer explicitly caps direct
  memory and the JVM survives the caught `OutOfMemoryError`): the leak is unambiguously
  real (climbs to a plateau near the cap, a forced `jcmd GC.run` reclaims nothing, the
  server logs genuine `OutOfMemoryError: Cannot reserve ... direct buffer memory` from
  `UascServerAsymmetricHandler`) — but the pooled arena self-limits at a plateau a few
  MiB short of the cap, so a lightweight legitimate handshake still fits in existing
  arena pages and keeps succeeding. **For this specific configuration, full `A:H` is NOT
  demonstrated** — the honest impact is degradation (`A:L`) plus a durable, unrecoverable
  memory loss, not denial.
- **Scenario B** — a container/cgroup memory limit with no protective direct-memory cap
  (the common Docker/Kubernetes deployment shape: `-Xmx`/`-XX:MaxDirectMemorySize` set
  generously, the actual binding constraint is `--memory`): there is no self-limiting
  plateau. RSS grows until the kernel OOM-killer terminates the container. **This is the
  headline result: `OOMKilled=true`, `ExitCode=137`, in seconds, from a SINGLE attacking
  IP, and legitimate clients are denied until the operator restarts the container.** This
  is full, demonstrated `A:H`.

Both scenarios are re-run against Milo **1.1.5** as a negative control: identical source
code, identical attack, only the Milo jars on the classpath differ (`-Dmilo.version=1.1.5`).
1.1.5 shows no leak (pinned direct memory returns to baseline within seconds) and never
gets OOM-killed under the same attack.

### Scenario B is a single attacking IP by design

A single source IP is the least-arguable demonstration — nobody can dismiss it as "you
just used more machines." `poc/scenarioB.sh` runs this as the **headline** (`MODE=single`,
the default). A 4-source-IP run exists only as a clearly-labeled **acceleration
comparison** (`MODE=multi`) showing that more attacking IPs reach the same total leaked
bytes faster; it is never the primary claim.

### Eight things this PoC proves, and where to find each one in `evidence/`

Every one of these appears verbatim in `evidence/scenarioB-vulnerable-1.1.4-single-ip.log`
(headline run) and is machine-checked by `scenarioB.sh` itself — the script exits nonzero
if any of them don't hold:

| # | Proof point | Measured (this session's actual run) |
|---|---|---|
| 1 | Legitimate client works **before** the attack | `LEGIT_CLIENT_RESULT=SUCCESS` |
| 2 | Accepted connections + exact bytes sent | **40 connections, 160.00 MiB**, single source IP |
| 3 | Direct memory **and** container RSS grow | direct memory 0 → tracked every 2s; container RSS climbed toward the 550 MiB limit |
| 4 | Kernel records the kill | **`OOMKilled=true`, `ExitCode=137`**, at **~t+10s** |
| 5 | Legitimate OPC UA client **fails against a resolvable endpoint** | `LEGIT_CLIENT_RESULT=FAILURE ... status=Bad_ConnectionRejected ... Connection refused: /127.0.0.1:12686` — a genuine transport-level refusal, not a Docker-DNS name-resolution artifact (see note below) |
| 6 | Unrelated co-located workload in the same JVM also stops | the heartbeat thread (see below) — last line `HEARTBEAT seq=23`, then nothing: **process-wide blast radius**, not a per-connection failure |
| 7 | Service returns **only** after restart | `LEGIT_CLIENT_RESULT=SUCCESS` after `docker start`, not before |
| 8 | Fixed 1.1.5 survives the **identical** attack sequence | see the identical-sequence table below |

**On proof point 5, and why it changed from an earlier draft of this PoC:** the legitimate
client does **not** run as a container resolving the server by its Docker-network hostname
(`opc.tcp://server:12686/milo`). Docker's embedded DNS deregisters a container's network
alias the instant it exits — even before `docker rm` — so a probe dialing that hostname
fails with `java.net.UnknownHostException` once the server is OOM-killed. That's a true
fact (the container is gone) but it's a **DNS artifact**, and a reviewer could fairly say
it only proves the container vanished, not that "the service" refused a connection.
Instead, `scenarioB.sh` publishes the server's port to the host (`-p 12686:12686`) and
runs the legitimate client as a **plain host process** dialing `opc.tcp://127.0.0.1:12686/milo`.
`127.0.0.1` always resolves, so the failure captured above is a genuine
`Bad_ConnectionRejected` / `Connection refused` at the transport layer — the actual
signature of "the service is down," not "the name is gone."

### Process-wide blast radius: the co-located heartbeat

`VictimServer.java` runs a second background thread with **zero dependency on Netty, OPC
UA, or the request-handling path** — just `seq++`, print, sleep 1s, forever. It stands in
for any unrelated workload that happens to share the JVM (a metrics exporter, a scheduled
job, another protocol handler). When the leak OOM-kills the process, this thread dies with
it even though it never touched the vulnerable code path — proof that the blast radius is
**the entire process**, not just OPC UA connection handling.

### Identical-sequence comparison: vulnerable 1.1.4 vs fixed 1.1.5

Same single source IP, same chunk pattern (`64` chunks × `65535` bytes), same
`INTER_CONN_SLEEP=0.30s`, same `DURATION_SEC=180`. The only difference between the two
runs is the Milo jar on the classpath:

| | 1.1.4 (vulnerable) | 1.1.5 (fixed) |
|---|---|---|
| Accepted connections | **40** | **502** (12.6× more, and the run still had headroom) |
| Bytes sent | **160.00 MiB** | **2007.97 MiB** (12.6× more) |
| Container outcome | **`OOMKilled=true`, `ExitCode=137`** at ~t+10s | **survived the full 180s** attack window |
| Direct memory | climbed to **306.5 MiB** before the kill | stayed at **0.00 MiB** the entire run |
| Legit client after attack | **FAILED** (`Connection refused`, resolvable endpoint) | **SUCCESS** |
| Co-located heartbeat | **STOPPED** (process-wide) | **RUNNING** throughout |

`scenarioB.sh` enforces this automatically: the fixed-build run is passed
`MIN_ACCEPTED_CONNS=40` (the exact count that killed 1.1.4) and asserts its own accepted
count is `>=` that value, so the comparison can't be quietly won by giving the fixed build
an easier run.

### Acceleration comparison (multi-IP, secondary — NOT the headline claim)

The same total leak threshold kills the server regardless of how many source IPs produced
it — more IPs just reach that threshold faster in parallel:

| | Single IP (headline) | 4 source IPs (acceleration comparison) |
|---|---|---|
| Accepted connections at kill | 40 | 42 |
| Bytes sent at kill | 160.00 MiB | 168.00 MiB |
| Time to `OOMKilled=137` | **~10s** | **~4s** |

### Screenshot summary (actual output from this session's headline run)

```
Legitimate client before attack: OK
Attacker: single source IP, 40 connections, 160.00 MiB sent
Server direct memory: 0 -> 306.50MiB (cap 512m; container limit 550m is the binding constraint)
Container: OOMKilled=1 ExitCode=137 after ~10s
Legitimate client after attack: FAILED
Co-located workload: STOPPED (process-wide)
Legitimate client after restart: OK
```

and the identical-sequence 1.1.5 control:

```
Legitimate client before attack: OK
Attacker: single source IP, 502 connections, 2007.97 MiB sent
Server direct memory: 0 -> 0.00MiB (cap 512m; container limit 550m is the binding constraint)
Container: OOMKilled=false ExitCode=0 (survived full 180s attack)
Legitimate client after attack: OK
Co-located workload: RUNNING (process healthy)
```

### Scenario A results (bounded direct-memory cap, host-only)

| Build | Result |
|---|---|
| 1.1.4 vulnerable | pinnedDirect peak **58.0 MiB**/64 MiB cap, **7** genuine `OutOfMemoryError`s, forced GC reclaimed **0** bytes (54.7 MiB before/after), legit clients still served (3/3) → degradation, not full denial |
| 1.1.5 fixed | pinnedDirect peak **7.9 MiB** despite 193 accepted leak attempts, **0** OOM errors, back to **0.00 MiB** baseline, legit clients unaffected |

Full transcripts (this session's actual `./run.sh` execution, unedited):
`evidence/scenarioA-vulnerable-1.1.4.log`, `evidence/scenarioA-fixed-1.1.5.log`,
`evidence/scenarioB-vulnerable-1.1.4-single-ip.log` (**headline**),
`evidence/scenarioB-fixed-1.1.5-single-ip.log` (identical-sequence control),
`evidence/scenarioB-vulnerable-1.1.4-multi-ip.log` (acceleration comparison, secondary).

### Exact dependency artifact hashes (this session's run, from local `~/.m2`)

```
milo-sdk-server-1.1.4.jar  sha256=9205ac17fa5454f0974276c6d84939dae9342065a753c21f7f41f4d4a1f32c51
milo-sdk-client-1.1.4.jar  sha256=8ac8054a62eb99bd25b7cbdb2dda7144ccb50c4ffc08b12f4f6b9d7cac872f5f
milo-stack-core-1.1.4.jar  sha256=e099d52e53c3d189f6274366badf298e06efb6cb3715380f246f60e1bc94d488
milo-sdk-server-1.1.5.jar  sha256=1f24ced03e6d517c4e3d6da043f5bf17e45ef6efcc57505864759fc5ced63a82
milo-sdk-client-1.1.5.jar  sha256=6a4b22afa5c92ce8e921623d5a32f0e9989527b0c3bd8db6fb5866036c248010
milo-stack-core-1.1.5.jar  sha256=6ee0a0f314c463f6b97dd06e8b0650d8393ebb0b28328b0951c763d231819c6e
poc/victim-server 1.1.4 shaded jar  sha256=2a7231ade96fdf7f56ba011fd789c0a4edd90f6ad532ff0f8b8d335e21afe022
poc/victim-server 1.1.5 shaded jar  sha256=c0bb02ba24dcaab554444adde800df5b71c981c6927762b64173fd0fb8d35f54
```

`./run.sh` recomputes and prints these on every run so they can be checked against
whatever is actually in `~/.m2` at reproduction time.

## Reproduction

```
cd poc
./run.sh                 # builds both jars offline, prints artifact hashes, builds Docker
                          # images, runs Scenario A (both versions) + Scenario B headline
                          # (single-IP, both versions, identical-sequence-enforced) +
                          # Scenario B acceleration comparison (multi-IP, vulnerable only)
./run.sh --skip-docker   # host-only: Scenario A for both versions, Scenario B skipped
```

Or individually:

```
cd poc
( cd victim-server && mvn -o package -Dmilo.version=1.1.4 )   # or -Dmilo.version=1.1.5
mkdir -p victim-server/target-versions
cp victim-server/target/victim-server.jar victim-server/target-versions/victim-server-1.1.4.jar

./scenarioA.sh victim-server/target-versions/victim-server-1.1.4.jar vulnerable-1.1.4 /tmp/out.log

docker build -f Dockerfile.app --build-arg JAR_PATH=victim-server/target-versions/victim-server-1.1.4.jar -t memory-leak-app:1.1.4 .
docker build -f Dockerfile.attacker -t memory-leak-attacker:latest .
# scenarioB.sh <IMAGE> <LABEL> <RESULTS_FILE> [MEMORY_LIMIT] [MODE single|multi] [DURATION_SEC] [MIN_ACCEPTED_CONNS]
./scenarioB.sh memory-leak-app:1.1.4 vulnerable-1.1.4 /tmp/out-b.log 550m single 180 0
```

Each script exits **0 only if every one of its checks passed** (nonzero on any mismatch
between expected and observed outcome), so `run.sh`'s own exit code is a machine-checked
verdict across the whole PoC, not just a "did it run" signal.

**Requirements:** JDK 17, Maven, Docker (Scenario B only). Milo 1.1.4 and 1.1.5 artifacts
must already be present in the local `~/.m2` cache for a fully offline build (`mvn -o`);
if they are not cached, drop `-o` and Maven will fetch them from Maven Central.

## Contents

- `poc/victim-server/` — standalone Maven project (no Milo source tree dependency).
  Depends only on released `org.eclipse.milo:milo-sdk-server` / `milo-sdk-client` Maven
  Central artifacts, version controlled by the `milo.version` property (default `1.1.4`).
  - `VictimServer.java` — a minimal, otherwise-unremarkable OPC UA server (None +
    Basic256Sha256 endpoints at `/milo`, default config), a background reporter that
    prints Netty's pooled direct-memory usage once a second, and a second, fully
    independent "heartbeat" thread (no Netty/OPC UA dependency) standing in for an
    unrelated co-located workload, used to prove process-wide blast radius.
  - `LegitClient.java` — a full, honest OPC UA session (connect, read
    `Server_ServerStatus_State`) used before/during/after the attack to prove availability
    or its absence, with a self-bounded watchdog so a hung handshake is recorded as denial
    rather than blocking forever.
  - `KeyStoreLoader.java` — self-signed certificate generation (adapted from Milo's own
    example server, trimmed to remove the Guava dependency).
- `poc/attacker/attacker.py` — the attacker. **Pure Python standard library sockets and
  `struct`, zero third-party dependencies, no Milo/OPC UA library of any kind.** Sends a
  valid UASC `HELLO`, then a bounded number of intermediate (`'C'`) `OpenSecureChannel`
  chunks that are never finalized, then closes the socket. Paced to Milo's default
  `RateLimitingHandler` acceptance window (a realistic rate-limited attacker, not a
  bypass of the limiter).
- `poc/Dockerfile.app`, `poc/Dockerfile.attacker` — image build (offline: they COPY an
  already-built jar, no Maven/network access at image-build time).
- `poc/scenarioA.sh` — bounded direct-memory cap, host-only, no Docker required.
- `poc/scenarioB.sh` — container memory limit, real OOM-kill. Single-IP headline by
  default (`MODE=single`); `MODE=multi` runs the labeled acceleration comparison. Exits
  nonzero if any of the eight proof points don't match what the build is expected to do.
- `poc/run.sh` — orchestrates all of the above and writes to `evidence/`.
- `evidence/` — this session's real run transcripts: `scenarioA-{vulnerable-1.1.4,fixed-1.1.5}.log`,
  `scenarioB-vulnerable-1.1.4-single-ip.log` (**headline**),
  `scenarioB-fixed-1.1.5-single-ip.log` (identical-sequence control),
  `scenarioB-vulnerable-1.1.4-multi-ip.log` (acceleration comparison, secondary).

## Honest notes and limitations

- **The attacker must be non-loopback for the rate limiter to be genuinely active.**
  Milo's `RateLimitingHandler` exempts loopback peers outright
  (`isLoopbackAddress()`), so testing against `127.0.0.1` would silently disable it and
  overstate the attack's ease. Scenario A targets the host's real LAN IP (not
  `127.0.0.1`); Scenario B runs attacker and victim as separate Docker containers on a
  bridge network, so the server genuinely sees non-loopback peers.
- **The `A:H` outcome is configuration-dependent, not a property of every deployment.**
  With a modest, explicit `-XX:MaxDirectMemorySize` and a JVM that survives the caught
  `OutOfMemoryError` (Scenario A), a single rate-limited attacker IP causes severe,
  durable degradation but not full denial of a lightweight legitimate client. With a
  container/cgroup memory limit and no protective direct cap — the common containerized
  deployment (Scenario B) — the same leak crashes the process outright. Both are real;
  neither should be quoted as the whole story on its own.
- **The underlying defect is unconditional.** Regardless of which availability outcome a
  given deployment lands on, the leak itself — permanent, pre-authentication, unreachable
  by garbage collection — is present in every affected version and warrants the fix
  regardless of `-XX:MaxDirectMemorySize`/container-limit configuration.
- Container memory limits in Scenario B (`--memory=550m`, idle RSS observed ~175–215 MiB)
  were sized empirically against this specific victim server/JVM combination on this
  machine; a different JVM, heap size, or base image will shift the numbers but not the
  qualitative result (confirmed by the 1.1.5 negative control surviving the identical
  setup and attack).
- **The single-IP number (40 connections / 160 MiB to kill 1.1.4) is not a universal
  constant.** It depends on this machine's idle RSS, the `--memory` limit chosen, and
  JVM/Docker overhead on the day of the run; a re-run may see a somewhat different count
  before the kill. What's invariant across runs (confirmed repeatedly in this session,
  including the 4-source-IP acceleration run reaching the kill at a comparable ~160–168
  MiB total regardless of source-IP count) is the *qualitative* result: a single
  rate-limited IP is sufficient to OOM-kill a default-configuration 1.1.4 server behind a
  typical container memory limit, and 1.1.5 does not exhibit this under the identical
  sequence.
- This PoC is entirely self-contained and does not share any harness, script, or code
  with the sibling username-token padding-oracle PoC in this repository — no shared
  runner, no shared victim server, independent directories.
- All testing was performed in an isolated local lab (host LAN interface + Docker bridge
  networks) for security research / defensive testing purposes only.
