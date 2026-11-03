# Eclipse Milo ≤ 1.1.4 — OPC UA server vulnerability PoCs

Proof-of-concept code for four of the six server-side vulnerabilities in
[Eclipse Milo](https://github.com/eclipse-milo/milo), the open-source **OPC UA (IEC 62541)** client/server
SDK for the JVM. All four are network-reachable against a Milo **server**; one is fully
**pre-authentication**, and one recovers a legitimate user's **plaintext password** from a single captured
token.

**Full technical write-up:** <https://abhinavagarwal07.github.io/posts/eclipse-milo-opcua-six-cves/>

All PoCs run against `127.0.0.1` (or a local container network) in an isolated lab. For security research
and defensive testing only.

## Vulnerabilities

| Finding | Component | Class (CWE) | Impact | CVSS v3.1 / v4.0 | Directory |
|-----|-----------|-------------|--------|------------------|-----------|
| Username-token padding oracle | Username-token identity validation | RSA PKCS#1 v1.5 padding oracle (CWE-204) | **Password recovery + impersonation** | 7.4 / **9.1 Critical** | [`username-token-padding-oracle/`](username-token-padding-oracle/) |
| `copy()` drops `RoleMapper` | `OpcUaServerConfig.copy()` | `RoleMapper` dropped, RBAC fails open (CWE-862) | Authorization bypass | 8.6 / 8.8 | [`serverconfig-copy-rolemapper/`](serverconfig-copy-rolemapper/) |
| Call mixed-batch bypass | Call service | Mixed-batch authorization bypass (CWE-863) | Authorization bypass | 8.2 / 8.7 | [`call-mixed-batch-authz-bypass/`](call-mixed-batch-authz-bypass/) |
| Pre-auth memory leak | UASC server transport | Pre-session direct-memory leak (CWE-401) | **Unauthenticated remote DoS** | 7.5 / 8.7 | [`uasc-preauth-memory-leak/`](uasc-preauth-memory-leak/) |

**Affected:** the padding oracle and the memory leak affect **0.6.0–0.6.16 and 1.0.0–1.1.4**; the
`RoleMapper` drop and the mixed-batch bypass affect **1.0.0–1.1.4** (1.x-only APIs). **All fixed in Eclipse Milo
[1.1.5](https://github.com/eclipse-milo/milo/releases/tag/v1.1.5)** (2026-07-16).

Two more issues were fixed in the same release and are covered in the write-up but have no PoC here:
a cross-session diagnostics disclosure, and monitored-item quota exhaustion / nested-decode DoS.

## Username-token padding oracle — captured token → plaintext password

Milo's username-token decryption maps the distinct failure modes of an RSA PKCS#1 v1.5 unpad onto
*different* OPC UA status codes: a validly-padded block with the wrong password returns a different code
than a badly-padded block. That discrepancy is a **Bleichenbacher decryption oracle**.

[`username-token-padding-oracle/`](username-token-padding-oracle/) is an
end-to-end attack across **five separate JVM processes** (server, victim, relay, attacker, verifier). A
relay records the victim's raw TCP bytes — it does no OPC UA parsing at all — and the attacker decodes the
UASC framing itself to recover the username, policy id, encrypted token, and the certificate the capture
was made against. It then opens a single anonymous session (no credentials of any kind) and sends adaptive
`ActivateSession` identity-change requests for the victim account, narrowing the RSA plaintext interval
until the **plaintext password is recovered**; a raw `ActivateSession` with that password returns `Good`.
A Milo 1.1.5 run is the negative control: both probes return one uniform status, so the attacker reports
the target as not vulnerable and refuses to attempt recovery.

**Why this is a proof, not a demo.** The victim password is generated at runtime, and the attacker process
has no path to it: no such flag exists in its argument parser, the shell variable is never exported, and
the only files it reads are raw packet captures that the harness itself greps for the password (aborting
if found). It holds no private key and performs no local decryption — every padding decision comes from a
live remote response. A separate verifier compares the recovered value against the real one only *after*
the attacker has committed its answer to a file.

> **Preconditions, stated plainly:** the server must be configured to accept the **deprecated
> `Basic128Rsa15`** username-token policy, and the attacker needs an **on-path capture of one victim
> token**. That is exactly what the CVSS v4.0 `AT:P` and the v3.1 `AC:H` price in. Recovery is
> probabilistic per run; query counts vary.

## Pre-authentication memory leak — unauthenticated, process-killing DoS

The UASC server transport retains incomplete message chunks in pooled **direct (off-heap)** memory and
releases them only on `exceptionCaught`, not on `channelInactive`. Because `SecurityPolicy.None` is
accepted for channel setup, an unauthenticated client can open a channel, send a non-final chunk,
disconnect, and repeat — leaking off-heap memory that garbage collection never reclaims. No session, no
credentials, no user interaction.

The attacker is a **pure-socket Python script with no Milo or OPC UA library dependency**. Under a bounded
direct-memory cap the leak pins memory at the limit and survives a forced GC; under a container memory
limit the JVM is **OOM-killed (`ExitCode 137`)** within seconds.

## Repository layout

```
<finding-name>/
  README.md      # root cause, CVSS, preconditions, reproduction, fix status
  poc/           # self-contained Maven project + run.sh (+ Dockerfiles where needed)
  evidence/      # captured transcripts: vulnerable run and Milo 1.1.5 negative control
```

Every PoC is **self-contained**: it builds against the **released** Eclipse Milo artifacts from Maven
Central and does not require the Milo source tree. The fixed-build negative control is the *same* PoC
bytecode with only the Milo dependency changed:

```bash
./run.sh                      # vulnerable: Milo 1.1.4
```

Each PoC's `run.sh` also runs the Milo 1.1.5 negative control; the exact flag differs per PoC (some run
both sides in one invocation, others take `--fixed`). See each finding's README for the precise form.

## Requirements

- **JDK 17** and **Maven 3.9+** (Milo 1.x targets Java 17)
- **Docker** — only for the memory-leak container-OOM scenario
- **Python 3** — for the memory-leak pure-socket attacker

## Safety

**Run these in a disposable VM or an isolated lab.** These are working exploits, not illustrations:

- The memory-leak PoC will **kill the JVM** it is pointed at, and it exhausts a process-wide off-heap pool —
  never run it against anything you do not own.
- The padding-oracle PoC recovers a real password from a server you control. Do not point it at third-party
  infrastructure; using it against systems you are not authorized to test is illegal in most
  jurisdictions.
- The PoCs deliberately pin **vulnerable** Milo versions. Do not copy these poms into production.

## Mitigation

Upgrade to **Eclipse Milo 1.1.5**. For the 0.6.x line there is no fixed 0.6 release — remediation is a
0.6 → 1.x migration. Interim hardening is documented per finding in the individual READMEs and in the
write-up.

## Credit

Found and reported by Abhinav Agarwal. Coordinated with the Eclipse Foundation Security Team
([vulnerability-reports#598](https://gitlab.eclipse.org/security/vulnerability-reports/-/work_items/598))
and CERT/CC (**VU#813184**).
