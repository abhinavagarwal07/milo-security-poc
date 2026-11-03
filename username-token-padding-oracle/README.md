# the padding oracle — RSA PKCS#1 v1.5 padding oracle in Eclipse Milo's `UserNameIdentityToken` decryption

> **On identifiers.** This finding is
> [CVE-2026-60007](https://www.cve.org/CVERecord?id=CVE-2026-60007), assigned by the Eclipse
> Foundation (CNA) and published on 4 August 2026. It is fixed in Eclipse Milo 1.1.5.
**Component:** `opc-ua-sdk/sdk-server/src/main/java/org/eclipse/milo/opcua/sdk/server/identity/AbstractIdentityValidator.java`,
`AbstractUsernameIdentityValidator.java`
**Class:** CWE-204 Observable Response Discrepancy → Bleichenbacher chosen-ciphertext RSA decryption oracle
**Impact:** Full recovery of a victim's plaintext `UserNameIdentityToken` password, followed by
session impersonation (`ActivateSession` as the victim returns `Good`)
**CVSS 3.1:** `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N` — **7.4 HIGH**
**CVSS 4.0:** `CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N` — **9.1 CRITICAL**
**CWE:** CWE-204 (Observable Response Discrepancy); parent class CWE-203 (Observable Discrepancy);
related CWE-208 (Observable Timing Discrepancy, superseded here by an explicit status code, which is
*easier* to exploit than a timing side channel); CWE-696 (incorrect error-handling structure is the
root structural defect)
**Affected:** Eclipse Milo 0.6.0 – 1.1.4
**Fixed:** 1.1.5, commit [`db59fae99`](https://github.com/eclipse-milo/milo/commit/db59fae993a3a1bc66fffc8a2796d444b40285fb)
("Close username-token padding oracle", PR [#1804](https://github.com/eclipse-milo/milo/pull/1804))

## TL;DR

```
Captured one encrypted OPC UA login
Recovered plaintext password in 11675 requests / 12.8 seconds
Wrong password: DENIED
Recovered password: LOGIN SUCCESSFUL
```

That is the actual final output of `./run.sh` (see `evidence/vulnerable_run.log` for the full
transcript). The attacker process that produced it never had the password by any channel — see
"Process isolation" below, which is the part of this PoC worth reading first.

## Root cause

`ActivateSession`'s `UserNameIdentityToken.password` field is RSA-encrypted with the server's own
certificate. `AbstractIdentityValidator.decryptTokenData()` decrypts it:

```java
// opc-ua-sdk/sdk-server/.../identity/AbstractIdentityValidator.java (pre-fix, ~line 177-215)
try {
  Cipher cipher = getCipher(algorithm, keyPair);
  for (int blockNumber = 0; blockNumber < blockCount; blockNumber++) {
    ((Buffer) passwordNioBuffer).limit(passwordNioBuffer.position() + cipherTextBlockSize);
    cipher.doFinal(passwordNioBuffer, plainTextNioBuffer);
  }
} catch (GeneralSecurityException e) {
  throw new UaException(StatusCodes.Bad_SecurityChecksFailed, e); // RSA unpadding failed
}
```

`Cipher.doFinal()` throws `BadPaddingException` (a `GeneralSecurityException`) whenever RSA
unpadding fails — for `Basic128Rsa15` (PKCS#1 v1.5), whenever the decrypted block does not start
with `0x00 0x02`, contain ≥8 non-zero padding bytes, and a `0x00` separator. That failure is mapped
unconditionally to `Bad_SecurityChecksFailed` (`0x80130000`).

If unpadding *succeeds*, control passes to
`AbstractUsernameIdentityValidator.validateUsernameToken()`, which returns **different** status
codes for every other failure mode: `Bad_IdentityTokenInvalid` (`0x80200000`) for a structurally
invalid plaintext or a stale/wrong nonce, and `Bad_UserAccessDenied` (`0x801F0000`) for a valid
nonce but wrong password. None of the three codes are normalized anywhere between here and the
wire — whatever `UaException` is thrown becomes the `ServiceFault.responseHeader.serviceResult`
returned verbatim to the caller.

That is a textbook RSA decryption oracle: an attacker who can submit arbitrary ciphertexts as the
`password` field and observe which status code comes back learns, for free, one bit per query —
"did PKCS#1 v1.5 unpadding succeed?" That is exactly the oracle Bleichenbacher's 1998
chosen-ciphertext attack (RFC 8017 §7.2.2 threat model) requires to recover an RSA-encrypted
plaintext without the private key.

## Why `AC:H`/`AT:P`, not `AC:L`/`AT:N`

Two real preconditions gate exploitation, both reflected in the CVSS vectors above:

1. **A `Basic128Rsa15` username `UserTokenPolicy` must be configured.** Milo's default
   `USER_TOKEN_POLICY_USERNAME` uses `Basic256Sha256` (RSA-OAEP), not PKCS#1 v1.5. `Basic128Rsa15`
   is a fully supported, spec-compliant OPC UA security policy (`SecurityPolicy.java`), and a server
   operator can enable it — but it is not present by default and not present in Milo's own test
   harness. (The status-code discrepancy itself exists regardless of which RSA policy is
   configured — it is present for every OAEP policy too — but the classical Bleichenbacher attack
   specifically needs PKCS#1 v1.5.)
2. **Attacker network position to capture one victim ciphertext.** The chosen-ciphertext oracle
   queries themselves need no credentials (an anonymous session suffices in Milo's default
   configuration), but bootstrapping the attack requires one legitimate encrypted
   `UserNameIdentityToken` ciphertext for the target account, obtained on the wire when the victim
   authenticates (trivial to capture passively on a `None`/`Sign`-only channel, or via an active
   relay as this PoC demonstrates, since the password field is RSA-encrypted independent of the
   outer channel's security mode).

Given both preconditions, no further user interaction, privilege, or timing/statistical measurement
is needed — the oracle is a deterministic, explicit status code, immune to network jitter, and once
running requires no rate limiting, account lockout, or session-invalidation bypass (Milo applies
none of these to `ActivateSession` identity-change attempts).

## Process isolation: why this PoC is a proof, not a demo

This is the design point that carried the most weight in review, and it is the strongest
credibility signal in this repository, so it is stated explicitly rather than left implicit in the
code.

The naive way to build this PoC is a single process/class that knows the victim's password (to set
up the scenario) and also runs the "attack" — which invites the fair objection that the recovery
"already knew" the answer. This PoC instead runs as **five separate JVM processes**, each with its
own `main()`, wired together only by files and TCP sockets, with every `java` invocation's exact
argv visible in [`run.sh`](poc/run.sh):

| Process | Class | Knows the password? | Role |
|---|---|---|---|
| 1 | `poc.ServerMain` | **Yes** (must, to authenticate) | The vulnerable (or fixed) Milo server; generates a fresh 2048-bit RSA key pair at startup |
| 2 | `poc.VictimMain` | **Yes** (is the legitimate user) | Authenticates once through the relay |
| 3 | `poc.RelayMain` | **No** | A "dumb pipe": records raw TCP bytes in both directions, does **no protocol parsing at all** |
| 4 | `poc.AttackerMain` | **No — never, by any channel** | Parses the raw capture itself, confirms the oracle, runs the entire Bleichenbacher recovery |
| 5 | `poc.VerifierMain` | **Yes** (given directly by `run.sh`) | Compares recovered-vs-actual, *after* the attacker has already committed to an answer |

**The victim's password is generated at runtime** by `run.sh` (`tr -dc 'A-Za-z0-9' < /dev/urandom
| head -c 20` — 20 random characters, a fresh value every run) — it is never a constant anywhere in
source. It is passed as a plain (never `export`ed) shell variable to exactly two `java` invocations,
`ServerMain` and `VictimMain`, and to `VerifierMain` as its ground-truth input. It is **not**
exported into the process environment at all, so it is structurally absent from every other child
process's environment block, including the attacker's.

**The relay does no extraction.** `poc.RelayMain` does not know what an `ActivateSessionRequest`
is. It records the raw client→server and server→client byte streams until the connection goes
quiet, writes them to two files (`capture-c2s.raw`, `capture-s2c.raw`), and exits. It cannot hand
the attacker a "pre-extracted blob" because it never computes one.

**`poc.AttackerMain` does the extraction itself**, from the raw bytes:

- It decodes the UASC framing and the `ActivateSessionRequest` in `capture-c2s.raw` to pull out the
  username, policyId, and the RSA-encrypted password ciphertext (`extractFromRawCapture`, backed
  by `WireCodec.extractPasswordCiphertextFromStream` — the actual UASC-chunk scan and OPC UA binary
  decode, not a stub).
- It decodes the `CreateSessionResponse` in `capture-s2c.raw` to independently pull out the server
  certificate that was live *at capture time* (`WireCodec.extractServerCertificateFromStream`), and
  compares its fingerprint against the *live* target's certificate (fetched via its own ordinary
  `GetEndpoints` call) — this is the certificate-binding control, entirely self-derived.
- Its complete inputs, exactly as specified: target host/port, and the two raw capture files (or,
  for manual/offline use, an explicit `--token-hex` + `--username` + `--policy-id`). Nothing else.

Audit this yourself:

```bash
grep -n -- '--password\|PASSWORD' poc/src/main/java/poc/AttackerMain.java   # no matches
grep -n 'AttackerMain' poc/run.sh                                            # see the exact argv used
```

`AttackerMain` also never touches a private key and never calls `Cipher.DECRYPT_MODE` anywhere —
`RawActivate.encryptToken()` is ordinary RSA **public**-key encryption against the server's already-
public certificate (used only to build the oracle-confirmation probe and the final impersonation
ciphertexts); every padding-validity bit it learns comes from a real `ActivateSession` response read
off a live socket in `WireOracle`.

`run.sh` also runs a live **self-check**: after the relay writes the two raw capture files, the
script `grep -a`s them for the generated password and aborts loudly if it is ever found there — see
the `Isolation self-check` line in `evidence/vulnerable_run.log`. (It never will be — the password
is RSA-encrypted before the victim even sends it — but this is a live, mechanical check on the
actual bytes, not just an assertion in prose.)

Finally, `AttackerMain` writes its recovered guess to `recovered.properties` and prints it, **without
knowing whether it is correct** — it has no ground truth to compare against. Only `poc.VerifierMain`,
invoked by `run.sh` with `--expected "$PASSWORD"` (the value `run.sh` itself generated), does that
comparison, and only after the attacker process has already exited.

## Attack chain (all steps executed live, over real sockets, across the five processes above)

1. **Discover + validate** (`AttackerMain`). Connects, performs ordinary endpoint discovery
   (`GetEndpoints`), confirms a username policy with `Basic128Rsa15` exists, fetches the server
   certificate and its 2048-bit RSA public key, and prints its SHA-256 fingerprint. Vulnerability is
   never inferred from a version string.
2. **Extract from the raw capture.** The attacker parses `capture-c2s.raw` itself to recover the
   username, policyId, and password ciphertext, and `capture-s2c.raw` to recover the certificate the
   capture was made against — see "Process isolation" above.
3. **Certificate-binding control.** If the certificate recovered from the raw capture does not match
   the *live* target's certificate, the attacker refuses (demonstrated in
   `evidence/cert_mismatch_control.log`: a token captured against one server instance is correctly
   rejected against a second, freshly-keyed instance).
4. **Confirm the oracle on the wire**, cheaply, before attempting recovery. The attacker builds two
   ciphertexts using only the server's *public* certificate (no secret required): one with valid
   PKCS#1 v1.5 padding but a deliberately wrong password (expected `Bad_UserAccessDenied`), and one
   of pure random bytes (expected `Bad_SecurityChecksFailed`). If both come back identical (as on
   1.1.5, both `Bad_IdentityTokenInvalid`), or in any other unexpected/inconsistent pattern, the
   attacker reports **NOT VULNERABLE** and refuses to attempt recovery. Timeouts or transport errors
   during any oracle query are retried a bounded number of times and, if still unresolved, abort the
   run rather than being silently treated as "padding valid."
5. **Recovery.** Classical Bleichenbacher interval-narrowing, driven only by live remote responses,
   bounded per invocation by `--max-queries` / `--max-runtime`, with a **checkpoint file**
   (phase, search cursor, interval set, cumulative query count and elapsed time, certificate
   fingerprint, and token hash) written periodically and on completion, so an interrupted or
   budget-exhausted run resumes exactly where it left off (`run.sh`'s attacker loop does this
   automatically; see `evidence/checkpoint_resume.log` for a real resumed run spanning multiple
   attempts).
6. **Parse + prove.** The recovered block is validated against the exact structure `00 02 ||
   nonzero padding || 00 || little-endian length || password || 32-byte server nonce`. Two fresh
   `ActivateSession` attempts follow: a deliberately wrong password (expect denied) and the
   recovered password (expect `Good`). On success, the attacker also reads **one** node
   (`i=2259`, `Server/ServerStatus/CurrentTime`) on the resulting session to prove it is live and
   usable post-authentication — it never writes a node or invokes a method. (Honest caveat: this
   PoC's server does not configure per-identity RBAC, so this read does not by itself demonstrate
   an access-control bypass; the impersonation proof itself is the `ActivateSession` status —
   `Good` for the recovered password, denied for a wrong one, on the identical call shape.)

## Preconditions / honesty notes

- **This is not a default configuration.** The PoC server explicitly adds a `Basic128Rsa15`
  username `UserTokenPolicy` (`username_rsa15`) alongside anonymous access — the same non-default
  choice a real operator would have to make. Milo's out-of-the-box example/test servers use OAEP for
  username tokens and are not exploitable by this specific classical attack (though the same
  observable-discrepancy defect is present for OAEP policies too — see "Scope" below).
- **Query count and wall-clock time vary run to run.** The step-2a "first conforming multiplier"
  search is geometric. Measured runs during this build ranged from **11,675 queries / 12.8 s** (one
  attacker attempt) up to runs spanning many resumed attempts under a deliberately small per-attempt
  budget — see "Real measured results" below for the exact numbers. `run.sh`'s attacker loop resumes
  from checkpoint across as many attempts as it takes (default cap 40 attempts × 90s each = up to
  one hour of budget), so a single slow run never needs to restart the search from scratch.
- **Loopback, unthrottled.** The measured throughput reflects local-network conditions; Milo's
  connection-level `RateLimitingHandler` throttles new TCP/`OpenSecureChannel` attempts, not
  application-layer `ActivateSession` requests on an already-active session, so there is no
  additional artificial delay on this path in any environment.
- **Scope beyond the primary PoC.** The same observable-discrepancy defect (distinct status codes
  for valid vs. invalid RSA padding) is also present for all of Milo's OAEP-based policies
  (`Basic256`, `Basic256Sha256`, `Aes128_Sha256_RsaOaep`, `Aes256_Sha256_RsaPss`). The observed
  OAEP response difference does not establish Manger exploitability; this PoC demonstrates
  password recovery only for `Basic128Rsa15`, via the Bleichenbacher path. The difference reveals
  whether the full OAEP padding validated, not the leading-zero-byte property that Manger's attack
  needs.

## Fix

Milo 1.1.5, [`db59fae99`](https://github.com/eclipse-milo/milo/commit/db59fae993a3a1bc66fffc8a2796d444b40285fb):
`AbstractUsernameIdentityValidator.validateUsernameToken()` now catches the `UaException` thrown by
`decryptTokenData()` and rethrows a uniform `Bad_IdentityTokenInvalid`, and remaps the previously
distinct `authenticateUsernamePassword()` failure to the same code — collapsing all three
previously-distinguishable failure paths (bad padding, bad structure/nonce, bad password) into one
externally observable status. `AttackerMain`'s oracle-confirmation step (see "Attack chain" above)
detects exactly this change and reports the target as NOT VULNERABLE rather than attempting a
doomed recovery — see `evidence/fixed_run.log`.

## Repository layout

```
poc/pom.xml                         standalone Maven project (no Milo source tree needed)
poc/src/main/java/poc/
  ServerMain.java                   process 1: the vulnerable/fixed embedded Milo server
  VictimMain.java                   process 2: the legitimate user
  RelayMain.java                    process 3: raw-byte recording relay ("dumb pipe", no parsing)
  AttackerMain.java                 process 4: THE ATTACKER (parses the raw capture itself; never sees the password)
  VerifierMain.java                 process 5: recovered-vs-actual comparison, after the fact
  common/                           shared, password-oblivious helpers:
    WireCodec.java                    UASC framing + OPC UA message decode (the actual extraction logic)
    RawActivate.java                  ActivateSession helpers; public-key-only RSA encryption
    BleichenbacherEngine.java         the interval-narrowing search, with checkpoint/resume
    EmbeddedServerFactory.java        builds the standalone Milo server from public API
    TcpRecordingProxy.java            the raw byte-recording relay engine
    Args.java, PropsFile.java         tiny CLI/props-file helpers
poc/run.sh                         orchestrates all five processes; --fixed / --cert-mismatch-demo
evidence/                          captured transcripts of actual runs (see below)
```

## Reproduction

Requires JDK 17 and Maven (developed against the project's pinned `mise` toolchain, Temurin
17.0.19 + Maven 3.9.16, but any JDK 17 + Maven 3.6+ works). Both `org.eclipse.milo:*:1.1.4` and
`1.1.5` must be resolvable (Maven Central, or already present in `~/.m2` as they were here).

```bash
cd poc
./run.sh                       # vulnerable (milo.version=1.1.4): full recovery + impersonation
./run.sh --fixed               # fixed (milo.version=1.1.5): oracle-closed, refuses to recover
./run.sh --cert-mismatch-demo  # vulnerable: attacker refuses a capture bound to a DIFFERENT server
```

Each invocation builds the shaded jar with the requested `milo.version` (and prints its SHA-256,
for provenance), generates a fresh random password, and launches all five processes end to end in a
temporary working directory (printed at the end of the run, retained for inspection).

**Exit codes** (machine-checkable, so CI/reviewers don't have to parse prose): `0` = full recovery +
impersonation verified; `3` = attacker refused (certificate-fingerprint mismatch); `4` = attacker
correctly reported the target as not vulnerable and refused to attempt recovery; `5` = this
invocation's budget was exhausted before recovery completed (internal to `run.sh`'s resume loop —
not a terminal state a caller of `run.sh` itself will see); `6` = recovery completed but the
impersonation proof failed (would indicate a bug, never observed); `7` = no `Basic128Rsa15` username
policy found at the target; `1` = any other error. `run.sh` itself always exits `0`, `3`, or `4` on
a clean run.

Target console transcript (from an actual vulnerable run; see `evidence/vulnerable_run.log` for the
full output including the process-startup noise):

```
[+] Basic128Rsa15 username policy found
[+] Padding oracle confirmed (valid-padding/wrong-password -> Bad_UserAccessDenied, invalid-padding -> Bad_SecurityChecksFailed)
[*] Captured token SHA-256: 1c27f1c645324e5d31b095d6b41c9f9fe2ec413e033c06dc5db4fa5de2b738bc
[*] Recovery complete: 11675 queries in 12.8 seconds
[+] Wrong-password control denied
[+] Recovered-password authentication succeeded
[+] VERIFIED: recovered password matches the victim's actual password (PASS)

Captured one encrypted OPC UA login
Recovered plaintext password in 11675 requests / 12.8 seconds
Wrong password: DENIED
Recovered password: LOGIN SUCCESSFUL
```

## Real measured results (actual runs, not projections)

Full captured transcripts are in `evidence/`.

| Run | Build | Result | Oracle queries | Wall-clock | Attacker attempts | Recovered password | Impersonation | Isolation self-check |
|---|---|---|---|---|---|---|---|---|
| `evidence/vulnerable_run.log` | 1.1.4 | **SUCCESS** | 11,675 | 12.8 s | 1 (no resume needed) | matches (VerifierMain: PASS) | `Good`; wrong password `Bad_UserAccessDenied` | grep-verified: no password in raw capture |
| `evidence/checkpoint_resume.log` | 1.1.4 | **SUCCESS** | 24,922 | 23.0 s | **5** — run with `ATTEMPT_MAX_RUNTIME=5` (a deliberately small 5s per-attempt budget) to force repeated resumes; 4 of the 5 attempts hit their budget and wrote a checkpoint, and the next attempt reloaded `phase`/`cursorS`/`intervals`/cumulative query count from that file and continued (see the `Resuming from checkpoint: phase=...` lines) | matches (VerifierMain: PASS) | `Good`; wrong password `Bad_UserAccessDenied` | grep-verified |
| `evidence/fixed_run.log` | 1.1.5 | **NOT VULNERABLE** | 2 (oracle-confirm gate queries only) | <1 s | 1 | n/a — refused before search | n/a | n/a |
| `evidence/cert_mismatch_control.log` | 1.1.4 | **REFUSED** (exit 3) | 0 (refused before any oracle query) | <1 s | 1 | n/a — wrong target certificate | n/a | n/a |

Query counts vary run to run: the two saved evidence runs above are 11,675 and 24,922, and
development runs of this same search (across earlier iterations of this PoC) have ranged from the
low tens of thousands up to the low hundreds of thousands. This is the expected geometric variance
of the classical step-2a "first conforming multiplier" search, not a defect in either the attack or
this PoC — don't extrapolate a single run's number as typical in either direction. Every successful
run is a complete, unbudgeted recovery against a fresh 2048-bit server key with an independently
random victim password, confirmed correct by a process (`VerifierMain`) that never participated in
the attack itself.

**Isolation, confirmed explicitly:** in every run above, `poc.AttackerMain`'s argv (visible in
`run.sh` and in each run's console transcript) contains only `--host`, `--port`,
`--capture-c2s-file`, `--capture-s2c-file`, `--checkpoint-file`, `--max-runtime`, and `--out-file` —
no password, no username, no policyId (it derives the latter two itself from the raw capture) — and
`run.sh`'s own `grep -a` self-check against both raw capture files passed on every run.

**Environment (this build's runs):** macOS (Darwin 24.6.0, arm64), Temurin JDK 17.0.19,
`org.eclipse.milo:*:1.1.4` / `:1.1.5` from `~/.m2` (originally resolved from Maven Central), shaded
jar built fresh per run with its SHA-256 printed by `run.sh` (see each transcript's `sha256=` line).

## Comparison to related CVEs

Same vulnerability *class* (RSA decryption oracle in OPC UA `UserNameIdentityToken` handling) as
CVE-2024-42512 (OPC Foundation .NET reference stack, timing-based oracle) and CVE-2025-1468
(Unified Automation OPC UA stack, presented DEF CON 33). All three are independent codebases with
no shared code, which is why CNA practice assigns separate identifiers to the same recurring class.
Milo's instance is a materially *more* practical oracle than CVE-2024-42512's: an explicit,
deterministic status code rather than a noisy timing side channel, requiring no statistical
averaging across samples.

## Suggested hardening beyond the 1.1.5 fix

1. **Constant-time-ish handling:** perform the same sequence of checks (decrypt, structural
   validate, nonce compare, password compare) regardless of where an earlier check failed, so a
   residual timing side channel does not reopen a variant of this class after status-code
   normalization.
2. **Rate limiting on `ActivateSession` identity changes**, independent of the existing
   connection-level `RateLimitingHandler` (which only governs new connection attempts, not
   application-layer requests on an already-active session).
3. **A defensive random delay** on the identity-token decryption/validation path, mirroring the
   0–1000ms delay Milo already applies to `UascServerAsymmetricHandler` `OpenSecureChannel` decode
   failures.
