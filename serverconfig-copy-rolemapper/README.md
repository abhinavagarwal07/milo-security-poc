# the RoleMapper-drop defect — `OpcUaServerConfig.copy()` drops the `RoleMapper`, RBAC fails open

> **On identifiers.** A CVE ID has been reserved for this finding by the Eclipse Foundation (CNA) but
> is not yet published. Per the CNA's terms a reserved identifier must not be used in public
> communication before publication, so none is cited here; this file will be updated once it is public.
**Component:** `opc-ua-sdk/sdk-server/src/main/java/org/eclipse/milo/opcua/sdk/server/OpcUaServerConfig.java`
**Class:** CWE-862 Missing Authorization
**Impact:** Authorization bypass — an identity that was never granted a privileged role can
Browse, Call methods, read RolePermissions/Historizing attributes, and AddNodes/DeleteNodes as
if RBAC were not configured at all
**CVSS:** v3.1 8.6 (`AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:L`) · v4.0 8.8 High
(`CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:H/VA:N/SC:N/SI:N/SA:N`)
**Auth:** none (exploitable by any identity the server accepts, anonymous included)
**Affected:** Milo **1.0.0 – 1.1.4** (the `RoleMapper`/RBAC API was introduced in the 1.x line;
0.6.x predates it and is not affected by this specific defect)
**Fixed:** **1.1.5**, commit
[`d51f03e9a75f313ab41c3d68d809f4b922073f1a`](https://github.com/eclipse-milo/milo/commit/d51f03e9a75f313ab41c3d68d809f4b922073f1a)
("Preserve role mappings when copying server config", PR #1801)

## Root cause

`OpcUaServerConfig.copy(config, consumer)` builds a new config by copying every field of an
existing one field-by-field into a fresh builder. Through 1.1.4 it copied the certificate
manager, identity validator, limits, executors, endpoints, build info, and more — but never
the `RoleMapper`:

```java
builder.setLimits(config.getLimits());
builder.setIdentityValidator(config.getIdentityValidator());
builder.setCertificateManager(config.getCertificateManager());
// no config.getRoleMapper().ifPresent(builder::setRoleMapper) -- the mapper is silently lost
builder.setExecutor(config.getExecutor());
```

The fix is a single line (PR #1801):

```java
config.getRoleMapper().ifPresent(builder::setRoleMapper);
```

Milo's `DefaultAccessController` gates a specific set of operations by `RolePermissions`/
`UserRolePermissions`: **Browse, Call, reads of the RolePermissions/Historizing attributes, and
AddNodes/DeleteNodes.** When a session has no roles to evaluate — which is exactly what happens
when the server's running config has no `RoleMapper` — the access controller has nothing to
check against and **grants access**. A config built through `copy()` therefore behaves as if no
RBAC were configured at all for every one of those operations, regardless of what
`RolePermissions` are attached to individual nodes.

**Read/write of a node's `Value` attribute is gated by `AccessLevel`, not `RolePermissions`** —
so a naive PoC that anonymously writes a "protected" variable would incorrectly show identical
(successful) behavior on both the vulnerable and fixed builds. This PoC deliberately demonstrates
the bypass on **Call**, the correct RolePermissions-gated surface, against a method with a real,
observable side effect (an invocation counter incremented from inside the method body) so success
means the privileged operation *actually ran*, not merely that the response status was `Good`.

## Why `copy()` matters

`copy()` exists so that embedding frameworks and wrapper layers can accept a caller-supplied
`OpcUaServerConfig` and adjust a few fields before constructing the server, without having to
enumerate and forward every field of `OpcUaServerConfig` themselves. Real integration frameworks and embedding wrappers do exactly this:

```java
public MiloServerComponent(final OpcUaServerConfig serverConfig) {
    this.opcServerConfig = OpcUaServerConfig.copy(serverConfig);
}
```

Any application that hands a `RoleMapper`-bearing config to that constructor (or any other
code path that runs a caller's config through `OpcUaServerConfig.copy()`) silently loses RBAC
on the resulting server, with no error, warning, or exception — the running server simply
enforces nothing for the affected operations.

## Reproduction

`poc/` is a standalone Maven project depending only on **released** Eclipse Milo artifacts from
Maven Central (`milo-sdk-server`, `milo-sdk-client`, `milo-stack-core`, `milo-transport`) — it
does not require the Milo source tree.

### Four causal controls, identical application code

The point is to prove that the **missing `RoleMapper` — not identity setup, harness behavior,
or anything else — is the sole cause**. `poc.PocServer` takes a `mode` argument; every mode
runs the exact same source (same `RoleMapper`, same `ControlNamespace`, same endpoint config) —
only the branch shown below, and which Milo jar the class is run against, differ:

| # | mode       | Milo  | what differs                                              | expected Call |
|---|------------|-------|------------------------------------------------------------|---------------|
| 1 | `original` | 1.1.4 | `finalConfig = baseConfig` — **no `copy()` at all**         | denied        |
| 2 | `copied`   | 1.1.4 | `finalConfig = OpcUaServerConfig.copy(baseConfig, b -> {})` | **ALLOWED (the bug)** |
| 3 | `restored` | 1.1.4 | same `copy()` call, but `b -> b.setRoleMapper(ROLE_MAPPER)` | denied        |
| 4 | `copied`   | 1.1.5 | identical source to #2, run against the **fixed** Milo jar  | denied        |

Control 3 is the causal clincher: it is *identical* to control 2 — same base config, same
`copy()` call, same Milo 1.1.4 build — except the RoleMapper is explicitly re-applied in the
same builder-consumer callback `copy()` already takes. Call goes back to being denied with
nothing else changed, which isolates the mapper's presence/absence as the only variable, not
some other side effect of `copy()` or of this harness.

### The victim: an independent legitimate client feels the consequence

For **every** control, three separate JVMs run against one `PocServer` instance, using only
realistic OPC UA client operations — no internal objects, no shared state between them:

- **`poc.PocServer`** hosts a `PumpController` object: `PumpFlow` (a Variable a background
  thread ticks upward every 300ms, Good status — the live feed), `InvocationCount` (a counter
  incremented from inside `restartPump`'s method body — server-side forensic ground truth that
  the privileged operation actually ran), and `restartPump` (`RolePermissions` grant `Call` to
  `AdminRole` only; `ObserverRole` gets `Browse` but not `Call`). Invoking it cancels the
  `PumpFlow` ticker and flips it to `Bad_NoCommunication` — permanently, since there is no
  Observer-reachable "start" method.
- **`poc.LiveClient`** is an independent legitimate monitoring client with nothing to do with
  the attack — a separate JVM/TCP session standing in for a real HMI/SCADA display or
  historian. It connects on its own, subscribes to `PumpFlow` before anything happens, and just
  keeps streaming it for the life of the run. It never calls `restartPump`.
- **`poc.AttackerClient`** connects with **zero credentials** partway through `LiveClient`'s
  stream, browses to discover `PumpController`/`restartPump` (no foreknowledge beyond normal
  discovery — a realistic attacker input, not an internal object), reads `InvocationCount`,
  issues one `Call` against `restartPump`, and reads `InvocationCount` again.

The payoff: on control 2, the Call is allowed, `restartPump`'s body actually runs, and it stops
the `PumpFlow` ticker — the same live feed the **independent** `LiveClient` has been receiving
the whole time. The role check was silently skipped, and the forbidden command disrupted
another connected client that had nothing to do with the attack. On controls 1, 3, and 4, the
Call is denied and `LiveClient`'s feed is completely unaffected.

`run.sh` machine-checks every control's actual Call outcome and victim impact against the
expected values in the table above and **exits non-zero if any control's actual result doesn't
match what's expected** — it is a verifier, not just a demo.

```bash
cd poc
./run.sh            # all four causal controls (1.1.4 controls 1-3 + 1.1.5 control 4)
./run.sh --vuln      # controls 1-3 only (against 1.1.4)
./run.sh --fixed     # control 4 only (against 1.1.5)
```

`1.1.4` and `1.1.5` are expected to already be present in the local Maven repository (the
default `run.sh` build is offline, `-o`); drop `POC_OFFLINE=0 ./run.sh` if a fetch is needed.
For each control: `LiveClient` streams ~4s of healthy readings → `AttackerClient` fires →
`LiveClient` streams ~8s more so the aftermath is observable → `run.sh` correlates
`LiveClient`'s heartbeats against the epoch-ms timestamp of the Call, and compares the actual
outcome against the expected one for that control.

### Observed results

Real, self-checked output from `./run.sh` (full transcript in `evidence/summary.log`):

```
============================================================
the RoleMapper-drop defect -- OpcUaServerConfig.copy() drops RoleMapper -- CAUSAL VERDICT MATRIX
captured 2026-07-28T12:00:06Z UTC
------------------------------------------------------------
#  control                  milo    expected  actual    victim      pass
1  original                 1.1.4   DENIED    DENIED    CONTINUOUS  PASS
2  copied                   1.1.4   ALLOWED   ALLOWED   DISRUPTED   PASS
3  restored                 1.1.4   DENIED    DENIED    CONTINUOUS  PASS
4  copied                   1.1.5   DENIED    DENIED    CONTINUOUS  PASS
------------------------------------------------------------
Root cause isolated: across controls 1-3 the ONLY variable is whether the RoleMapper
survives onto the running config (same Milo 1.1.4 build, same application code every
time). Control 3 (mapper explicitly restored after copy()) returning to DENIED, with
nothing else changed from control 2, is the causal clincher.
"Copying the server configuration silently erased its entire role map and made RBAC
fail open."
------------------------------------------------------------
OVERALL: PASS
============================================================
```

`run.sh` computes `actual` and `victim` from the real client output and compares them against
`expected` itself; `OVERALL` is `PASS` only if every row matches, and the process exits non-zero
otherwise (verified by deliberately mis-declaring an expectation and confirming both the FAIL
row and the non-zero exit code appear before restoring the correct value).

**Control 2 (`copied`, Milo 1.1.4) — the bug.** The server's own log
(`evidence/server-c2-copied-vulnerable.log`) shows the mapper dropped and the method actually
running:

```
POC_SERVER_CONFIG mode=copied roleMapperPresentOnBaseConfig=true roleMapperPresentOnRunningConfig=false (DROPPED ...)
POC_SIDE_EFFECT restartPump EXECUTED invocationCount=1 pumpWasRunning=true pumpFlowNowBad=true
```

The anonymous attacker (`evidence/attack-c2-copied-vulnerable.log`):

```
ATTACK_CALL_RESULT ts=... statusCode=StatusCode[name=Good, value=0x00000000, quality=good] good=true
ATTACK_VERDICT BYPASS -- anonymous client (ObserverRole, never granted Call) invoked restartPump and it EXECUTED (invocationCount 0 -> 1).
```

And the **independent** `LiveClient` (`evidence/live-c2-copied-vulnerable.log`), which never
called anything and was streaming the whole time, observes the disruption directly — its
heartbeat sequence climbs through the pre-attack window and then freezes at 6 for every
remaining heartbeat, `lastStatus` flipping from `Good` to `Bad_0x80310000`
(`StatusCodes.Bad_NoCommunication`) and never recovering:

```
IMPACT_VERDICT DISRUPTED (notifications 4 -> 6, finalStatus=Bad_0x80310000)
```

**Control 3 (`restored`, Milo 1.1.4) — the causal clincher.** Identical `copy()` call, same
Milo build, only the RoleMapper is explicitly re-applied (`evidence/server-c3-restored.log`):

```
POC_SERVER_CONFIG mode=restored roleMapperPresentOnBaseConfig=true roleMapperPresentOnRunningConfig=true (PRESERVED ...)
```

No `POC_SIDE_EFFECT` line appears — the Call was denied (`evidence/attack-c3-restored.log`
shows `Bad_UserAccessDenied`) — and `LiveClient`'s feed
(`evidence/live-c3-restored.log`) never stops: `IMPACT_VERDICT CONTINUOUS (notifications 5 ->
12, finalStatus=Good)`. Nothing else differs from control 2 except the mapper being present,
and denial returns exactly as in control 1.

**Control 4 (`copied`, Milo 1.1.5) — upstream fix, real regression check.** Same source line as
control 2, run against the released fixed jar: mapper preserved
(`evidence/server-c4-copied-fixed.log`), Call denied, `LiveClient` unaffected
(`evidence/live-c4-copied-fixed.log`).

Every control's full transcript — server config, `POC_SIDE_EFFECT` ground truth, the
attacker's requests and results, and the independent `LiveClient`'s complete heartbeat stream —
is in [`evidence/`](evidence/), alongside `environment.log` (exact `java`/`mvn`/OS versions)
and `artifact-hashes.log` (sha256 of every Milo jar resolved for both versions).

## Preconditions — stated plainly

This is **not** a stock-default exposure; three things all have to be true:

1. The embedding application (or a framework/wrapper it uses) builds the config it actually
   runs the server with via `OpcUaServerConfig.copy()`, rather than the builder directly.
2. The application **intends** RBAC — it attaches a non-trivial `RoleMapper` and relies on
   `RolePermissions`/`UserRolePermissions` to gate Browse/Call/AddNodes/DeleteNodes/attribute
   reads.
3. The server accepts at least one identity that is **not** supposed to hold the privileged
   role for the operation in question (in the common case, an anonymous or otherwise
   lower-privileged identity) — the impact is specifically that this lower-privileged identity
   gets treated as if no restriction applied.

An application that builds its config directly with the builder (never calling `copy()`), or
that does not use `RoleMapper`/`RolePermissions` at all, is not affected by this specific
defect. Public integration frameworks expose constructors that take a caller-supplied
`OpcUaServerConfig` and route it through `copy()` — a concrete,
shipped example of a code path that hits it.

## Fix / mitigation

Upgrade to **Eclipse Milo 1.1.5**. There is no configuration workaround: as long as the running
server's config was produced by a vulnerable `copy()`, its `RoleMapper` is unconditionally
absent regardless of what was set on the config passed in. Applications that cannot upgrade
immediately can work around it by explicitly re-applying `.setRoleMapper(...)` in the builder
consumer passed to `copy()` (i.e. `OpcUaServerConfig.copy(base, b -> b.setRoleMapper(mapper))`),
which restores the mapper on the resulting config.

## Contents

```
poc/         standalone Maven project (pom.xml, run.sh) + Java sources
             (PocServer, ControlNamespace, LiveClient, AttackerClient, ClientUtil)
evidence/    real transcripts from the four causal controls (c1-original, c2-copied-vulnerable,
             c3-restored, c4-copied-fixed):
               server-c*.log         server-side config + POC_SIDE_EFFECT ground truth
               live-c*.log           the independent legitimate client's heartbeat stream + verdict
               attack-c*.log         the anonymous attacker's discovery, Call, and verdict
               summary.log           the screenshot-friendly causal verdict matrix (all 4 controls)
               environment.log       exact java/mvn versions and OS/arch this was run on
               artifact-hashes.log   sha256 of every Milo jar resolved for 1.1.4 and 1.1.5
```

## Safety

Everything here runs against `127.0.0.1` only, in an isolated lab. For security research and
defensive testing only.

## Credit

Found and reported by Abhinav Agarwal. Coordinated with the Eclipse Foundation Security Team.
