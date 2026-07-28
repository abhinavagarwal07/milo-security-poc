# the mixed-batch bypass — Call service mixed-batch authorization bypass in Eclipse Milo

> **On identifiers.** A CVE ID has been reserved for this finding by the Eclipse Foundation (CNA) but
> is not yet published. Per the CNA's terms a reserved identifier must not be used in public
> communication before publication, so none is cited here; this file will be updated once it is public.
**Component:** `opc-ua-sdk/sdk-server/src/main/java/org/eclipse/milo/opcua/sdk/server/servicesets/impl/DefaultMethodServiceSet.java`,
method `call(CallRequest, Session)`
**Class:** CWE-863 Incorrect Authorization
**Impact:** A denied `Call` service method executes with real side effects whenever it is batched
in the same `CallRequest` alongside at least one method the caller *is* authorized to invoke. The
server can return a denial — or nothing at all (a timeout) — to the attacker, while the forbidden
command has already run and disrupted an entirely separate, legitimate client's session.
**CVSS 3.1:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:L` — **8.2 HIGH**
**CVSS 4.0:** `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N` — **8.7 HIGH**
**CWE:** CWE-863 (Incorrect Authorization)
**Auth:** any session with Call permission on at least one method in the batch (anonymous
sessions qualify if the deployment grants Call to anonymous for anything at all)
**Affected:** Eclipse Milo 1.0.0 – 1.1.4
**Fixed:** 1.1.5, commit [`59b50bed09`](https://github.com/eclipse-milo/milo/commit/59b50bed094de0d18a130a48f3527254dc76105d)
("Restrict Call dispatch to authorized methods", PR [#1802](https://github.com/eclipse-milo/milo/pull/1802))

## Root cause

The OPC UA `Call` service invokes one or more methods in a single request (`CallRequest.methodsToCall`
is a list). `DefaultMethodServiceSet.call()` first computes a per-method authorization verdict:

```java
Map<CallMethodRequest, AccessResult> accessResults =
    server.getAccessController().checkCallAccess(session, methodsToCall);
```

It then partitions the request with `GroupMapCollate.groupMapCollate()`, which groups consecutive
`CallMethodRequest`s that share the same `AccessResult` and, for each group, invokes a
per-partition handler with `group` — the authorized-only (or denied-only) subset belonging to
that partition. Inside the "allowed" branch, the code is supposed to dispatch only that
authorized subset:

```java
// buggy (1.0.0 - 1.1.4)
return server.getAddressSpaceManager().call(callContext, methodsToCall);

// fixed (1.1.5+)
return server.getAddressSpaceManager().call(callContext, group);
```

`methodsToCall` is the **full, original, unfiltered** request list — including any methods that
were just denied by the very `accessResults` map this branch is conditioned on. The one-word
regression means: whenever a `CallRequest` batches at least one authorized method with one or more
denied methods, the "allowed" partition's dispatch is handed the entire original list, and
`AddressSpaceManager.call()` executes every method in it — authorized and denied alike — with real
side effects. A method called **alone** is denied correctly (the "denied" branch never touches
`AddressSpaceManager.call()` at all); the defect only manifests for **mixed batches**.

Every other Milo service set that uses the same `groupMapCollate` pattern (Read, Write, Browse,
HistoryRead, etc.) correctly passes `group`, not the original unfiltered list — `DefaultMethodServiceSet`
is the only one with this defect.

## Reachability

Exploiting this requires a server that actually turns on OPC UA's role-based access control for
`Call`:

- A non-default `RoleMapper` mapping identities (including, typically, anonymous sessions) to
  roles, and
- `UserRolePermissions` / `RolePermissionType` set on the affected method nodes granting `Call`
  to only some of those roles.

Milo's **out-of-the-box default configuration does not enable RBAC** — with no `RoleMapper`
installed, `DefaultAccessController` has no roles to check against and every `Call` succeeds (or
fails) independent of this bug. **This is not exploitable against a stock default-config Milo
server.** It is exploitable against any real deployment that turns on per-method role-based `Call`
authorization — which is the documented, intended way to restrict `Call` access in Milo, and
exactly the configuration an industrial deployment gating PLC control, firmware updates, or
safety-relevant operations behind an operator/administrator role split would use.

Given such a deployment, any identity that holds `Call` permission on **any** node can weaponize
this: pair that one permitted method (as a harmless "carrier") with any denied method(s) of
interest in the same `CallRequest`, and the denied method(s) execute anyway. No additional
privilege, user interaction, or race condition is needed (`AC:L`, `PR:N`, `UI:N`).

A quirk observed in testing, reported honestly rather than glossed over: on the vulnerable build,
`GroupMapCollate`'s internal collation can throw an uncaught `RuntimeException` once the
(buggy) unfiltered result-list size for the "allowed" partition no longer matches the filtered
group size — this happens *after* the denied method's side effect has already run. Practically,
the attacker's `client.call(batch)` frequently completes exceptionally on the wire (e.g.
`Bad_Timeout`, no `CallResponse` ever delivered) even though the bypass succeeded server-side. The
attacker gets no clean confirmation of which status applied to which method, but the side effect
already happened — the proof of the bypass in this PoC comes from a server-side, ground-truth
invocation counter, not from the client-visible status code.

## Victim impact: an independent, legitimate client actually gets hurt

The invocation counter above is forensic ground truth, but on its own it's a weak impact
statement. To make the effect concrete, the PoC also wires an identically-shaped denied method
`stopSensorFeed()` to a real, continuously-updated process variable (`Plant/SensorFeed/Value`,
ticking every 200ms) that a wholly **separate, legitimate client process** — `LegitClient`, its
own anonymous session, its own JVM, never touched by the attacker or the admin identity —
subscribes to and streams.

Observed in this run: `LegitClient` was streaming a healthy tick every ~200ms (`goodTicks` climbing,
`badTicks=0`) when the anonymous attacker's mixed batch landed. On vulnerable Milo 1.1.4 the
attacker's own `client.call()` completed with nothing but a `Bad_Timeout` — no confirmation of
anything — while `LegitClient`, in its own process, watched the feed die (`badTicks` go from `0`
to `1`, status flipping to `Bad_NoCommunication`) moments later. On Milo 1.1.5, the byte-identical
attack left `LegitClient`'s stream completely uninterrupted (`badTicks` stayed `0` for the whole
run). This holds regardless of which order the batch lists the two methods in.

That is the headline: **the server told the attacker "no" (or said nothing at all), but the
forbidden command had already reached, and disrupted, someone else's session.**

## Contents

- `poc/` — standalone Maven project (own `pom.xml`, not part of the Milo reactor build), depending
  only on published Maven Central coordinates `org.eclipse.milo:milo-server-examples` and
  `org.eclipse.milo:milo-sdk-client` (`${milo.version}`, default `1.1.4`). Packaged as a shaded/fat
  jar via `maven-shade-plugin`. Application code is byte-for-byte identical between the vulnerable
  and fixed runs — `run.sh` only ever changes `-Dmilo.version`.
  - `PocServer` — boots `org.eclipse.milo.examples.server.ExampleServer` (a public SDK entry
    point) on `opc.tcp://localhost:12686/milo` with a `RoleMapper`: anonymous sessions get an
    `Operator` role only; the username identity `admin`/`password2` (already built into
    `ExampleServer`'s validator) additionally gets `Admin`.
  - `PocNamespace` — exposes two independent Admin-only "denied" targets, so the bypass is shown
    to generalize across methods, not just be a quirk of one:
    - `Plant/Device/readStatus()` — Call granted to Operator **and** Admin, the authorized
      "carrier" method placed in every mixed batch.
    - `Plant/Device/resetDevice()` — Call granted to **Admin only** (Operator may only Browse it).
      Invocation counter only.
    - `Plant/SensorFeed/stopSensorFeed()` — identical RBAC shape to `resetDevice()`, but its
      effect is a real, independently-observable state change: it permanently kills the live
      `Plant/SensorFeed/Value` tick and forces its status to `Bad_NoCommunication`.
    All invocations increment counters written to a well-known file, independent of whatever the
    client observes on the wire.
  - `Attacker` — a genuine, unmodified `milo-sdk-client` client with **no internal shortcuts or
    shared state** — it only ever Browses the real address space (no hardcoded NodeIds) and
    issues normal `Call` requests, exactly like any other OPC UA client. Supports calling either
    method alone, or as a 2-element mixed batch in **either order** (`[allowed, denied]` or
    `[denied, allowed]`). Reports the exact wire outcome — a clean `CallResponse` or an exception —
    without assuming either.
  - `LegitClient` — a separate, independent, legitimate client process (its own anonymous session,
    its own JVM) that subscribes to `Plant/SensorFeed/Value` and streams timestamped
    `LEGIT_TICK`/`LEGIT_SUMMARY` lines — the third-party victim.
  - `run.sh` — orchestrates the full 12-row demonstration with plain `mvn`/`java` (no Docker, no
    `mise` dependency, no Milo source checkout required). Server, attacker, and `LegitClient` are
    always three separate OS processes. Every row's expectation is machine-checked; the script
    prints a compact, screenshot-friendly verdict table and **exits non-zero if any row behaves
    unexpectedly**.
- `evidence/` — real transcripts from an actual `run.sh` execution: one log per row (`row1-…` through
  `row7r-…`), full server stdout for both builds, and `environment.log` (exact JDK/Maven versions,
  OS, the two `org.eclipse.milo:*` dependency versions used, and the SHA-256 of each built jar).

## Reproduction

Prerequisites: JDK 17 and Maven on `PATH` (this PoC does not require Docker or the Milo source
tree; Maven resolves `org.eclipse.milo:*:1.1.4`/`1.1.5` from Maven Central or the local `~/.m2`
cache).

```
cd poc
./run.sh          # exits 0 if every row matched its expectation, 1 otherwise
```

This runs the full 12-row matrix in one command — the core bypass, both batch orderings, a second
independent method, and the live third-party victim — printing a verdict table like:

```
Row    | Scenario                                                   | Result
-------+------------------------------------------------------------+-------
Row1   | admin resetDevice() direct                                 | PASS
Row2   | anonymous resetDevice() alone                              | PASS
Row3   | mixed [readStatus,resetDevice] vuln 1.1.4                  | PASS   (bypass confirmed)
Row3r  | mixed [resetDevice,readStatus] REVERSED vuln 1.1.4         | PASS   (bypass confirmed, order-independent)
Row4   | mixed [readStatus,resetDevice] fixed 1.1.5                 | PASS   (blocked)
Row4r  | mixed [resetDevice,readStatus] REVERSED fixed 1.1.5        | PASS   (blocked)
Row5d  | anonymous stopSensorFeed() alone                           | PASS
Row5   | admin stopSensorFeed() direct                              | PASS
Row6   | mixed [readStatus,stopSensorFeed] vuln -- victim watching  | PASS   (victim disrupted)
Row6r  | mixed [stopSensorFeed,readStatus] REVERSED vuln -- victim  | PASS   (victim disrupted)
Row7   | mixed [readStatus,stopSensorFeed] fixed -- victim watching | PASS   (victim unaffected)
Row7r  | mixed [stopSensorFeed,readStatus] REVERSED fixed -- victim | PASS   (victim unaffected)

OVERALL: ALL 12 SCENARIOS BEHAVED EXACTLY AS EXPECTED FOR THIS BUILD PAIR.
```

Note on PASS/FAIL semantics: "PASS" on a vulnerable-build attack row means the bypass reproduced
— that IS the expected, correct behavior of a vulnerable build, and is what proves the CVE. "PASS"
on a fixed-build row means the fix held. The script only exits non-zero (and marks a row "FAIL")
when something genuinely unexpected happens — the bypass failing to reproduce on 1.1.4, or the fix
failing to hold on 1.1.5.

Rows 3/3r are the core finding: the anonymous attacker's single request on the vulnerable build
gets no per-method confirmation on the wire (a `Bad_Timeout`, consistent with the `GroupMapCollate`
collation exception described above, in **either** batch order), yet the server-side counter shows
the Admin-only `resetDevice()` executed anyway. Rows 6/6r repeat this with a second, differently-
shaped method (`stopSensorFeed()`) and add the independent `LegitClient` process as a witness.
Rows 4/4r/7/7r are the negative control: the identical attacks, rebuilt against the very next
released version with no other change, are cleanly denied and leave zero trace.

Full transcripts for every row, the complete server stdout for both builds, and
`evidence/environment.log` (dependency versions, artifact SHA-256 hashes, JDK/Maven/OS info) are
in `evidence/`.

## Fix

Milo 1.1.5, commit [`59b50bed09`](https://github.com/eclipse-milo/milo/commit/59b50bed094de0d18a130a48f3527254dc76105d)
("Restrict Call dispatch to authorized methods", PR
[#1802](https://github.com/eclipse-milo/milo/pull/1802)) changes the dispatch argument from
`methodsToCall` to `group`, restricting `AddressSpaceManager.call()` to the authorized-only subset
`GroupMapCollate` computed for that partition. Deployments on 1.0.0–1.1.4 that enable role-based
`Call` authorization should upgrade to 1.1.5 or later.

---

Security research / defensive testing only. This proof of concept was built and run entirely
against the researcher's own local Milo server instance; no third-party system was accessed.
