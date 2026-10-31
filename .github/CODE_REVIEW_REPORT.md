# Code Review Report: openGym

Generated: 2026-11-01 (nightly Claude Code review, scoped manual pass)

Scope reviewed: `api/sync-stamps.js`, `api/nudge-copy.js`, `api/coach/routes.js`, `api/coach/jobs.js`, `api/coach/config.js`, `api/coach/cohort.js`, `api/push-messages.js`, `api/passkeys-store.js`, `api/password.js`, `api/queue.js`, `mcp/src/api-client.js`, `mcp/src/state.js`, `mcp/src/write-tools.js`, `mcp/src/tools.js`, `scripts/ci/deps-audit.mjs`, `scripts/ci/test-audit.mjs`, `frontend/public/sw.js`.

Every finding below was verified against the source in this repository before opening the PR.

---

## 1. CRITICAL (must fix)

### 1.1 The scrypt memory bound omits `p` — a stored hash can demand ~2 GiB
**`api/password.js:76`**

```js
if (params.ln < 10 || params.ln > 17 || params.r < 1 || params.r > 16 || params.p < 1 || params.p > 16) return null;
if (128 * 2 ** params.ln * params.r > 256 * 1024 * 1024) return null;
```

The memory formula for scrypt is `128 * N * r * p` where `N = 2**ln`. The check omits `p` entirely, but the `maxmem` handed to `crypto.scrypt` *does* include it. So `ln=16, r=16, p=16` passes the check (the check computes 134 MiB) while the real allocation is `128 * 65536 * 16 * 16` = **2.1 GiB**.

The comment directly above this line states the intent: *"Bounds on what a stored string may ask for, so a hand-edited db.json cannot make one sign-in allocate more than 256 MiB or spin for minutes."* A corrupted or hand-edited `db.json` therefore bypasses the guard it was written to enforce and OOMs the API process on the next sign-in.

**Fix:** `if (128 * 2 ** params.ln * params.r * params.p > 256 * 1024 * 1024) return null;`

### 1.2 `atomicWrite` does not apply the file mode to an existing temp file
**`api/coach/config.js:139-143`**

```js
function atomicWrite(file, content, mode) {
  const tmp = file + '.tmp';
  fs.writeFileSync(tmp, content, mode ? { mode } : undefined);
  fs.renameSync(tmp, file);
}
```

`fs.writeFileSync` applies `mode` only when it **creates** the file. If a previous write was interrupted after the `.tmp` file was created (with the process umask default, `0644`), the next `atomicWrite` reuses that existing temp file and silently keeps `0644` — the `0o600` argument is ignored. The rename then publishes a world-readable file.

This path writes `coach.json`, `coach-auth-<uid>.json` and `coach-<uid>.json` — all of which carry encrypted provider credentials.

**Fix:** unlink the temp file before writing (`fs.rmSync(tmp, { force: true })`) or `fs.chmodSync(tmp, 0o600)` after the write.

---

## 2. HIGH (should fix)

### 2.1 Saving the caps form silently resets the other cap to unlimited
**`api/coach/routes.js:274-279`**

```js
if (body.caps) {
  patch.caps = {
    perProfileDaily: Math.max(0, Math.min(200, +body.caps.perProfileDaily || 0)),
    instanceDaily:   Math.max(0, Math.min(5000, +body.caps.instanceDaily || 0))
  };
}
```

`patch.caps` is rebuilt from the request body alone instead of being merged with the current configuration. A body carrying only `perProfileDaily` evaluates `+body.caps.instanceDaily || 0` → `0` — the **instance-wide daily cap is reset to unlimited**, and vice-versa. This is a silent limit removal on an admin save.

**Fix:** `patch.caps = { ...current.caps, perProfileDaily: ..., instanceDaily: ... };`

### 2.2 The "endpoint host changed → clear the stored key" check compares the wrong baseline
**`api/coach/routes.js:292-301`**

```js
const hostOf = cfg => { try { return new URL(baseUrlFor(target, cfg) || '').host; } catch { return ''; } };
const before = hostOf(current);
const saved = cfgStore.save(patch);
if (patch.providerOptions && before && hostOf(saved) !== before && saved.auth?.[target]) {
  cfgStore.saveAuth(target, null);
}
```

`hostOf` resolves the URL for `target` — the **new** provider — out of `cfg`, which still holds the **old** provider's options. When an admin switches provider *and* changes the base URL in one request, `before` is computed from the new provider's default URL against the old config, so the comparison is against the wrong baseline. The stored key for the new provider may survive a host change it should have been cleared for — and the comment above the code states exactly why that matters: *"sent to a new host it is handed to whoever runs that host."*

**Fix:** compute `before` as `baseUrlFor(target, current)` for the target provider, and compare against `baseUrlFor(target, saved)`.

### 2.3 `GET /api/coach/disclosure` leaks the provider host to signed-in users even when the Coach is off
**`api/coach/routes.js:52-65`**

The route does not check `cfgStore.isEnabled()` before computing `baseUrlFor(cfg.provider, cfg)`. On an instance where the Coach is switched off, every signed-in user still learns which provider this box is wired to and — if the endpoint is on the LAN — its internal address.

**Fix:** return `{ enabled: false }` without the host when `!cfgStore.isEnabled()`.

### 2.4 Prototype pollution through client-controlled keys in the sync stamp maps
**`api/sync-stamps.js:45` (`same`), `:102`, `:219-221`**

```js
const pr = isMap(cur?._prior) ? clone(cur._prior) : {};
...
delete pr[key];
pr[key] = [...].slice(-PRIOR_KEEP);
```

`key` comes from the union of `Object.keys(cur)` and `Object.keys(next)` — the client's own document. `JSON.parse` creates a **genuine own property** named `__proto__`, so `Object.keys` returns it, and `pr['__proto__'] = [...]` invokes the `[[Set]]` of `Object.prototype.__proto__`, replacing the map's prototype with attacker-controlled data. The same shape appears in the other plain-object maps built from client keys.

**Fix:** skip `__proto__` / `constructor` / `prototype` when writing, or build the maps with `Object.create(null)` and use `Object.defineProperty`.

### 2.5 `Object.assign` copies a client-controlled `__proto__` into the merged profile state
**`mcp/src/state.js:96,137`**

`Object.assign({}, defaultsShape(), state)` uses `[[Set]]` semantics, so a `__proto__` own property on the client-supplied `state` becomes the merged object's prototype. Fields the code then reads (`targetW`, `unit`, …) can be resolved from that prototype instead of from the document.

**Fix:** use object spread (`{ ...defaultsShape(), ...state }`) or a null-prototype target.

### 2.6 The service worker caches a redirected login page as if it were the app
**`frontend/public/sw.js:296-299`**

```js
fetch(e.request).then(res => {
  clearTimeout(slow)
  if (res.ok) { const copy = res.clone(); caches.open(CACHE).then(c => c.put(e.request, copy)).catch(() => {}) }
  resolve(res)
})
```

The install path (`precache`) deliberately refuses redirected answers — `if (res.ok && !res.redirected)` — for exactly the reason stated in the comment above it: *"an auth proxy's login page would otherwise stand in for the chunk for the rest of this build."* The **runtime** network-first handler has no `!res.redirected` check, so a 200-after-redirect login page is stored in the build cache under the app's own URL and served back as the app.

**Fix:** `if (res.ok && !res.redirected)`.

### 2.7 A broken dependency audit does not fail the build
**`scripts/ci/deps-audit.mjs:15-19,43`**

```js
} catch (e) { out = e.stdout }          // npm audit exits 1 when it finds anything
try { return JSON.parse(out) } catch { return { error: String(out).slice(0, 300) } }
...
if (fail) { console.log('::error::...'); process.exit(1) }
```

When `npm audit` cannot run at all (npm missing, network error, malformed JSON), the script prints "audit failed" in the summary table but `fail` is never set — `fail` is only set by a shipped high/critical advisory. The audit failing to run therefore **passes CI silently**, which is the exact opposite of what the step exists for.

**Fix:** set `fail = true` when `prod.error` or `all.error` is present.

### 2.8 Coach consent is read from the profile's own synced state
**`api/coach/jobs.js:198-221`**

Consent is read from `S.coach.consent.agreedAt` — inside the state blob that any writer of the profile can set (the MCP server, a `curl` PUT). A writer can therefore grant Coach consent unilaterally, and the first Coach job then ships the profile's workouts and weight to a third-party provider without a human ever having seen the disclosure.

**Fix:** record consent server-side (timestamp + disclosure version) through an explicit endpoint and require it before the first job.

---

## 3. MEDIUM (consider fixing)

### 3.1 `GET /api/admin/coach` spawns the provider runtime on every request
**`api/coach/routes.js:166-235`** — `adapter.check(...)` runs `codex --version` (a child process) per GET. An admin page on a polling loop spawns a process repeatedly. Cache the result for ~60 s.

### 3.2 `removePasskeyRecord` trusts a caller-supplied `otherWays` count
**`api/passkeys-store.js:87-92`** — the "may I remove this?" check and the actual removal both take `otherWays` as a number, with no consistency check between the two calls. A caller that passes different values can delete the last way into a profile. Derive the count inside the module.

### 3.3 `doneIds` reads `S.queue.since` raw instead of the normalised value
**`api/queue.js:45-61`** — with `since` missing, `(w.start ?? 0) >= undefined` is `false` for every workout (comparison with `undefined` → `NaN`), and the date bound collapses to the 1970 fallback computed by `queueOf`. Normalise `since` once in `queueOf` and use the normalised value.

### 3.4 `safe(uid)` silently rewrites a uid, so two distinct uids can alias one coach file
**`api/coach/jobs.js:49-50`** — `a/b` sanitises to `ab`, colliding with the legitimate uid `ab`. `api/coach/config.js:213` uses a strict validator that throws; the two should agree.

### 3.5 `jobEnv` silently drops the credential for an unknown type
**`api/coach/config.js:339-354`** — a credential whose `type` is not one of the three known types produces `name = null`, so the job runs with no key and the failure surfaces as a provider error instead of a configuration error.

### 3.6 The service worker may be terminated before a cache write lands
**`frontend/public/sw.js:262,298`** — `caches.open(CACHE).then(c => c.put(...))` is fire-and-forget and not attached to `e.waitUntil`, so the write can be cancelled when the worker is terminated. The offline shell then silently loses an asset. Wrap it in `e.waitUntil(...)`.

### 3.7 A range request is sliced even when the server answered 206
**`frontend/public/sw.js:189-197`** — `slice(res, range)` is called regardless of the status; a partial body is then treated as the whole file. Check `res.status === 200` before slicing.

### 3.8 `cache.add` accepts redirects during precache
**`frontend/public/sw.js:76`** — the code path that explicitly avoids redirects elsewhere uses `cache.add` for the non-code refs, so a `.webmanifest`/`.json` fetched through an auth proxy's login page is cached as the real file. Use the manual fetch-and-check path for the manifest.

### 3.9 `skipWaiting()` is called unconditionally on install
**`frontend/public/sw.js:91`** — a new build takes over an open page immediately, which can break the running app's chunk loading (the classic "chunk 404 after update"). Gate it behind an explicit update request from the page.

### 3.10 Push re-subscribe failures are swallowed and the status is not checked
**`frontend/public/sw.js:236-241`** — `.catch(() => {})` plus no status check means a 401 leaves the server with a stale subscription and the user silently loses push.

### 3.11 `DEVICE_URL` is an absolute path that misses in a subpath deployment
**`frontend/public/sw.js:240`** — `'/opengym-device-id'` does not match a relative key stored by the page; the device id then misses and the account receives duplicate notifications.

### 3.12 `slice()` reads the whole cached file into memory for every range request
**`frontend/public/sw.js:160,186`** — a 100 MB clip means a 100 MB allocation in the service worker on a phone.

### 3.13 A broken symlink makes `test-audit` skip the entire root
**`scripts/ci/test-audit.mjs:17-21,44`** — `statSync` throws on a broken symlink and the `catch { return [] }` discards the whole root. Handle per-entry errors so one bad file does not void the audit.

### 3.14 `stampPut` re-serialises the whole document several times per PUT
**`api/sync-stamps.js:535-573`** — `content(next)` twice, `highestStamp` twice, a full `notePrior` walk and the `keepUnknown` LCS over every routine and workout, on every PUT. For a multi-megabyte profile this is minutes of event-loop blocking.

### 3.15 `mcp/src/state.js` reads `db.json` once at init and never refreshes it
**`mcp/src/state.js:45`** — a profile created after the server started is invisible to the MCP server.

### 3.16 `mcp/src/write-tools.js:183` sends `baseRev: 0` when the server's revision is missing
**`mcp/src/write-tools.js:183`** — `got.body.rev ?? 0` sends a bogus base revision instead of refusing the write.

---

## 4. MINOR

- **`api/sync-stamps.js:45`** — `same()` compares via `JSON.stringify`, so key order decides equality; a client that re-serialises with sorted keys sees every field as changed. Use a key-sorted stringify.
- **`api/sync-stamps.js:60-66`** — `capStamps` orders by `Math.abs(stamp)`, so an add-back and a deletion of equal magnitude are trimmed in an arbitrary order; the `laterDel` tie-break is not honoured.
- **`api/sync-stamps.js:385-390`** — the coach-namespace shrink loop calls `JSON.stringify(out)` on every iteration (up to 60 times).
- **`api/sync-stamps.js:503-519`** — `keepHeld` overwrites a negative (add-back) record with a positive one, silently un-deleting a re-added entry.
- **`api/password.js:210-215`** — `resetCodeMatches` does not invalidate the code; single-use must be enforced by the caller.
- **`api/password.js:43-54`** — the scrypt slot handoff resolves a waiter without re-incrementing `running`, leaving a brief window where `running` over-counts the real occupancy.
- **`api/passkeys-store.js:47-65`** — `cred.id`, `cred.publicKey` and `cred.counter` are stored without type validation.
- **`api/push-messages.js:77`** — the tone is validated against the English table only; a locale missing a tone yields `undefined` and `copy.lines` throws. Use `copy?.[tone] ?? 'friendly'`.
- **`api/push-messages.js:39-43`** — `routineEmoji` passes any non-ASCII string through verbatim, so a multi-kilobyte "emoji" reaches the push title. Bound it.
- **`api/queue.js:66-72`** — a new `Intl.DateTimeFormat` is constructed on every `dayIn` call, several times per profile per reminder tick. Cache it per timezone.
- **`api/coach/cohort.js:151`** — `catch { return null }` swallows every error in `cohortForPayload`, so a broken cohort is invisible in the logs.
- **`api/coach/jobs.js:463-473`** — the `/bin/rm` helper inherits the server's environment; pass `env: {}` so no credential can reach the child.
- **`api/coach/jobs.js:89`** — `listUserIds` returns `f.slice(6, -5)`, so a stray `state-.json` yields an empty id.
- **`api/coach/routes.js:83-86,148-152`** — `body.intake` and the `accepted`/`rejected` arrays are accepted unbounded.
- **`mcp/src/tools.js:199-200`** — `isoToday` is re-implemented inline instead of using the `todayIso()` helper two lines above.
- **`mcp/src/tools.js:274`** — `localeCompare` on ISO dates relies on digit ordering; a strict `<`/`>` comparison is unambiguous.
- **`mcp/src/tools.js:40-43,90-105`** — `exerciseOf` does a linear scan of `S.customEx` for every set of every workout.
- **`mcp/src/tools.js:49-52`** — `withCustomsIndexed` mutates a module-global exercise index; safe only because every builder is synchronous.
- **`mcp/src/state.js:162-169`** — `localUid()` returns `OPENGYM_UID` without validating it and without honouring the documented "unreadable data directory throws" contract.
- **`scripts/ci/deps-audit.mjs:30`** — the dev-only counts go negative when the prod audit fails to parse.
- **`scripts/ci/deps-audit.mjs:33-36`** — a `via` entry that is a bare package name is dropped, so the dependency chain is not shown.
- **`scripts/ci/test-audit.mjs:41`** — `\bok\s*\(` counts as an assertion, so a test that merely calls a helper named `ok` is judged as asserting something.
- **`scripts/ci/test-audit.mjs:65`** — the "next test" boundary includes `describe`, so a trailing test's assertions can be cut off from the raw text.
- **`frontend/public/sw.js:176`** — `touched` grows for the worker's lifetime and is never pruned when `trimMedia` deletes entries.
- **`frontend/public/sw.js:238`** — `sub.toJSON()` may be `null`; `JSON.stringify({subscription: null})` is posted as-is.

---

## Summary

No remote-execution or injection surface was found: the API is a local HTTP server with its own auth layer, the MCP server talks to it over the same API, and no endpoint builds a shell command from client input. The defects are concentrated in three areas:

1. **Bounds that do not bound** — the scrypt memory check omits `p` (1.1) and `atomicWrite` does not enforce the file mode it was given (1.2). Both are the kind of guard that exists specifically to stop a corrupted file from taking the service down, and neither does.
2. **Silent resets of security-relevant state** — the caps merge (2.1), the provider-host comparison (2.2) and the service-worker redirect cache (2.6) all remove or fail to remove something the surrounding code says it is protecting.
3. **Trusting the client document** — the prototype-pollution paths (2.4, 2.5) and the consent read from synced state (2.8) all treat client-controlled data as authoritative.

The remaining HIGH/MEDIUM items are robustness and hygiene rather than immediate exposure.
