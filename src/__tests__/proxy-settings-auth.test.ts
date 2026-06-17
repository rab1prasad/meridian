/**
 * Regression test for issue #477 + auth audit (extended for Feature 1/2).
 *
 * #477: every route under `/settings/*` (including the PATCH that mutates
 * per-adapter SDK feature config) must go through `requireAuth`. This pins
 * that gate.
 *
 * Feature 1 made the HTML page SHELLS public (so a browser can load them and
 * then attach the stored key via JS), while their data children stay gated.
 * The audit therefore checks BOTH directions:
 *   - every non-public registered prefix rejects an unauthenticated caller (401);
 *   - the known public shells stay public (so a data route can't silently
 *     follow them onto the public list);
 *   - an explicit positive list of data endpoints is asserted 401 so a future
 *     "made the wrong thing public" can't pass by editing the public set alone.
 *
 * Feature 2 adds role-gating: `/admin/*` requires an admin principal (403 for
 * a scoped user key, 200 for the master key).
 */
import { describe, it, expect, beforeAll, afterAll } from "bun:test"
import { mkdtempSync, rmSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"

const SAVED_KEY = process.env.MERIDIAN_API_KEY
const SAVED_DB = process.env.MERIDIAN_AUTH_DB
const TEST_KEY = "test-meridian-api-key"
let tmpDir: string
let userKey: string

beforeAll(async () => {
  tmpDir = mkdtempSync(join(tmpdir(), "meridian-auth-audit-"))
  process.env.MERIDIAN_API_KEY = TEST_KEY
  process.env.MERIDIAN_AUTH_DB = join(tmpDir, "auth.db")
  const ks = await import("../proxy/keyStore")
  ks._resetKeyStoreForTests()
  userKey = ks.createKey({ label: "u", userId: "u", role: "user", allowedModels: ["sonnet"] }).plaintext
})

afterAll(async () => {
  const ks = await import("../proxy/keyStore")
  ks._resetKeyStoreForTests()
  if (SAVED_KEY !== undefined) process.env.MERIDIAN_API_KEY = SAVED_KEY
  else delete process.env.MERIDIAN_API_KEY
  if (SAVED_DB !== undefined) process.env.MERIDIAN_AUTH_DB = SAVED_DB
  else delete process.env.MERIDIAN_AUTH_DB
  try { rmSync(tmpDir, { recursive: true, force: true }) } catch { /* ignore */ }
})

const { createProxyServer } = await import("../proxy/server")

describe("MERIDIAN_API_KEY — /settings/api/* (regression for #477)", () => {
  it("rejects GET /settings/api/features without auth", async () => {
    const { app } = createProxyServer({ port: 0, host: "127.0.0.1" })
    const res = await app.fetch(new Request("http://localhost/settings/api/features"))
    expect(res.status).toBe(401)
  })

  it("rejects PATCH /settings/api/features/:adapter without auth", async () => {
    const { app } = createProxyServer({ port: 0, host: "127.0.0.1" })
    const res = await app.fetch(new Request("http://localhost/settings/api/features/opencode", {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ sharedMemory: true }),
    }))
    expect(res.status).toBe(401)
  })

  it("accepts GET /settings/api/features with a matching x-api-key", async () => {
    const { app } = createProxyServer({ port: 0, host: "127.0.0.1" })
    const res = await app.fetch(new Request("http://localhost/settings/api/features", {
      headers: { "x-api-key": TEST_KEY },
    }))
    expect(res.status).toBe(200)
  })

  it("accepts GET /settings/api/features with a matching Bearer token", async () => {
    const { app } = createProxyServer({ port: 0, host: "127.0.0.1" })
    const res = await app.fetch(new Request("http://localhost/settings/api/features", {
      headers: { "authorization": `Bearer ${TEST_KEY}` },
    }))
    expect(res.status).toBe(200)
  })
})

describe("Feature 1: public HTML shells, gated data children", () => {
  const SHELLS = ["/login", "/telemetry", "/settings", "/profiles", "/plugins", "/admin"]
  const DATA = ["/telemetry/summary", "/settings/api/features", "/profiles/list", "/plugins/list", "/admin/keys", "/auth/whoami", "/v1/models"]

  it("serves each page shell without auth (not 401)", async () => {
    const { app } = createProxyServer({ port: 0, host: "127.0.0.1" })
    for (const path of SHELLS) {
      const res = await app.fetch(new Request(`http://localhost${path}`))
      expect(res.status).not.toBe(401)
    }
  })

  it("gates every data endpoint (401 without auth)", async () => {
    const { app } = createProxyServer({ port: 0, host: "127.0.0.1" })
    for (const path of DATA) {
      const res = await app.fetch(new Request(`http://localhost${path}`))
      expect({ path, status: res.status }).toEqual({ path, status: 401 })
    }
  })
})

describe("Feature 2: /admin/* role gate", () => {
  it("401s /admin/keys without any key", async () => {
    const { app } = createProxyServer({ port: 0, host: "127.0.0.1" })
    const res = await app.fetch(new Request("http://localhost/admin/keys"))
    expect(res.status).toBe(401)
  })

  it("allows GET /admin/keys for a scoped user key (read-only view)", async () => {
    // Non-admins can read the keys list so the admin page can render it in
    // read-only mode. Mutations remain admin-only (see next two tests).
    const { app } = createProxyServer({ port: 0, host: "127.0.0.1" })
    const res = await app.fetch(new Request("http://localhost/admin/keys", {
      headers: { "x-api-key": userKey },
    }))
    expect(res.status).toBe(200)
    const text = await res.text()
    expect(text).not.toContain("key_hash")
  })

  it("403s POST /admin/keys with a scoped user key (mint is admin-only)", async () => {
    const { app } = createProxyServer({ port: 0, host: "127.0.0.1" })
    const res = await app.fetch(new Request("http://localhost/admin/keys", {
      method: "POST",
      headers: { "Content-Type": "application/json", "x-api-key": userKey },
      body: JSON.stringify({ label: "x", userId: "x", allowedModels: ["*"] }),
    }))
    expect(res.status).toBe(403)
  })

  it("403s POST /admin/keys/:id/revoke with a scoped user key (revoke is admin-only)", async () => {
    const { app } = createProxyServer({ port: 0, host: "127.0.0.1" })
    const res = await app.fetch(new Request("http://localhost/admin/keys/key_xxxx/revoke", {
      method: "POST",
      headers: { "x-api-key": userKey },
    }))
    expect(res.status).toBe(403)
  })

  it("200s /admin/keys with the master key (no hashes in payload)", async () => {
    const { app } = createProxyServer({ port: 0, host: "127.0.0.1" })
    const res = await app.fetch(new Request("http://localhost/admin/keys", {
      headers: { "x-api-key": TEST_KEY },
    }))
    expect(res.status).toBe(200)
    const text = await res.text()
    expect(text).not.toContain("key_hash")
  })

  it("serves the /admin shell without a key (200)", async () => {
    const { app } = createProxyServer({ port: 0, host: "127.0.0.1" })
    const res = await app.fetch(new Request("http://localhost/admin"))
    expect(res.status).toBe(200)
  })
})

// ---------------------------------------------------------------------------
// Audit: any sensitive route added in the future must go through requireAuth.
// ---------------------------------------------------------------------------
describe("auth audit: every registered prefix is protected when MERIDIAN_API_KEY is set", () => {
  // Intentionally public: landing + health (read-only, non-sensitive) and the
  // Feature 1 page shells (HTML only; their data children stay gated and the
  // client JS attaches the key). Adding here is a security review.
  const PUBLIC_PREFIXES = new Set([
    "/", "/health",
    "/login", "/telemetry", "/settings", "/profiles", "/plugins", "/admin",
  ])

  it("rejects unauthenticated requests to every non-public route prefix", async () => {
    const { app } = createProxyServer({ port: 0, host: "127.0.0.1" })

    const routes = (app as unknown as { routes: Array<{ method: string; path: string }> }).routes
    const prefixes = new Set<string>()
    for (const r of routes) {
      if (r.method === "ALL") continue
      const probePath = r.path.replace(/:\w+/g, "x")
      prefixes.add(probePath)
    }

    const failures: string[] = []
    for (const path of prefixes) {
      if (PUBLIC_PREFIXES.has(path)) continue
      const res = await app.fetch(new Request(`http://localhost${path}`))
      // 401 = gated. 403 = gated + role-denied (admin routes hit with no key
      // still return 401 from requireAuth, so 403 won't appear here, but allow
      // it defensively for future role-only gates). Anything else = a leak.
      if (res.status !== 401 && res.status !== 403) {
        failures.push(`${path} returned ${res.status} (expected 401 — not protected by requireAuth)`)
      }
    }

    expect(failures).toEqual([])
  })
})
