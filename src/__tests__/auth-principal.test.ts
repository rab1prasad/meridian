import { describe, expect, it, beforeEach, afterEach } from "bun:test"
import { mkdtempSync, rmSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"

/**
 * Principal resolution tests for auth.ts: env master key → admin, open mode →
 * synthetic admin (no login), stored scoped key → its role/scope, bad token →
 * 401. resolvePrincipal reads process.env live, so no re-import is needed
 * between env mutations; the key store is isolated via MERIDIAN_AUTH_DB.
 */

let tmpDir: string
let savedKey: string | undefined
let savedDbEnv: string | undefined

function mockCtx(headers: Record<string, string> = {}) {
  const vars: Record<string, unknown> = {}
  return {
    req: { header: (n: string) => headers[n.toLowerCase()] },
    set: (k: string, v: unknown) => { vars[k] = v },
    get: (k: string) => vars[k],
    json: (body: unknown, status?: number) => ({ body, status: status ?? 200 }),
  }
}

beforeEach(() => {
  savedKey = process.env.MERIDIAN_API_KEY
  savedDbEnv = process.env.MERIDIAN_AUTH_DB
  tmpDir = mkdtempSync(join(tmpdir(), "meridian-auth-"))
  process.env.MERIDIAN_AUTH_DB = join(tmpDir, "auth.db")
})

afterEach(async () => {
  const ks = await import("../proxy/keyStore")
  ks._resetKeyStoreForTests()
  if (savedKey !== undefined) process.env.MERIDIAN_API_KEY = savedKey
  else delete process.env.MERIDIAN_API_KEY
  if (savedDbEnv !== undefined) process.env.MERIDIAN_AUTH_DB = savedDbEnv
  else delete process.env.MERIDIAN_AUTH_DB
  try { rmSync(tmpDir, { recursive: true, force: true }) } catch { /* ignore */ }
})

describe("resolvePrincipal — open mode (no env key)", () => {
  it("returns a synthetic admin with full scope", async () => {
    delete process.env.MERIDIAN_API_KEY
    const { resolvePrincipal, authEnabled } = await import("../proxy/auth")
    expect(authEnabled()).toBe(false)
    const p = resolvePrincipal(mockCtx() as never)
    expect(p).toBeDefined()
    expect(p!.role).toBe("admin")
    expect(p!.allowedModels).toEqual(["*"])
  })
})

describe("resolvePrincipal — env master key", () => {
  it("resolves the master key to admin/['*']", async () => {
    process.env.MERIDIAN_API_KEY = "master-secret-xyz"
    const { resolvePrincipal } = await import("../proxy/auth")
    const p = resolvePrincipal(mockCtx({ "x-api-key": "master-secret-xyz" }) as never)
    expect(p).toBeDefined()
    expect(p!.role).toBe("admin")
    expect(p!.label).toBe("master")
    expect(p!.allowedModels).toEqual(["*"])
  })

  it("returns undefined for a missing key when auth is enabled", async () => {
    process.env.MERIDIAN_API_KEY = "master-secret-xyz"
    const { resolvePrincipal } = await import("../proxy/auth")
    expect(resolvePrincipal(mockCtx() as never)).toBeUndefined()
  })

  it("returns undefined for a wrong key", async () => {
    process.env.MERIDIAN_API_KEY = "master-secret-xyz"
    const { resolvePrincipal } = await import("../proxy/auth")
    expect(resolvePrincipal(mockCtx({ "x-api-key": "nope" }) as never)).toBeUndefined()
  })

  it("accepts the master key via Authorization: Bearer", async () => {
    process.env.MERIDIAN_API_KEY = "master-secret-xyz"
    const { resolvePrincipal } = await import("../proxy/auth")
    const p = resolvePrincipal(mockCtx({ authorization: "Bearer master-secret-xyz" }) as never)
    expect(p?.role).toBe("admin")
  })
})

describe("resolvePrincipal — stored scoped key", () => {
  it("resolves a user key to its role + model scope", async () => {
    process.env.MERIDIAN_API_KEY = "master-secret-xyz"
    const ks = await import("../proxy/keyStore")
    ks._resetKeyStoreForTests()
    const created = ks.createKey({ label: "alice", userId: "alice", role: "user", allowedModels: ["sonnet"] })

    const { resolvePrincipal } = await import("../proxy/auth")
    const p = resolvePrincipal(mockCtx({ "x-api-key": created.plaintext }) as never)
    expect(p).toBeDefined()
    expect(p!.role).toBe("user")
    expect(p!.allowedModels).toEqual(["sonnet"])
    expect(p!.keyId).toBe(created.id)
  })

  it("rejects a revoked stored key with 401 via requireAuth", async () => {
    process.env.MERIDIAN_API_KEY = "master-secret-xyz"
    const ks = await import("../proxy/keyStore")
    ks._resetKeyStoreForTests()
    const created = ks.createKey({ label: "bob", userId: "bob", role: "user", allowedModels: ["*"] })
    ks.revokeKey(created.id)

    const { requireAuth } = await import("../proxy/auth")
    let nextCalled = false
    const res = await requireAuth(
      mockCtx({ "x-api-key": created.plaintext }) as never,
      async () => { nextCalled = true },
    )
    expect(nextCalled).toBe(false)
    expect((res as { status: number }).status).toBe(401)
  })
})

describe("requireAdmin", () => {
  it("allows admin and 403s a user principal", async () => {
    const { requireAdmin } = await import("../proxy/auth")

    const adminCtx = mockCtx() as never as { set: (k: string, v: unknown) => void }
    adminCtx.set("principal", { role: "admin", allowedModels: ["*"] })
    let adminNext = false
    await requireAdmin(adminCtx as never, async () => { adminNext = true })
    expect(adminNext).toBe(true)

    const userCtx = mockCtx() as never as { set: (k: string, v: unknown) => void }
    userCtx.set("principal", { role: "user", allowedModels: ["sonnet"] })
    let userNext = false
    const res = await requireAdmin(userCtx as never, async () => { userNext = true })
    expect(userNext).toBe(false)
    expect((res as { status: number }).status).toBe(403)
  })
})
