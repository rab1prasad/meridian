import { describe, expect, it, beforeEach, afterEach } from "bun:test"
import { mkdtempSync, rmSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"

/**
 * Key store unit tests. Each test gets an isolated on-disk auth DB via
 * MERIDIAN_AUTH_DB + _resetKeyStoreForTests() so the lazy getDb() reopens
 * against the fresh path.
 */

let tmpDir: string
let savedDbEnv: string | undefined

async function freshStore() {
  const ks = await import("../proxy/keyStore")
  ks._resetKeyStoreForTests()
  return ks
}

beforeEach(() => {
  savedDbEnv = process.env.MERIDIAN_AUTH_DB
  tmpDir = mkdtempSync(join(tmpdir(), "meridian-keystore-"))
  process.env.MERIDIAN_AUTH_DB = join(tmpDir, "auth.db")
})

afterEach(async () => {
  const ks = await import("../proxy/keyStore")
  ks._resetKeyStoreForTests()
  if (savedDbEnv !== undefined) process.env.MERIDIAN_AUTH_DB = savedDbEnv
  else delete process.env.MERIDIAN_AUTH_DB
  try { rmSync(tmpDir, { recursive: true, force: true }) } catch { /* ignore */ }
})

describe("keyStore.createKey + findByHash", () => {
  it("creates a key and resolves it by hash", async () => {
    const ks = await freshStore()
    const created = ks.createKey({ label: "alice", userId: "alice", role: "user", allowedModels: ["sonnet"] })
    expect(created.plaintext).toMatch(/^sk-meridian-/)
    expect(created.id).toMatch(/^key_/)

    const resolved = ks.findByHash(ks.hashKey(created.plaintext))
    expect(resolved).toBeDefined()
    expect(resolved!.userId).toBe("alice")
    expect(resolved!.role).toBe("user")
    expect(resolved!.allowedModels).toEqual(["sonnet"])
  })

  it("returns undefined for an unknown hash", async () => {
    const ks = await freshStore()
    expect(ks.findByHash(ks.hashKey("nope"))).toBeUndefined()
  })
})

describe("keyStore expiry + revoke", () => {
  it("rejects an expired key", async () => {
    const ks = await freshStore()
    const created = ks.createKey({
      label: "temp", userId: "temp", role: "user", allowedModels: ["*"],
      expiresAt: Date.now() - 1000,
    })
    expect(ks.findByHash(ks.hashKey(created.plaintext))).toBeUndefined()
  })

  it("accepts a not-yet-expired key", async () => {
    const ks = await freshStore()
    const created = ks.createKey({
      label: "temp", userId: "temp", role: "user", allowedModels: ["*"],
      expiresAt: Date.now() + 60_000,
    })
    expect(ks.findByHash(ks.hashKey(created.plaintext))).toBeDefined()
  })

  it("rejects a revoked key", async () => {
    const ks = await freshStore()
    const created = ks.createKey({ label: "r", userId: "r", role: "user", allowedModels: ["opus"] })
    expect(ks.revokeKey(created.id)).toBe(true)
    expect(ks.findByHash(ks.hashKey(created.plaintext))).toBeUndefined()
  })
})

describe("keyStore.listKeys", () => {
  it("omits the key hash and never returns plaintext", async () => {
    const ks = await freshStore()
    ks.createKey({ label: "a", userId: "a", role: "user", allowedModels: ["sonnet"] })
    const list = ks.listKeys()
    expect(list.length).toBe(1)
    const rec = list[0] as Record<string, unknown>
    expect(rec.keyPrefix).toBeDefined()
    expect("key_hash" in rec).toBe(false)
    expect("keyHash" in rec).toBe(false)
    expect("plaintext" in rec).toBe(false)
  })
})

describe("keyStore.touchLastUsed", () => {
  it("updates last_used_at and never throws", async () => {
    const ks = await freshStore()
    const created = ks.createKey({ label: "a", userId: "a", role: "user", allowedModels: ["*"] })
    expect(ks.listKeys()[0]!.lastUsedAt).toBeNull()
    ks.touchLastUsed(created.id, 1234567890)
    expect(ks.listKeys()[0]!.lastUsedAt).toBe(1234567890)
    // unknown id is a no-op, not a throw
    expect(() => ks.touchLastUsed("key_does_not_exist")).not.toThrow()
  })
})

describe("keyStore.normalizeAllowedModels", () => {
  it("collapses any list containing '*' to ['*']", async () => {
    const ks = await freshStore()
    expect(ks.normalizeAllowedModels(["sonnet", "*"])).toEqual(["*"])
  })

  it("keeps only known families, deduped", async () => {
    const ks = await freshStore()
    expect(ks.normalizeAllowedModels(["sonnet", "SONNET", "opus", "bogus"])).toEqual(["opus", "sonnet"])
  })

  it("returns [] for an empty array — keys without model access are allowed", async () => {
    const ks = await freshStore()
    expect(ks.normalizeAllowedModels([])).toEqual([])
  })

  it("throws when non-empty input contains no recognized families", async () => {
    const ks = await freshStore()
    expect(() => ks.normalizeAllowedModels(["bogus"])).toThrow()
    expect(() => ks.normalizeAllowedModels("sonnet" as unknown)).toThrow()
  })
})

describe("keyStore.isModelAllowed", () => {
  it("honors wildcard and explicit family membership", async () => {
    const ks = await freshStore()
    expect(ks.isModelAllowed(["*"], "opus")).toBe(true)
    expect(ks.isModelAllowed(["sonnet"], "sonnet")).toBe(true)
    expect(ks.isModelAllowed(["sonnet"], "opus")).toBe(false)
  })
})
