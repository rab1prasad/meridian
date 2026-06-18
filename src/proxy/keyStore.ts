/**
 * Persistent store for scoped, per-user API keys.
 *
 * Backs Feature 2 (multi-key auth). The single env key `MERIDIAN_API_KEY`
 * remains the master/admin key and is NOT stored here — it is validated
 * directly in `auth.ts`. This store holds the additional keys an admin
 * mints from the admin panel, each scoped by expiry and allowed model
 * families.
 *
 * Unlike the telemetry SQLite store (which is gated behind TELEMETRY_PERSIST
 * and is allowed to fall back to memory), API keys are configuration that
 * MUST survive restarts — so persistence is always on. `libsql` is already a
 * regular dependency. The DB is opened lazily on first use so a deployment
 * with only the env key boots without touching disk.
 *
 * Security posture:
 *   - Only the sha256 hash of each key is stored; the plaintext is returned
 *     once at creation and never persisted.
 *   - `findByHash` fails CLOSED: any DB/error path returns undefined (→ 401),
 *     never a principal.
 *
 * This is a leaf module: it must not import from `server.ts` or `session/`.
 */

import Database from "libsql"
import { createHash, randomBytes } from "node:crypto"
import { existsSync, mkdirSync } from "node:fs"
import { homedir } from "node:os"
import { dirname, join } from "node:path"
import { MODEL_FAMILIES, type ModelFamily } from "./models"

export type KeyRole = "admin" | "user"

/** Wildcard meaning "every model family is allowed". */
export const ALLOW_ALL_MODELS = "*"

export interface ApiKeyRecord {
  id: string
  label: string
  userId: string
  keyPrefix: string
  role: KeyRole
  /** `["*"]` or a subset of MODEL_FAMILIES. */
  allowedModels: string[]
  createdAt: number
  expiresAt: number | null
  revoked: boolean
  lastUsedAt: number | null
}

/** Result of a successful key lookup — what the auth layer needs. */
export interface ResolvedKey {
  id: string
  label: string
  userId: string
  role: KeyRole
  allowedModels: string[]
}

const SCHEMA = `
CREATE TABLE IF NOT EXISTS api_keys (
  id             TEXT    PRIMARY KEY,
  label          TEXT    NOT NULL,
  user_id        TEXT    NOT NULL,
  key_hash       TEXT    NOT NULL,
  key_prefix     TEXT    NOT NULL,
  role           TEXT    NOT NULL CHECK (role IN ('admin','user')),
  allowed_models TEXT    NOT NULL,
  created_at     INTEGER NOT NULL,
  expires_at     INTEGER,
  revoked        INTEGER NOT NULL DEFAULT 0,
  last_used_at   INTEGER
);
CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(key_hash);
`

function defaultDbPath(): string {
  return join(homedir(), ".config", "meridian", "auth.db")
}

let db: Database.Database | null = null

/**
 * Idempotently open (and create, with parent dirs) the auth DB. Returns null
 * if the database cannot be opened — callers must treat null as "no keys"
 * (fail closed). Reuses the `~/.config/meridian` convention shared with
 * profiles.ts and the telemetry store.
 */
function getDb(): Database.Database | null {
  if (db) return db
  try {
    const dbPath = process.env.MERIDIAN_AUTH_DB || defaultDbPath()
    const dir = dirname(dbPath)
    if (!existsSync(dir)) mkdirSync(dir, { recursive: true })
    const opened = new Database(dbPath)
    opened.pragma("journal_mode = WAL")
    opened.pragma("synchronous = NORMAL")
    opened.exec(SCHEMA)
    db = opened
    return db
  } catch (err) {
    console.error(`[keyStore] Failed to open auth DB: ${err instanceof Error ? err.message : err}`)
    return null
  }
}

/** Test/teardown hook — close and forget the handle so the next call reopens. */
export function _resetKeyStoreForTests(): void {
  try { db?.close() } catch { /* ignore */ }
  db = null
}

/** Idempotent eager init. Optional — getDb() lazy-inits on first real call. */
export function initKeyStore(): void {
  getDb()
}

export function hashKey(plaintext: string): string {
  return createHash("sha256").update(plaintext).digest("hex")
}

/**
 * Validate + canonicalize an allowed-models list. Accepts `["*"]` (or any
 * list containing "*") → `["*"]`. Otherwise keeps only known families,
 * deduped and ordered.
 *
 * Empty input is valid and returns `[]` — the key has no model access. This
 * supports keys that only need to call non-model endpoints. The scope check
 * in `server.ts` treats `[]` as "deny every family" (since `includes("*")`
 * is false and no family matches), exactly the intended behavior.
 *
 * Non-empty input that contains no recognized families (e.g. `["bogus"]`)
 * still throws — that's a typed-it-wrong signal, not a "no access" intent.
 */
export function normalizeAllowedModels(input: unknown): string[] {
  if (!Array.isArray(input)) {
    throw new Error("allowedModels must be an array")
  }
  if (input.length === 0) return []
  const raw = input.map((v) => String(v).toLowerCase().trim())
  if (raw.includes(ALLOW_ALL_MODELS)) return [ALLOW_ALL_MODELS]
  const families = MODEL_FAMILIES.filter((f) => raw.includes(f))
  if (families.length === 0) {
    throw new Error(
      `allowedModels must be "*", [], or include at least one of: ${MODEL_FAMILIES.join(", ")}`
    )
  }
  return [...families]
}

/** True when a key's scope permits the given resolved family. */
export function isModelAllowed(allowedModels: string[], family: ModelFamily): boolean {
  return allowedModels.includes(ALLOW_ALL_MODELS) || allowedModels.includes(family)
}

function rowToRecord(r: Record<string, unknown>): ApiKeyRecord {
  return {
    id: r.id as string,
    label: r.label as string,
    userId: r.user_id as string,
    keyPrefix: r.key_prefix as string,
    role: r.role as KeyRole,
    allowedModels: JSON.parse(r.allowed_models as string),
    createdAt: r.created_at as number,
    expiresAt: (r.expires_at as number) ?? null,
    revoked: r.revoked === 1,
    lastUsedAt: (r.last_used_at as number) ?? null,
  }
}

export interface CreateKeyInput {
  label: string
  userId: string
  role: KeyRole
  allowedModels: string[]
  /** Epoch ms; null/undefined = never expires. */
  expiresAt?: number | null
}

export interface CreatedKey {
  id: string
  /** The plaintext key — shown to the admin ONCE, never stored. */
  plaintext: string
  prefix: string
}

/**
 * Mint a new key. Generates high-entropy plaintext, stores only its hash +
 * prefix, and returns the plaintext once. Throws if the store is unavailable
 * or inputs are invalid.
 */
export function createKey(input: CreateKeyInput): CreatedKey {
  const handle = getDb()
  if (!handle) throw new Error("Key store unavailable")

  const role: KeyRole = input.role === "admin" ? "admin" : "user"
  const allowedModels = normalizeAllowedModels(input.allowedModels)
  const label = String(input.label || "").trim() || "unnamed"
  const userId = String(input.userId || "").trim() || label

  // `sk-meridian-` prefix makes keys recognizable; 32 random bytes (base64url)
  // is ample entropy.
  const plaintext = `sk-meridian-${randomBytes(32).toString("base64url")}`
  const id = `key_${randomBytes(8).toString("hex")}`
  const prefix = plaintext.slice(0, 16)
  const now = Date.now()
  const expiresAt = input.expiresAt ?? null

  handle
    .prepare(
      `INSERT INTO api_keys (id, label, user_id, key_hash, key_prefix, role, allowed_models, created_at, expires_at, revoked, last_used_at)
       VALUES (@id, @label, @userId, @keyHash, @keyPrefix, @role, @allowedModels, @createdAt, @expiresAt, 0, NULL)`
    )
    .run({
      id,
      label,
      userId,
      keyHash: hashKey(plaintext),
      keyPrefix: prefix,
      role,
      allowedModels: JSON.stringify(allowedModels),
      createdAt: now,
      expiresAt,
    })

  return { id, plaintext, prefix }
}

/**
 * Resolve a presented plaintext key to its scope, or undefined if it is
 * unknown / revoked / expired / the store is unavailable. FAILS CLOSED.
 */
export function findByHash(hash: string): ResolvedKey | undefined {
  const handle = getDb()
  if (!handle) return undefined
  try {
    const row = handle
      .prepare(`SELECT * FROM api_keys WHERE key_hash = ? LIMIT 1`)
      .get(hash) as Record<string, unknown> | undefined
    if (!row) return undefined
    const rec = rowToRecord(row)
    if (rec.revoked) return undefined
    if (rec.expiresAt !== null && rec.expiresAt <= Date.now()) return undefined
    return {
      id: rec.id,
      label: rec.label,
      userId: rec.userId,
      role: rec.role,
      allowedModels: rec.allowedModels,
    }
  } catch (err) {
    console.error(`[keyStore] Lookup failed (denying): ${err instanceof Error ? err.message : err}`)
    return undefined
  }
}

/** All keys, newest first, WITHOUT hashes. Returns [] on error. */
export function listKeys(): ApiKeyRecord[] {
  const handle = getDb()
  if (!handle) return []
  try {
    const rows = handle
      .prepare(`SELECT * FROM api_keys ORDER BY created_at DESC`)
      .all() as Record<string, unknown>[]
    return rows.map(rowToRecord)
  } catch {
    return []
  }
}

export interface UpdateKeyInput {
  allowedModels?: string[]
  expiresAt?: number | null
  label?: string
}

/** Update a key's scope/expiry/label. Returns the updated record or undefined. */
export function updateKey(id: string, input: UpdateKeyInput): ApiKeyRecord | undefined {
  const handle = getDb()
  if (!handle) return undefined
  try {
    const sets: string[] = []
    const params: Record<string, unknown> = { id }
    if (input.allowedModels !== undefined) {
      sets.push("allowed_models = @allowedModels")
      params.allowedModels = JSON.stringify(normalizeAllowedModels(input.allowedModels))
    }
    if (input.expiresAt !== undefined) {
      sets.push("expires_at = @expiresAt")
      params.expiresAt = input.expiresAt
    }
    if (input.label !== undefined) {
      sets.push("label = @label")
      params.label = String(input.label).trim() || "unnamed"
    }
    if (sets.length > 0) {
      handle.prepare(`UPDATE api_keys SET ${sets.join(", ")} WHERE id = @id`).run(params)
    }
    const row = handle.prepare(`SELECT * FROM api_keys WHERE id = ?`).get(id) as
      | Record<string, unknown>
      | undefined
    return row ? rowToRecord(row) : undefined
  } catch (err) {
    throw err instanceof Error ? err : new Error(String(err))
  }
}

/** Mark a key revoked. Returns true if a row was affected. */
export function revokeKey(id: string): boolean {
  const handle = getDb()
  if (!handle) return false
  try {
    const res = handle.prepare(`UPDATE api_keys SET revoked = 1 WHERE id = ?`).run(id)
    return (res.changes ?? 0) > 0
  } catch {
    return false
  }
}

/** Best-effort last-used timestamp bump. Never throws. */
export function touchLastUsed(id: string, ts: number = Date.now()): void {
  const handle = getDb()
  if (!handle) return
  try {
    handle.prepare(`UPDATE api_keys SET last_used_at = ? WHERE id = ?`).run(ts, id)
  } catch {
    /* best effort */
  }
}
