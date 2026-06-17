/**
 * API key authentication + authorization middleware.
 *
 * Two layers:
 *
 *  1. The master/admin key from `MERIDIAN_API_KEY` (env). When set, auth is
 *     "enabled" — every gated route requires a valid key. When unset, the
 *     proxy runs in OPEN MODE: requests are unauthenticated and treated as a
 *     single trusted admin (backward compatible with the original behavior).
 *
 *  2. Additional scoped keys minted by an admin and persisted in `keyStore.ts`.
 *     Each carries a role (admin|user) and an allowed-model-family scope.
 *
 * `requireAuth` resolves the caller to a `Principal` and stashes it on the
 * Hono context (`c.set("principal", ...)`) so downstream handlers can enforce
 * per-key model scoping (see `server.ts` handleMessages) and role-gate the
 * admin panel (`requireAdmin`). The principal is ALWAYS set — including in
 * open mode — so `getPrincipal` never returns undefined on a gated route.
 *
 * Uses constant-time comparison for the env master key to prevent timing
 * attacks. Stored keys are matched by sha256 hash lookup (no incremental
 * string-compare oracle exists for a hash, so constant-time isn't needed
 * there); both failure modes return an identical 401.
 *
 * Leaf module: must not import from `server.ts` or `session/`.
 */

import { createHmac, timingSafeEqual } from "node:crypto"
import type { Context, Next } from "hono"
import { findByHash, hashKey, touchLastUsed, type KeyRole } from "./keyStore"

export interface Principal {
  role: KeyRole
  /** `["*"]` or a subset of model families this caller may use. */
  allowedModels: string[]
  /** Stored-key id, when the caller authenticated with a minted key. */
  keyId?: string
  /** Human label — "master" for the env key, else the key's label. */
  label?: string
  /** Username (key userId) for telemetry attribution. "master"/"open" for the
   *  env key / open mode. */
  user?: string
}

/**
 * Hono environment type. Parameterize the app as `new Hono<AppEnv>()` so
 * `c.get/set("principal")` is fully typed.
 */
export type AppEnv = {
  Variables: {
    principal: Principal
  }
}

function getConfiguredKey(): string | undefined {
  return process.env.MERIDIAN_API_KEY || undefined
}

/**
 * Whether API key authentication is enabled — true iff MERIDIAN_API_KEY is
 * set. The admin master key bootstraps the whole multi-key system; without
 * it the proxy is open and the admin panel is freely usable by the single
 * trusted operator.
 */
export function authEnabled(): boolean {
  return Boolean(getConfiguredKey())
}

/**
 * Constant-time string comparison to prevent timing attacks.
 * Hashes both values to ensure equal-length comparison regardless of input.
 */
function safeCompare(a: string, b: string): boolean {
  const hashA = createHmac("sha256", "meridian").update(a).digest()
  const hashB = createHmac("sha256", "meridian").update(b).digest()
  return timingSafeEqual(hashA, hashB)
}

/**
 * Extract the API key from the request.
 * Checks x-api-key header first, then Authorization: Bearer.
 */
function extractKey(c: Context): string | undefined {
  const apiKey = c.req.header("x-api-key")
  if (apiKey) return apiKey

  const auth = c.req.header("authorization")
  if (auth?.startsWith("Bearer ")) return auth.slice(7)

  return undefined
}

/** The principal used in open mode (no env key configured). */
const OPEN_MODE_PRINCIPAL: Principal = { role: "admin", allowedModels: ["*"], label: "open", user: "open" }

function unauthorized(c: Context) {
  return c.json(
    {
      type: "error",
      error: {
        type: "authentication_error",
        message: "Invalid or missing API key",
      },
    },
    401
  )
}

/**
 * Resolve the caller to a Principal without sending a response. Returns
 * undefined when a key is required but missing/invalid. Exported for reuse
 * (e.g. the /auth/whoami handler and tests).
 */
export function resolvePrincipal(c: Context): Principal | undefined {
  if (!authEnabled()) return OPEN_MODE_PRINCIPAL

  const provided = extractKey(c)
  if (!provided) return undefined

  // Master/admin key — constant-time compare against the env value.
  const master = getConfiguredKey()
  if (master && safeCompare(provided, master)) {
    return { role: "admin", allowedModels: ["*"], label: "master", user: "master" }
  }

  // Stored scoped key — sha256 hash lookup (fails closed).
  const resolved = findByHash(hashKey(provided))
  if (resolved) {
    // Best-effort usage bump; never blocks the request.
    touchLastUsed(resolved.id)
    return {
      role: resolved.role,
      allowedModels: resolved.allowedModels,
      keyId: resolved.id,
      label: resolved.label,
      user: resolved.userId,
    }
  }

  return undefined
}

/**
 * Hono middleware: authenticate the request and stash the Principal.
 * No-op auth (open-mode admin principal) when MERIDIAN_API_KEY is unset.
 */
export async function requireAuth(c: Context, next: Next) {
  const principal = resolvePrincipal(c)
  if (!principal) return unauthorized(c)
  c.set("principal", principal)
  return next()
}

/**
 * Read the resolved principal off the context. Throws if called on a route
 * that did not go through `requireAuth` (defense-in-depth — a missing
 * principal is a wiring bug, not an auth decision).
 */
export function getPrincipal(c: Context): Principal {
  const principal = c.get("principal") as Principal | undefined
  if (!principal) {
    throw new Error("getPrincipal called without requireAuth on this route")
  }
  return principal
}

/**
 * Hono middleware: require the resolved principal to be an admin. Must run
 * AFTER `requireAuth`. Returns 403 (authenticated but not authorized) for
 * non-admin principals.
 */
export async function requireAdmin(c: Context, next: Next) {
  const principal = getPrincipal(c)
  if (principal.role !== "admin") {
    return c.json(
      {
        type: "error",
        error: {
          type: "permission_error",
          message: "Admin privileges required",
        },
      },
      403
    )
  }
  return next()
}
