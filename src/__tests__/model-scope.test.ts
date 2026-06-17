/**
 * Model-scope enforcement (Feature 2). A scoped user key may only invoke the
 * model families in its allowedModels; the master key (and open mode) bypass.
 * Enforcement lives at a single chokepoint in handleMessages after
 * mapModelToClaudeModel resolves the family, so it also covers the internal
 * /v1/chat/completions → /v1/messages hop.
 *
 * SDK is mocked (same pattern as integration.test.ts) so the allowed-path
 * requests return 200 without hitting the real Claude API.
 */

import { describe, it, expect, mock, beforeAll, beforeEach, afterAll } from "bun:test"
import { mkdtempSync, rmSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { assistantMessage } from "./helpers"

let mockMessages: any[] = []

mock.module("@anthropic-ai/claude-agent-sdk", () => ({
  query: () => (async function* () { for (const m of mockMessages) yield m })(),
  createSdkMcpServer: () => ({ type: "sdk", name: "test", instance: {} }),
  tool: () => ({}),
}))

mock.module("../logger", () => ({
  claudeLog: () => {},
  withClaudeLogContext: (_ctx: any, fn: any) => fn(),
}))

mock.module("../mcpTools", () => ({
  createOpencodeMcpServer: () => ({ type: "sdk", name: "opencode", instance: {} }),
}))

const MASTER = "master-secret-xyz"
let tmpDir: string
let savedKey: string | undefined
let savedDbEnv: string | undefined
let savedPassthrough: string | undefined

tmpDir = mkdtempSync(join(tmpdir(), "meridian-scope-"))
savedKey = process.env.MERIDIAN_API_KEY
savedDbEnv = process.env.MERIDIAN_AUTH_DB
savedPassthrough = process.env.MERIDIAN_PASSTHROUGH
process.env.MERIDIAN_API_KEY = MASTER
process.env.MERIDIAN_AUTH_DB = join(tmpDir, "auth.db")
process.env.MERIDIAN_PASSTHROUGH = "0"

const { createProxyServer } = await import("../proxy/server")
const keyStore = await import("../proxy/keyStore")

let app: any
let userKey: string

beforeAll(() => {
  keyStore._resetKeyStoreForTests()
  const created = keyStore.createKey({
    label: "alice", userId: "alice", role: "user", allowedModels: ["sonnet"],
  })
  userKey = created.plaintext
  app = createProxyServer({ port: 0, host: "127.0.0.1" }).app
})

afterAll(() => {
  keyStore._resetKeyStoreForTests()
  if (savedKey !== undefined) process.env.MERIDIAN_API_KEY = savedKey
  else delete process.env.MERIDIAN_API_KEY
  if (savedDbEnv !== undefined) process.env.MERIDIAN_AUTH_DB = savedDbEnv
  else delete process.env.MERIDIAN_AUTH_DB
  if (savedPassthrough !== undefined) process.env.MERIDIAN_PASSTHROUGH = savedPassthrough
  else delete process.env.MERIDIAN_PASSTHROUGH
  try { rmSync(tmpDir, { recursive: true, force: true }) } catch { /* ignore */ }
})

beforeEach(() => {
  mockMessages = [assistantMessage([{ type: "text", text: "hi" }])]
})

function messages(model: string, key: string, path = "/v1/messages") {
  return app.fetch(new Request("http://localhost" + path, {
    method: "POST",
    headers: { "Content-Type": "application/json", "x-api-key": key },
    body: JSON.stringify({ model, max_tokens: 16, stream: false, messages: [{ role: "user", content: "hi" }] }),
  }))
}

describe("model scope — /v1/messages", () => {
  it("allows a sonnet-scoped key to call sonnet", async () => {
    const res = await messages("sonnet", userKey)
    expect(res.status).toBe(200)
  })

  it("403s a sonnet-scoped key calling opus", async () => {
    const res = await messages("opus", userKey)
    expect(res.status).toBe(403)
  })

  it("treats opus[1m] / canonical opus id as the opus family (403 for sonnet scope)", async () => {
    const res = await messages("claude-opus-4-8", userKey)
    expect(res.status).toBe(403)
  })

  it("lets the master (admin/'*') key call any family", async () => {
    expect((await messages("opus", MASTER)).status).toBe(200)
    expect((await messages("sonnet", MASTER)).status).toBe(200)
  })
})

describe("model scope — internal /v1/chat/completions hop", () => {
  it("403s a sonnet-scoped key requesting opus via the OpenAI endpoint", async () => {
    const res = await app.fetch(new Request("http://localhost/v1/chat/completions", {
      method: "POST",
      headers: { "Content-Type": "application/json", "x-api-key": userKey },
      body: JSON.stringify({ model: "opus", messages: [{ role: "user", content: "hi" }] }),
    }))
    expect(res.status).toBe(403)
  })
})
