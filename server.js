// BorgLayer Marketplace MCP — SECURITY MODEL:
//  - Pure HTTPS proxy to /api/v1/ (no shell, no eval, no fs, no DB).
//  - Holds NO secrets. The agent supplies its own API key per request
//    (Authorization: Bearer blk_...), which the v1 API validates + scopes.
//  - All authz (scopes, spending limits) enforced server-side by the API.
//  - A compromised MCP can do nothing beyond what a caller's key already allows.
import express from "express";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { SSEServerTransport } from "@modelcontextprotocol/sdk/server/sse.js";
import { z } from "zod";

const API_BASE = "https://api.borglayer.com/api/v1";

// Extract + validate the caller's API key from the request (never stored).
function keyFrom(req) {
  const h = req.headers["authorization"] || "";
  const m = /^Bearer\s+(blk_(live|test)_[a-z0-9_]+)$/i.exec(h.trim());
  return m ? m[1] : null;
}

// Fixed API caller — no dynamic URLs, no user-controlled hosts (SSRF-safe).
async function callApi(path, apiKey, { method = "GET", body } = {}) {
  const res = await fetch(`${API_BASE}${path}`, {
    method,
    headers: {
      "Authorization": `Bearer ${apiKey}`,
      "Content-Type": "application/json",
      "User-Agent": "BorgLayer-MCP/1.0",
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  let data; try { data = JSON.parse(text); } catch { data = { raw: text }; }
  return { ok: res.ok, status: res.status, data };
}

function makeServer(apiKey) {
  const server = new Server(
    { name: "borglayer-marketplace", version: "1.0.0" },
    { capabilities: { tools: {} } }
  );

  const tools = [
    { name: "search_domains", desc: "Search marketplace domain listings by keyword.",
      schema: { q: z.string().min(1).max(64), limit: z.number().int().min(1).max(50).optional() },
      run: (a) => callApi(`/domains/search?q=${encodeURIComponent(a.q)}&limit=${a.limit||20}`, apiKey) },
    { name: "get_domain", desc: "Get a domain's details, listing, and appraisal.",
      schema: { domain: z.string().min(3).max(253) },
      run: (a) => callApi(`/domains/${encodeURIComponent(a.domain)}`, apiKey) },
    { name: "get_appraisal", desc: "Get the appraised value of a domain.",
      schema: { domain: z.string().min(3).max(253) },
      run: (a) => callApi(`/domains/${encodeURIComponent(a.domain)}/appraisal`, apiKey) },
    { name: "list_listings", desc: "Browse active marketplace listings.",
      schema: { limit: z.number().int().min(1).max(50).optional() },
      run: (a) => callApi(`/listings?limit=${a.limit||20}`, apiKey) },
    { name: "create_checkout", desc: "Create a checkout for a listing (requires checkout.write scope + spending limit).",
      schema: { listing_id: z.string().uuid(), buyer_wallet: z.string().regex(/^0x[0-9a-fA-F]{40}$/) },
      run: (a) => callApi(`/checkout`, apiKey, { method: "POST", body: a }) },
    { name: "get_order", desc: "Get an order's full details.",
      schema: { order_id: z.string().uuid() },
      run: (a) => callApi(`/orders/${a.order_id}`, apiKey) },
    { name: "get_order_status", desc: "Get an order's current status.",
      schema: { order_id: z.string().uuid() },
      run: (a) => callApi(`/orders/${a.order_id}/status`, apiKey) },
  ];

  server.setRequestHandler({ method: "tools/list" }, async () => ({
    tools: tools.map(t => ({ name: t.name, description: t.desc,
      inputSchema: { type: "object", properties: Object.fromEntries(
        Object.entries(t.schema).map(([k, v]) => [k, { type: "string" }])) } })),
  }));

  server.setRequestHandler({ method: "tools/call" }, async (req) => {
    const tool = tools.find(t => t.name === req.params.name);
    if (!tool) return { content: [{ type: "text", text: "unknown tool" }], isError: true };
    // Validate args (injection-safe)
    const parsed = z.object(tool.schema).safeParse(req.params.arguments || {});
    if (!parsed.success) return { content: [{ type: "text", text: "invalid arguments: " + parsed.error.message }], isError: true };
    const r = await tool.run(parsed.data);
    return { content: [{ type: "text", text: JSON.stringify(r.data) }], isError: !r.ok };
  });

  return server;
}

const app = express();
app.get("/health", (_req, res) => res.json({ ok: true, service: "borglayer-mcp" }));
app.get("/sse", async (req, res) => {
  const apiKey = keyFrom(req);
  if (!apiKey) { res.status(401).json({ error: "Missing/invalid API key (Bearer blk_...)" }); return; }
  const transport = new SSEServerTransport("/messages", res);
  const server = makeServer(apiKey);
  await server.connect(transport);
});
const PORT = 8790;
app.listen(PORT, "127.0.0.1", () => console.log(`BorgLayer MCP on 127.0.0.1:${PORT}`));
