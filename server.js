// BorgLayer MCP — SECURITY MODEL:
//  - Pure HTTPS proxy to the BorgLayer API /api/v1/ (no shell, no eval, no fs, no DB).
//  - Holds NO secrets. The agent supplies its own API key per request
//    (Authorization: Bearer blrk_...), which the API validates + scopes.
//  - All authz (scopes, prepaid-balance limits) enforced server-side by the API.
//  - A compromised MCP can do nothing beyond what a caller's key already allows.
//
// Transport: Streamable HTTP (stateless) at POST/GET/DELETE /mcp — the current MCP
// transport (SSE is deprecated). Each request carries the caller's Bearer key.
//
// The BorgLayer API is a prepaid-USDC-balance account: register / transfer / DNS /
// formation debit the account balance (insufficient balance -> top up).
import express from "express";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { z } from "zod";

const API_BASE = "https://api.borglayer.com/api/v1";

// Validate + extract the caller's API key (never stored). BorgLayer keys are blrk_<prefix>_<secret>.
function keyFrom(req) {
  const h = req.headers["authorization"] || "";
  const m = /^Bearer\s+(blrk_[a-z0-9_]+)$/i.exec(h.trim());
  return m ? m[1] : null;
}

// Fixed API caller — no dynamic URLs, no user-controlled hosts (SSRF-safe).
async function callApi(path, apiKey, { method = "GET", body } = {}) {
  const res = await fetch(`${API_BASE}${path}`, {
    method,
    headers: {
      "Authorization": `Bearer ${apiKey}`,
      "Content-Type": "application/json",
      "User-Agent": "BorgLayer-MCP/3.0",
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  let data; try { data = JSON.parse(text); } catch { data = { raw: text }; }
  return { ok: res.ok, status: res.status, data };
}

const qs = (obj) => {
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(obj)) if (v !== undefined && v !== null && v !== "") p.set(k, String(v));
  const s = p.toString();
  return s ? `?${s}` : "";
};

const ok = (r) => ({ content: [{ type: "text", text: JSON.stringify(r.data) }], isError: !r.ok });

// Build a fresh McpServer bound to one caller's key. Stateless: one per request.
function buildServer(apiKey) {
  const server = new McpServer({ name: "borglayer", version: "3.0.0" });

  // ---- read (read-only) ----
  server.registerTool("search_domains",
    { title: "Search domains", description: "Search available domains across BorgLayer's registrar (priced for your account).",
      inputSchema: { q: z.string().min(1).max(64) }, annotations: { readOnlyHint: true } },
    async (a) => ok(await callApi(`/search${qs({ q: a.q })}`, apiKey)));

  server.registerTool("list_domains",
    { title: "List my domains", description: "List the domains registered on your BorgLayer account.",
      inputSchema: {}, annotations: { readOnlyHint: true } },
    async () => ok(await callApi(`/domains`, apiKey)));

  server.registerTool("get_balance",
    { title: "Get account balance", description: "Get your BorgLayer account's prepaid USDC balance (in micro-USDC).",
      inputSchema: {}, annotations: { readOnlyHint: true } },
    async () => ok(await callApi(`/balance`, apiKey)));

  server.registerTool("list_chains",
    { title: "List funding chains", description: "List supported chains + stablecoins for funding, each with its verified escrow contract.",
      inputSchema: {}, annotations: { readOnlyHint: true } },
    async () => ok(await callApi(`/chains`, apiKey)));

  // ---- register (debits balance) ----
  server.registerTool("register_domain",
    { title: "Register a domain", description: "Register an available domain. Debits your prepaid USDC balance; returns the charge and remaining balance. Requires the domains.register scope. For country-code TLDs, set a default registrant profile first (create_registrant_profile).",
      inputSchema: { domain: z.string().min(3).max(253), years: z.number().int().min(1).max(10).optional() },
      annotations: { destructiveHint: true } },
    async (a) => ok(await callApi(`/register`, apiKey, { method: "POST", body: { domain: a.domain, years: a.years || 1 } })));

  // ---- transfer in (may debit balance) ----
  server.registerTool("transfer_in_domain",
    { title: "Transfer a domain in", description: "Transfer a domain you own at another registrar INTO BorgLayer. Needs the auth/EPP code from your current registrar (unlocked). Free for free ccTLDs; others include a 1-year extension debited from balance. Requires domains.transfer.",
      inputSchema: { domain: z.string().min(3).max(253), auth_code: z.string().max(255).optional(), whois_privacy: z.boolean().optional() },
      annotations: { destructiveHint: true } },
    async (a) => ok(await callApi(`/transfer-in`, apiKey, { method: "POST", body: { domain: a.domain, auth_code: a.auth_code, whois_privacy: a.whois_privacy } })));

  // ---- DNS ----
  server.registerTool("list_dns",
    { title: "List DNS records", description: "List DNS records for a domain on your account.",
      inputSchema: { domain: z.string().min(3).max(253) }, annotations: { readOnlyHint: true } },
    async (a) => ok(await callApi(`/domains/${encodeURIComponent(a.domain)}/dns`, apiKey)));

  server.registerTool("add_dns_record",
    { title: "Add a DNS record", description: "Add a DNS record to a domain on your account. Requires dns.write.",
      inputSchema: { domain: z.string().min(3).max(253), type: z.enum(["A","AAAA","CNAME","MX","TXT","NS","SRV","CAA"]), name: z.string().min(1).max(255), content: z.string().min(1).max(2000), ttl: z.number().int().min(60).max(604800).optional(), priority: z.number().int().min(0).max(65535).optional() } },
    async (a) => ok(await callApi(`/domains/${encodeURIComponent(a.domain)}/dns`, apiKey, { method: "POST", body: { type: a.type, name: a.name, content: a.content, ttl: a.ttl, priority: a.priority } })));

  server.registerTool("delete_dns_record",
    { title: "Delete a DNS record", description: "Delete a DNS record by id from a domain on your account. Requires dns.write.",
      inputSchema: { domain: z.string().min(3).max(253), record_id: z.string().min(1).max(64) }, annotations: { destructiveHint: true } },
    async (a) => ok(await callApi(`/domains/${encodeURIComponent(a.domain)}/dns/${encodeURIComponent(a.record_id)}`, apiKey, { method: "DELETE" })));

  // ---- registrant profiles ----
  server.registerTool("list_registrant_profiles",
    { title: "List registrant profiles", description: "List the registrant (owner) profiles on your account. Country-code domains require real registrant data.",
      inputSchema: {}, annotations: { readOnlyHint: true } },
    async () => ok(await callApi(`/registrant-profiles`, apiKey)));

  server.registerTool("create_registrant_profile",
    { title: "Create a registrant profile", description: "Create a registrant (owner) profile used as the real owner on registrations and transfers. WHOIS privacy masks it publicly where the TLD allows. Requires registrant.write.",
      inputSchema: { first_name: z.string().max(120), last_name: z.string().max(120), email: z.string().email().max(200), phone: z.string().max(40), address_line1: z.string().max(200), city: z.string().max(120), postal_code: z.string().max(40), country: z.string().length(2), organization_name: z.string().max(200).optional(), address_line2: z.string().max(200).optional(), state: z.string().max(120).optional(), label: z.string().max(120).optional(), is_default: z.boolean().optional() } },
    async (a) => ok(await callApi(`/registrant-profiles`, apiKey, { method: "POST", body: a })));

  server.registerTool("delete_registrant_profile",
    { title: "Delete a registrant profile", description: "Delete a registrant profile by id.",
      inputSchema: { id: z.string().min(1).max(64) }, annotations: { destructiveHint: true } },
    async (a) => ok(await callApi(`/registrant-profiles/${encodeURIComponent(a.id)}`, apiKey, { method: "DELETE" })));

  // ---- LLC formation ----
  server.registerTool("formation_quote",
    { title: "Quote an LLC formation", description: "Get a price quote to form a US LLC (or other entity) in a given state, with optional EIN and BOI add-ons. Read-only.",
      inputSchema: { company: z.string().min(1).max(200), state: z.string().min(2).max(40), entity: z.string().max(20).optional(), ein: z.boolean().optional(), boi: z.boolean().optional() },
      annotations: { readOnlyHint: true } },
    async (a) => ok(await callApi(`/formation/quote${qs({ company: a.company, state: a.state, entity: a.entity, ein: a.ein ? 1 : "", boi: a.boi ? 1 : "" })}`, apiKey)));

  server.registerTool("create_formation",
    { title: "Form an LLC", description: "Form a US LLC (or other entity). Debits your prepaid USDC balance for the quoted amount, then files. Requires formation.write and a contact object (name/email/address). Returns the order reference + status.",
      inputSchema: { company: z.string().min(1).max(200), state: z.string().min(2).max(40), entity: z.string().max(20).optional(), contact: z.record(z.any()), ein: z.boolean().optional(), boi: z.boolean().optional(), email: z.string().email().max(200).optional() },
      annotations: { destructiveHint: true } },
    async (a) => ok(await callApi(`/formation`, apiKey, { method: "POST", body: a })));

  server.registerTool("get_formation",
    { title: "Get formation status", description: "Get the status of a formation order by its reference.",
      inputSchema: { reference: z.string().min(1).max(64) }, annotations: { readOnlyHint: true } },
    async (a) => ok(await callApi(`/formation/${encodeURIComponent(a.reference)}`, apiKey)));

  return server;
}

const app = express();
app.use(express.json({ limit: "1mb" }));

app.get("/health", (_req, res) => res.json({ ok: true, service: "borglayer-mcp" }));

// Streamable HTTP, stateless: a new server+transport per request, closed on finish.
async function handleMcp(req, res) {
  const apiKey = keyFrom(req);
  if (!apiKey) {
    res.status(401).json({ jsonrpc: "2.0", error: { code: -32001, message: "Missing/invalid API key (Bearer blrk_...)" }, id: null });
    return;
  }
  const server = buildServer(apiKey);
  const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
  res.on("close", () => { try { transport.close(); server.close(); } catch (_) {} });
  try {
    await server.connect(transport);
    await transport.handleRequest(req, res, req.body);
  } catch (e) {
    if (!res.headersSent) {
      res.status(500).json({ jsonrpc: "2.0", error: { code: -32603, message: "Internal server error" }, id: null });
    }
  }
}

app.post("/mcp", handleMcp);
// GET/DELETE on /mcp: stateless server has no standalone stream or session to end.
app.get("/mcp", (_req, res) => res.status(405).json({ jsonrpc: "2.0", error: { code: -32000, message: "Method Not Allowed. Use POST for stateless Streamable HTTP." }, id: null }));
app.delete("/mcp", (_req, res) => res.status(405).json({ jsonrpc: "2.0", error: { code: -32000, message: "Method Not Allowed." }, id: null }));

const PORT = 8790;
app.listen(PORT, "127.0.0.1", () => console.log(`BorgLayer MCP (Streamable HTTP) on 127.0.0.1:${PORT}/mcp`));
