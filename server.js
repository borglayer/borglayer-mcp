// BorgLayer MCP — SECURITY MODEL:
//  - Pure HTTPS proxy to the BorgLayer API /api/v1/ (no shell, no eval, no fs, no DB).
//  - Holds NO secrets. The agent supplies its own API key per request
//    (Authorization: Bearer blrk_...), which the API validates + scopes.
//  - All authz (scopes, prepaid-balance limits) enforced server-side by the API.
//  - A compromised MCP can do nothing beyond what a caller's key already allows.
//
// The BorgLayer API is a prepaid-USDC-balance account: register / transfer / DNS /
// formation debit the account balance (insufficient balance -> top up). Every tool
// here maps 1:1 to a scoped /api/v1 endpoint.
import express from "express";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { SSEServerTransport } from "@modelcontextprotocol/sdk/server/sse.js";
import { z } from "zod";

const API_BASE = "https://api.borglayer.com/api/v1";

// Extract + validate the caller's API key from the request (never stored).
// BorgLayer API keys are blrk_<prefix>_<secret>.
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
      "User-Agent": "BorgLayer-MCP/2.0",
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

function makeServer(apiKey) {
  const server = new Server(
    { name: "borglayer", version: "2.0.0" },
    { capabilities: { tools: {} } }
  );

  const tools = [
    // ---- read ----
    { name: "search_domains", desc: "Search available domains across BorgLayer's registrar (priced for your account).",
      schema: { q: z.string().min(1).max(64) },
      run: (a) => callApi(`/search${qs({ q: a.q })}`, apiKey) },
    { name: "list_domains", desc: "List the domains registered on your BorgLayer account.",
      schema: {},
      run: () => callApi(`/domains`, apiKey) },
    { name: "get_balance", desc: "Get your BorgLayer account's prepaid USDC balance (in micro-USDC).",
      schema: {},
      run: () => callApi(`/balance`, apiKey) },
    { name: "list_chains", desc: "List supported chains + stablecoins for funding, each with its verified escrow contract.",
      schema: {},
      run: () => callApi(`/chains`, apiKey) },

    // ---- register (debits balance) ----
    { name: "register_domain", desc: "Register an available domain. Debits your prepaid USDC balance; returns the charge and remaining balance. Requires the domains.register scope. For country-code TLDs, set a default registrant profile first (create_registrant_profile).",
      schema: { domain: z.string().min(3).max(253), years: z.number().int().min(1).max(10).optional() },
      run: (a) => callApi(`/register`, apiKey, { method: "POST", body: { domain: a.domain, years: a.years || 1 } }) },

    // ---- transfer in (debits balance / free for free ccTLDs) ----
    { name: "transfer_in_domain", desc: "Transfer a domain you own at another registrar INTO BorgLayer. Needs the auth/EPP code from your current registrar (unlocked). Free for free ccTLDs; others include a 1-year extension debited from balance. Requires domains.transfer.",
      schema: { domain: z.string().min(3).max(253), auth_code: z.string().max(255).optional(), whois_privacy: z.boolean().optional() },
      run: (a) => callApi(`/transfer-in`, apiKey, { method: "POST", body: { domain: a.domain, auth_code: a.auth_code, whois_privacy: a.whois_privacy } }) },

    // ---- DNS ----
    { name: "list_dns", desc: "List DNS records for a domain on your account.",
      schema: { domain: z.string().min(3).max(253) },
      run: (a) => callApi(`/domains/${encodeURIComponent(a.domain)}/dns`, apiKey) },
    { name: "add_dns_record", desc: "Add a DNS record to a domain on your account. Requires dns.write.",
      schema: { domain: z.string().min(3).max(253), type: z.enum(["A","AAAA","CNAME","MX","TXT","NS","SRV","CAA"]), name: z.string().min(1).max(255), content: z.string().min(1).max(2000), ttl: z.number().int().min(60).max(604800).optional(), priority: z.number().int().min(0).max(65535).optional() },
      run: (a) => callApi(`/domains/${encodeURIComponent(a.domain)}/dns`, apiKey, { method: "POST", body: { type: a.type, name: a.name, content: a.content, ttl: a.ttl, priority: a.priority } }) },
    { name: "delete_dns_record", desc: "Delete a DNS record by id from a domain on your account. Requires dns.write.",
      schema: { domain: z.string().min(3).max(253), record_id: z.string().min(1).max(64) },
      run: (a) => callApi(`/domains/${encodeURIComponent(a.domain)}/dns/${encodeURIComponent(a.record_id)}`, apiKey, { method: "DELETE" }) },

    // ---- registrant profiles (required owner data for ccTLDs) ----
    { name: "list_registrant_profiles", desc: "List the registrant (owner) profiles on your account. Country-code domains require real registrant data.",
      schema: {},
      run: () => callApi(`/registrant-profiles`, apiKey) },
    { name: "create_registrant_profile", desc: "Create a registrant (owner) profile used as the real owner on registrations and transfers. WHOIS privacy masks it publicly where the TLD allows. Requires registrant.write.",
      schema: { first_name: z.string().max(120), last_name: z.string().max(120), email: z.string().email().max(200), phone: z.string().max(40), address_line1: z.string().max(200), city: z.string().max(120), postal_code: z.string().max(40), country: z.string().length(2), organization_name: z.string().max(200).optional(), address_line2: z.string().max(200).optional(), state: z.string().max(120).optional(), label: z.string().max(120).optional(), is_default: z.boolean().optional() },
      run: (a) => callApi(`/registrant-profiles`, apiKey, { method: "POST", body: a }) },
    { name: "delete_registrant_profile", desc: "Delete a registrant profile by id.",
      schema: { id: z.string().min(1).max(64) },
      run: (a) => callApi(`/registrant-profiles/${encodeURIComponent(a.id)}`, apiKey, { method: "DELETE" }) },

    // ---- LLC formation ----
    { name: "formation_quote", desc: "Get a price quote to form a US LLC (or other entity) in a given state, with optional EIN and BOI add-ons. Read-only.",
      schema: { company: z.string().min(1).max(200), state: z.string().min(2).max(40), entity: z.string().max(20).optional(), ein: z.boolean().optional(), boi: z.boolean().optional() },
      run: (a) => callApi(`/formation/quote${qs({ company: a.company, state: a.state, entity: a.entity, ein: a.ein ? 1 : "", boi: a.boi ? 1 : "" })}`, apiKey) },
    { name: "create_formation", desc: "Form a US LLC (or other entity). Debits your prepaid USDC balance for the quoted amount, then files. Requires formation.write and a contact object (name/email/address). Returns the order reference + status.",
      schema: { company: z.string().min(1).max(200), state: z.string().min(2).max(40), entity: z.string().max(20).optional(), contact: z.record(z.any()), ein: z.boolean().optional(), boi: z.boolean().optional(), email: z.string().email().max(200).optional() },
      run: (a) => callApi(`/formation`, apiKey, { method: "POST", body: a }) },
    { name: "get_formation", desc: "Get the status of a formation order by its reference.",
      schema: { reference: z.string().min(1).max(64) },
      run: (a) => callApi(`/formation/${encodeURIComponent(a.reference)}`, apiKey) },
  ];

  // zod -> minimal JSON Schema (string/number/boolean) for tools/list
  const jsonType = (zt) => {
    const d = zt?._def?.typeName;
    if (d === "ZodNumber") return "number";
    if (d === "ZodBoolean") return "boolean";
    return "string"; // string, enum, record, and optional-wrapped default to string-ish
  };

  server.setRequestHandler({ method: "tools/list" }, async () => ({
    tools: tools.map(t => ({
      name: t.name, description: t.desc,
      inputSchema: {
        type: "object",
        properties: Object.fromEntries(Object.entries(t.schema).map(([k, v]) => {
          const inner = v?._def?.innerType || v; // unwrap .optional()
          return [k, { type: jsonType(inner) }];
        })),
        required: Object.entries(t.schema).filter(([, v]) => v?._def?.typeName !== "ZodOptional").map(([k]) => k),
      },
    })),
  }));

  server.setRequestHandler({ method: "tools/call" }, async (req) => {
    const tool = tools.find(t => t.name === req.params.name);
    if (!tool) return { content: [{ type: "text", text: "unknown tool" }], isError: true };
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
  if (!apiKey) { res.status(401).json({ error: "Missing/invalid API key (Bearer blrk_...)" }); return; }
  const transport = new SSEServerTransport("/messages", res);
  const server = makeServer(apiKey);
  await server.connect(transport);
});
const PORT = 8790;
app.listen(PORT, "127.0.0.1", () => console.log(`BorgLayer MCP on 127.0.0.1:${PORT}`));
