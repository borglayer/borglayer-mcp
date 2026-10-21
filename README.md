# BorgLayer MCP

The official MCP server for the [BorgLayer](https://borglayer.com) API. It lets
AI agents manage domains end to end on a BorgLayer account — **search** and
**register** domains, **transfer** domains in from another registrar, manage
**DNS**, set **registrant** details, and **form a US LLC** — all behind one
scoped, per-request API key, paid from a prepaid USDC account balance.

**Endpoint:** `https://mcp.borglayer.com/sse`

## How it works

A BorgLayer API key (`blrk_…`) is an account with a **prepaid USDC balance**.
Actions that cost money — registering a domain, transferring one in, forming an
LLC — debit that balance; if it's too low the API returns `insufficient_balance`
with a "top up" message and charges nothing. Read actions (search, list, DNS
read, quotes) are free. Every tool maps to one scoped `/api/v1` endpoint, and the
key only does what its scopes allow.

## Tools

**Read**
- **search_domains** — search available domains, priced for your account
- **list_domains** — the domains registered on your account
- **get_balance** — your prepaid USDC balance (micro-USDC)
- **list_chains** — supported chains + stablecoins for funding, each with its verified escrow contract

**Domains**
- **register_domain** — register an available domain · debits balance · `domains.register`
- **transfer_in_domain** — transfer a domain in with its auth/EPP code (free for free ccTLDs; others add a year) · `domains.transfer`
- **list_dns** — a domain's DNS records · `dns.read`
- **add_dns_record** / **delete_dns_record** — edit DNS (A/AAAA/CNAME/MX/TXT/NS/SRV/CAA) · `dns.write`

**Registrant (owner) details** — country-code TLDs require real registrant data
- **list_registrant_profiles** · **create_registrant_profile** (`registrant.write`) · **delete_registrant_profile**

**LLC formation**
- **formation_quote** — price a US LLC / entity with optional EIN + BOI · `formation.read`
- **create_formation** — form the entity; debits balance then files · `formation.write`
- **get_formation** — status of a formation order by reference · `formation.read`

> Buying a *listed* marketplace domain through on-chain escrow is a separate,
> wallet-signed flow and is not part of this account API. Use the BorgLayer app
> or web marketplace for escrow purchases.

## Supported chains & stablecoins (for funding / escrow)

| Chain | Stablecoins | Verified escrow contract |
|-------|-------------|--------------------------|
| Base | USDC | [`0x91749468…9274a`](https://basescan.org/address/0x91749468B26306308595aa55C4B140eBaf79274a#code) |
| Arbitrum | USDC | [`0x91749468…9274a`](https://arbiscan.io/address/0x91749468B26306308595aa55C4B140eBaf79274a#code) |
| Polygon | USDC | [`0x91749468…9274a`](https://polygonscan.com/address/0x91749468B26306308595aa55C4B140eBaf79274a#code) |
| BNB Chain | USDC | [`0xc2B555F0…7d016`](https://bscscan.com/address/0xc2B555F06851D09Dd96fD5741DF347C98D07d016#code) |
| BNB Chain | USDT | [`0x843Fc057…3f676`](https://bscscan.com/address/0x843Fc057949d635564cFc1c9281e351A5423f676#code) |
| BNB Chain | USD1 | [`0x1bdC9E33…45a23`](https://bscscan.com/address/0x1bdC9E3317E3EBA55F3aeed71B95922046a45a23#code) |
| Robinhood Chain | USDG | [`0x91749468…9274a`](https://robinhoodchain.blockscout.com/address/0x91749468B26306308595aa55C4B140eBaf79274a) |

## Authentication

Each agent supplies its own BorgLayer API key per request
(`Authorization: Bearer blrk_…`). The server holds no secrets; all scopes and the
prepaid-balance accounting are enforced server-side by the BorgLayer API. Get a
key and top up its balance at [borglayer.com](https://borglayer.com).

## Security

- No secrets stored; the caller's key is used per-request and never persisted.
- Fixed API base URL — no dynamic hosts (SSRF-safe).
- All inputs schema-validated before the request is made.
- Money-spending tools each require their own scope (`domains.register`,
  `domains.transfer`, `formation.write`) and are bounded by the account's prepaid
  balance, so an agent can never spend beyond what's funded.
- Dangerous operations that give a domain away — transferring a domain OUT
  (revealing its auth code) and account-to-account push — are intentionally **not**
  exposed by this server.

## Links

- BorgLayer: https://borglayer.com
- API docs: https://borglayer.com/docs
