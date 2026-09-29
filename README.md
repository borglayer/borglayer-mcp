# BorgLayer Marketplace MCP

An MCP server that lets AI agents search, appraise, and buy domains from the
[BorgLayer](https://borglayer.com) marketplace — across five blockchains, each
settled through a verified, non-custodial escrow contract.

**Endpoint:** `https://mcp.borglayer.com/sse`

## Supported chains & stablecoins

| Chain | Stablecoins | Verified escrow contract |
|-------|-------------|--------------------------|
| Base | USDC | [`0x91749468…9274a`](https://basescan.org/address/0x91749468B26306308595aa55C4B140eBaf79274a#code) |
| Arbitrum | USDC | [`0x91749468…9274a`](https://arbiscan.io/address/0x91749468B26306308595aa55C4B140eBaf79274a#code) |
| Polygon | USDC | [`0x91749468…9274a`](https://polygonscan.com/address/0x91749468B26306308595aa55C4B140eBaf79274a#code) |
| BNB Chain | USDC | [`0xc2B555F0…7d016`](https://bscscan.com/address/0xc2B555F06851D09Dd96fD5741DF347C98D07d016#code) |
| BNB Chain | USDT | [`0x843Fc057…3f676`](https://bscscan.com/address/0x843Fc057949d635564cFc1c9281e351A5423f676#code) |
| BNB Chain | USD1 | [`0x1bdC9E33…45a23`](https://bscscan.com/address/0x1bdC9E3317E3EBA55F3aeed71B95922046a45a23#code) |
| Robinhood Chain | USDG | [`0x91749468…9274a`](https://robinhoodchain.blockscout.com/address/0x91749468B26306308595aa55C4B140eBaf79274a) |

Every escrow is the same audited-pattern `DomainEscrow` contract: 0.99% platform
fee (enforced on-chain), non-custodial, with a 2-of-3 multisig (Gnosis Safe) as
the dispute resolver. Funds only ever move to the buyer, the seller, or the fee
receiver.

## Tools

- **search_domains** — search marketplace listings by keyword (domains.read)
- **get_domain** — a domain's details, listing, and appraisal (domains.read)
- **get_appraisal** — four-tier appraisal in USDC (domains.read)
- **list_listings** — browse active listings (listings.read)
- **list_chains** — supported chains + stablecoins, each with its verified escrow
- **create_checkout** — start an escrow checkout on a chosen chain + stablecoin
  (checkout.write; honours per-key spending limits)
- **get_order** / **get_order_status** — track an order (orders.read)

## Authentication

Each agent supplies its own BorgLayer API key per request
(`Authorization: Bearer blk_live_…`). The server holds no secrets; all scopes and
spending limits are enforced server-side by the BorgLayer v1 API. Get a key at
[borglayer.com/partners/apply](https://borglayer.com/partners/apply).

## Security

- No secrets stored; the caller's key is used per-request and never persisted.
- Fixed API base URL — no dynamic hosts (SSRF-safe).
- All inputs schema-validated.
- Purchases require the `checkout.write` scope + a per-key USDC spending limit,
  so an agent can never spend beyond its budget.

## Links

- Marketplace: https://borglayer.com/marketplace
- API docs: https://borglayer.com/docs
- Become a partner: https://borglayer.com/partners/apply
