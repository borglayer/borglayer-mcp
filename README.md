# BorgLayer Marketplace MCP

Search, appraise, and purchase domains from the BorgLayer marketplace from any MCP-compatible AI agent.

## Connect

Remote MCP endpoint (SSE): https://mcp.borglayer.com/sse

Authenticate with a BorgLayer API key (Authorization: Bearer blk_live_...). Get one at https://borglayer.com

## Tools

- search_domains - Search marketplace listings (domains.read)
- get_domain - Domain details + appraisal (domains.read)
- get_appraisal - Four-tier appraisal in USDC (domains.read)
- list_listings - Browse active listings (listings.read)
- create_checkout - Escrow checkout for a listing (checkout.write)
- get_order - Order details (orders.read)
- get_order_status - Order status (orders.read)

## Security

- API keys are scoped (least-privilege) and can carry a spending limit.
- Purchases require the checkout.write scope explicitly.
- Funds held in non-custodial escrow (Base + USDC) with a 2-of-3 multisig resolver.

## REST API

Same operations over REST: https://borglayer.com/docs

## License

MIT
