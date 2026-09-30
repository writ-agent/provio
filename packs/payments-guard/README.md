# payments-guard

Hard block on live-mode Stripe writes from the shell, and human gates on
money movement and billing changes: the Stripe CLI, payment MCP tools
(Stripe agent toolkit / Stripe MCP, PayPal, wallet servers), `curl` to
payment provider APIs, cloud billing CLIs, and crypto wallets. Read-only
`list`/`retrieve`/`get` calls are not matched.

```yaml
version: 1
default: allow        # or ask
packs: [floor, payments-guard]
```

| Rule | Verdict | Covers |
|---|---|---|
| `pay-stripe-live-write-denied` | deny | Stripe CLI with `--live` and a write (`<resource> create/update/delete/confirm/capture/cancel/pay/finalize/send/void/…`, `stripe post`, `stripe delete`); `curl … api.stripe.com/v1/…` with an `sk_live_`/`rk_live_` key and a request body or POST/DELETE |
| `pay-stripe-money-movement-asks` | ask, irreversible | `stripe charges create/capture`, `payment_intents confirm/capture`, `refunds create`, `payouts create`, `transfers create`, `topups create`, `invoices pay/finalize/send`, `credit_notes create`, and `stripe post /v1/<those>`; inline SDK calls in a shell command (`stripe.Refund.create(`, `stripe.refunds.create(`, `stripe.PaymentIntent.confirm(`, …) |
| `pay-stripe-billing-change-asks` | ask, irreversible | `stripe subscriptions create/cancel/update/delete/resume`, `subscription_items delete/update`, `customers/products/prices/plans/coupons/payment_methods/tax_rates/accounts delete/detach/reject`, `invoices void/mark_uncollectible/delete`, `payment_links create`, `stripe delete /v1/…` |
| `pay-api-money-movement-asks` | ask, irreversible | POST/DELETE (`-d`, `--data`, `-F`, `-X POST`, `-Method Post`, `requests.post(`) to payment endpoints of Stripe, PayPal (live `api-m.paypal.com`), Square (`connect.squareup.com`), Adyen live, Braintree production, Wise, Mercury, Razorpay, Mollie, GoCardless; `curl -G` reads are skipped |
| `pay-mcp-money-movement-asks` | ask, irreversible | MCP tools such as `create_refund`, `create_payout`, `create_charge`, `capture_payment_intent`, `finalize_invoice`, `pay_invoice`, `send_invoice`, `pay_order`, `capture_order`, `transfer_funds`, `accept_dispute_claim`, `refund_*`; `create_transfer` only on a payment server (stripe, paypal, wise, bank, …); not `create_payment_intent`, `create_payment_method` |
| `pay-mcp-billing-change-asks` | ask, irreversible | `create/cancel/update/pause/delete_subscription`, `create_subscription_plan`, `create_payment_link`, `void_invoice`, `cancel_sent_invoice`, camelCase forms |
| `pay-cloud-billing-change-asks` | ask | `gcloud billing projects unlink/link`, `gcloud billing budgets delete/update`, billing-account IAM changes; `aws budgets delete-budget/update-budget/…`; `az consumption budget delete/update`, `az billing … update/delete/create` |
| `pay-crypto-transfer-asks` | ask, irreversible | `cast send/publish`, `forge script/create --broadcast`, `solana transfer`, `spl-token transfer`, `bitcoin-cli sendtoaddress/sendmany/sendrawtransaction/send/sendall`, `electrum payto/broadcast`, `hardhat run/deploy --network <mainnet chain>`, `eth_sendTransaction`/`eth_sendRawTransaction` JSON-RPC; not when the RPC URL is localhost, `solana -u localhost/devnet/testnet`, or `bitcoin-cli -regtest/-testnet/-signet` |
| `pay-mcp-crypto-transfer-asks` | ask, irreversible | wallet MCP tools `send_transaction`, `send_eth`, `transfer_tokens`, `sign_and_send_transaction`, `sendRawTransaction`; bare `transfer`/`trade`/`swap` only on a wallet server (coinbase, agentkit, wallet, solana, ethereum, evm, …) |

**Test mode vs live mode.** The Stripe CLI and API use whatever key they
resolve (`stripe login`, `STRIPE_API_KEY`, `--api-key`). writ sees only
the command line, so it denies what is visibly live (`--live`,
`sk_live_`) and asks for everything else, test mode included. If your
agent only ever holds test keys, skip `pay-stripe-money-movement-asks`
and `pay-stripe-billing-change-asks`. PayPal and Square sandboxes use
different hosts (`api-m.sandbox.paypal.com`, `connect.squareupsandbox.com`)
and are not matched.

## What it deliberately does not cover

- **Creating objects that do not move money**: customers, products,
  prices, coupons, draft invoices (`create_invoice`), unconfirmed payment
  intents, PayPal `create_order`. They fall to your `default`.
- **Live-mode reads** (`stripe customers list --live`): they expose
  customer data but move no money; `secrets-guard` and `pii-redaction`
  are the places for that.
- **Keys held in variables.** `curl … -u "$STRIPE_KEY:"` against the live
  API asks instead of being denied, because writ cannot tell the mode.
- **Generic API tools on payment servers** (Square MCP's
  `make_api_request`, a raw `stripe_api` tool): the action is in an
  argument writ does not expose.
- **Other chains' CLIs and custodial exchanges** (`near send`,
  `aptos move run`, exchange APIs): add rules for the ones you use.
- **Scripts.** `node scripts/refund-all.js` is not matched by these
  regexes (only SDK calls written inline in the command are); writ's
  script inspection reads scripts the agent writes and runs.

## Tests

`fixtures/payments-guard.yaml` (45 cases): every rule, plus near misses
that must not fire (`stripe trigger`, `stripe charges retrieve`,
`stripe payment_intents create`, `stripe customers list --live`,
`curl -G` Stripe list, PayPal sandbox capture, Stripe MCP
`list_payment_intents`/`create_invoice`/`retrieve_balance`,
`create_transfer` on a file-transfer server, `gcloud billing accounts
list`, `cast send` to a local anvil node, `forge script` without
`--broadcast`, `cast call`, bare `transfer` on a non-wallet server).
