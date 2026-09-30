# exposure-guard

Asks before an agent makes this machine, a service, or data reachable from
the internet: public tunnels, servers listening on all interfaces, database
ports published by Docker, host firewall openings, world-open cloud ingress
rules, and public storage shares. Every rule is `ask`, because a tunnel or
an open port is sometimes exactly the task; the point is that a human sees
it happen.

```yaml
version: 1
default: ask
packs: [floor, exposure-guard]
```

| Rule | Verdict | Covers |
|---|---|---|
| `expose-tunnel-asks` | ask | `ngrok http/tcp/tls/start/tunnel`, `cloudflared tunnel run`, `cloudflared tunnel --url`, `cloudflared service install`, localtunnel (`lt --port`, `npx localtunnel`), `bore local`, `zrok share public`, `devtunnel … --allow-anonymous`, `tailscale funnel <target>`; Windows `.exe` and path-qualified binaries |
| `expose-ssh-forward-asks` | ask | `ssh -R` remote forwards in any flag position or cluster (`-NR`, serveo.net, localhost.run, pinggy, `autossh -M 0 -R`), `-g`, `-o GatewayPorts=yes`, `-o RemoteForward`, and `-L`/`-D` bound to `0.0.0.0`, `*`, `::` or an empty address |
| `expose-listener-asks` | ask | `python -m http.server` / `SimpleHTTPServer` unless `--bind`/`-b` is `127.x`, `localhost` or `::1`; `php -S 0.0.0.0:…`; `nc/ncat -l` unless bound to loopback; `socat TCP-LISTEN:` unless `bind=127.…`; `http-server`/`serve` with `-a`/`--listen`/`--host 0.0.0.0`; `kubectl port-forward --address 0.0.0.0`; Jupyter with an empty token or password; `netsh interface portproxy add` unless `listenaddress=127.…` |
| `expose-docker-db-port-asks` | ask | `docker`/`podman`/`nerdctl` `run`/`create` publishing 5432, 3306, 6379, 27017, 9200, 11211, 5984 or 1433 without a loopback host address (`-p 5432:5432`, `-p 0.0.0.0:6379:6379`, `--publish=27017`, `-p 15432:5432`) |
| `expose-host-firewall-asks` | ask | `ufw allow`/`disable`, `firewall-cmd --add-port/--add-service/--add-rich-rule/--add-forward-port` (with or without `--permanent`), stopping firewalld/ufw/nftables, `iptables -A/-I INPUT … -j ACCEPT`, `-P INPUT ACCEPT`, `-F`, `nft add rule … input … accept`, `netsh advfirewall firewall add rule` (not `dir=out` or `action=block`), `New-NetFirewallRule` (not `-Action Block` or `-Direction Outbound`), `Enable-NetFirewallRule`, enabling RDP (`fDenyTSConnections` 0), `Enable-PSRemoting`, `winrm quickconfig`, `systemsetup -setremotelogin on` |
| `expose-cloud-world-open-asks` | ask | `aws ec2 authorize-security-group-ingress`/`modify-security-group-rules` and `Grant-EC2SecurityGroupIngress` with `0.0.0.0/0` or `::/0`; `--publicly-accessible` on any `aws` call; Lightsail public ports; Lambda function URLs with `--auth-type NONE`; `gcloud compute firewall-rules create/update` with a world source range, or `create` with no source at all (gcloud then defaults to `0.0.0.0/0`); `gcloud sql instances` authorized networks of `0.0.0.0/0`; `az network nsg rule create/update` with source `*`, `Internet`, `Any` or `0.0.0.0/0`, or `create` with no source (az defaults to `*`); `az vm open-port`; Azure SQL/Postgres/MySQL firewall rules ending at `255.255.255.255` or `--public-access All`; `New-AzNetworkSecurityRuleConfig -SourceAddressPrefix */Internet`; `kubectl expose --type=LoadBalancer` |
| `expose-public-share-asks` | ask, irreversible | `gsutil` with `allUsers`/`allAuthenticatedUsers`/`public-read`, `gcloud storage` with `--predefined-acl=publicRead` or `entity=allUsers`, `az storage container create/set-permission --public-access blob/container`, `az storage account create/update --allow-blob-public-access true` (and the Az PowerShell equivalents), `aws s3 cp/sync/mv` and `s3api put-object/create-bucket` with `--acl public-read` or an AllUsers grant, EBS snapshots/AMIs shared with `all`, RDS snapshots with `--values-to-add all`, `gh gist create --public`/`-p` |

## What it deliberately does not cover

- **Framework dev servers.** `vite --host`, `next dev -H 0.0.0.0`,
  `uvicorn/flask/rails --host 0.0.0.0`, `hugo/jekyll serve --bind` are
  everyday commands, and inside containers `0.0.0.0` is required. Only
  static file servers ask, because they hand out a whole directory.
  `http-server` and `serve` also bind all interfaces when given no address;
  they ask only with an explicit wildcard address, to keep front-end
  preview commands quiet.
- **Public deploys.** `gcloud run deploy --allow-unauthenticated`,
  `vercel`, `fly deploy` and friends publish a site on purpose; gating
  every deploy is a different pack's job.
- **Private-network exposure.** `tailscale serve` (tailnet only), `code
  tunnel` and dev tunnels without `--allow-anonymous` (sign-in required),
  plain `ssh -L`/`-D` bound to loopback, and binds to one LAN address.
- **Configuration files.** `ports:` in `docker-compose.yml`, Terraform
  `cidr_blocks = ["0.0.0.0/0"]`, Kubernetes Service manifests,
  `--ip-permissions file://…` JSON: the pack reads the command line only.
  Review those with `terraform-safety` / `k8s-prod` or in code review.
- **`docker run -P`** (publish all exposed ports): the image name does not
  say which ports it exposes.
- **Already covered elsewhere.** S3 bucket policy/ACL and Block Public
  Access (`aws-safety`), gcloud IAM bindings including `allUsers`
  (`gcp-azure-safety`), public repositories (`github-safety`), reverse
  shells (`floor`), switching the Windows firewall off (`windows-safety`).

## Tests

`fixtures/exposure-guard.yaml`: every rule, with flags in different orders
and Windows `.exe` forms, plus near misses that must not fire
(`ngrok config add-authtoken`, `ngrok version`, `tailscale funnel status`,
`ssh -L 127.0.0.1:…`, `http.server --bind 127.0.0.1`,
`docker run -p 127.0.0.1:5432:5432`, `docker run -p 8080:80`,
`npx vite --host 0.0.0.0`, `ufw status`, the Azure-services-only SQL
firewall rule, a secret gist).
