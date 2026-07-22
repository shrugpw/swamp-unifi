# @shrug/unifi-networks

Query UniFi Network sites through Ubiquiti's **official integration API** and
map the pieces together: VLANs, firewall zones/policies, connected clients, and
WiFi SSIDs — with reports that render a firewall summary and a zone posture
matrix.

> **Vendored fork.** This is a fork of [`@dmc/unifi-networks`](https://swamp-club.com/extensions/@dmc/unifi-networks)
> by Dan McClain (MIT — see `LICENSE.txt`), maintained in-tree for the shrug
> fleet. Changes from upstream `2026.07.07.1`:
> - **Policy `name` is optional** — the UDM allows nameless firewall rules; the
>   upstream schema required `name`, so a single nameless rule failed validation
>   of the whole `siteFirewall` resource and silently skipped both reports.
>   Nameless policies now map to `(unnamed)`.
> - **`PRESET` protocol rendering fixed** — `ipProtocolScope.protocolFilter` of
>   type `PRESET` carries an object (`{name: "TCP_UDP"}`); upstream stringified
>   it to `[object Object]`. Now renders the preset name (e.g. `tcp_udp`).

## Modes

| Mode    | Key source                                        | Reaches                                    |
| ------- | ------------------------------------------------- | ------------------------------------------ |
| `local` | Console → Settings → Control Plane → Integrations | `https://<host>/proxy/network/integration` |
| `cloud` | [unifi.ui.com](https://unifi.ui.com) → API Keys   | Ubiquiti cloud proxy (`api.ui.com`)        |

- **local** requires `host`; set `verifyTls: false` for a factory UDM's
  self-signed certificate (those calls route through `curl`). If your console
  presents a valid cert (e.g. via a hostname with real DNS + a public CA cert),
  leave `verifyTls: true` and everything runs over native `fetch`/`WebSocket`.
- **cloud** discovers consoles automatically; pin one with `consoleId`.
- `scanUpdates` additionally requires `username`/`password` — the UniFi OS
  local admin account (not the Integration API key), since update status is
  only exposed via the management-plane websocket. If that account has MFA
  enabled, also set `totpSecret` (the account's base32 TOTP seed) — MFA
  accounts reject password-only logins with `MFA_AUTH_REQUIRED`, and the
  extension derives the current code in-process at login. Local-only admin
  accounts bypass SSO MFA and can omit it.

## Methods

| Method         | What it does                                                |
| -------------- | ---------------------------------------------------------- |
| `scan`         | Networks/VLANs per site                                     |
| `scanFirewall` | Firewall zones + policies, joined to zone names             |
| `scanClients`  | Connected clients, mapped to VLAN by IPv4-subnet match      |
| `scanWifi`     | WiFi SSIDs, mapped to VLAN via their network reference      |
| `scanUpdates`  | UDM OS + app update status via the management-plane websocket (local mode, requires `username`/`password`) |
| `consoles`     | List consoles visible to a cloud key (cloud mode)           |
| `deletePolicy` | Delete one USER_DEFINED firewall policy (verifies first)    |

## Reports

Both run automatically after `scanFirewall`:

- **`@shrug/unifi-firewall-summary`** — zone inventory + user-defined policy
  table, with an "Attention" section flagging temporary-looking or unrestricted
  rules.
- **`@shrug/unifi-zone-matrix`** — source→destination posture grid from the
  catch-all defaults, marking pairs a higher-priority rule overrides.

## Known limitations (upstream, not yet fixed here)

- `scanClients` maps clients to VLANs by **IPv4** subnet only; IPv6-only clients
  fall into `unmappedCount`.

## Install & Usage

Pull the extension into your swamp workspace:

```bash
swamp extension pull @shrug/unifi-networks
```

Create a model instance, passing `globalArguments` as repeatable `--global-arg
key=value` flags:

```bash
swamp model create @shrug/unifi-networks my-unifi \
  --global-arg mode=local \
  --global-arg host=192.0.2.1 \
  --global-arg 'apiKey=${{ vault.get("unifi", "integration-key") }}' \
  --global-arg verifyTls=true
```

For `scanUpdates`, also pass the UniFi OS local admin credentials:

```bash
  --global-arg 'username=${{ vault.get("udm", "username") }}' \
  --global-arg 'password=${{ vault.get("udm", "password") }}'
```

If that admin account has MFA enabled, also pass its base32 TOTP seed:

```bash
  --global-arg 'totpSecret=${{ vault.get("udm", "totp-secret") }}'
```

Run methods against the instance:

```bash
swamp model method run my-unifi scan          # networks/VLANs
swamp model method run my-unifi scanFirewall  # firewall zones+policies, renders both reports
swamp model method run my-unifi scanClients   # connected clients → VLAN
swamp model method run my-unifi scanWifi      # SSIDs → VLAN
swamp model method run my-unifi scanUpdates   # UDM OS + app update status
```

Read results back through the data model rather than re-running a method:

```bash
swamp data get my-unifi <resource-instance-name>
```

or from a workflow via CEL, e.g.
`data.latest("my-unifi", "consoleUpdates").attributes.os.updateAvailable`.
