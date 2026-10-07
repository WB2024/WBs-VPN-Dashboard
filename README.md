# WB's VPN Dashboard

Control the NordVPN client on each of your Linux machines from one place: connect, switch country, disconnect, kill switch,
Pi-hole DNS and Tailscale, per device, from a browser (or from inside [Glance](https://github.com/glanceapp/glance)).

```
Glance / browser ──► panel (Docker)  ◄── long-poll ──  agent on each device ──► nordvpn / tailscale CLI
                       JSON API + tiny web page            (one static Go binary)
```

* **panel** (`cmd/panel`): keeps the device list, queues commands, serves the API and a fallback web page. Stdlib only, state in one JSON file.
* **agent** (`cmd/agent`): runs on each device, reports status, executes a *fixed* set of commands. It cannot run arbitrary shell commands.
* Agents connect **out** to the panel, so adding a device needs no inbound ports and works through Tailscale too.

## Safety (the network must not go down)

* Before every connect the agent allowlists your LAN (`192.168.1.0/24`) and Tailscale (`100.64.0.0/10`) in the Nord client.
* After connecting it checks the panel, DNS and the internet. If any check fails within 40 s it **rolls back** (kill switch off, disconnect).
* The kill switch cannot be enabled while disconnected, and disconnecting turns it off first.
* **Pi-hole DNS while connected** is a per-device toggle. Nord's firewall otherwise drops port 53 to the LAN; the toggle sets the Pi-holes as DNS, allowlists port 53, and reverts itself if DNS stops working.
* Nord throttles rapid reconnects; on a "too many connection attempts / session limit" error the agent backs off for 10 minutes.
* Adding a device shows its token once; only a hash is stored. Tokens can be rotated; removing a device kills its access.

## Run the panel

```sh
cp .env.example .env          # set API_KEY (openssl rand -hex 24) and PUBLIC_URL
docker compose up -d          # panel on :3010
```

## Add a device

In the panel click **Add device**, then run the one-line command it shows on that machine:

```sh
curl -fsSL http://<panel>/install.sh | sudo TOKEN=<token> sh
```

It installs `/usr/local/bin/wbs-vpn-agent` and a systemd service running as an unprivileged `wbs-vpn` user in the `nordvpn` group.
Install the Nord CLI and log in once per device first (`nordvpn login --token <token>`). Per-device settings go in `/etc/wbs-vpn-agent.env`:
`ALLOW_SUBNETS` (default `192.168.1.0/24,100.64.0.0/10`) and `PIHOLE_DNS` (default `192.168.1.53,192.168.1.54`).

## API (all need `X-API-Key`)

| | |
|---|---|
| `GET /api/v1/devices` | devices with status, queued/in-flight commands, last results, country list |
| `POST /api/v1/devices` `{"name"}` | add; returns the one-time token and install command |
| `POST /api/v1/devices/{id}/command` | `{"type":"connect","country":"Germany"}`, `disconnect`, `killswitch` / `pihole_dns` / `tailscale` with `"value":"on\|off"` |
| `POST /api/v1/devices/{id}/token` | rotate token |
| `DELETE /api/v1/devices/{id}` | remove |

## Develop

```sh
go test ./...
docker build -t wb20244/wbs-vpn-dashboard:dev .
```
