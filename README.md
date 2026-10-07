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

## DNS while connected (Pi-hole and local names)

By default Nord takes over DNS, so your Pi-hole and local names stop working while connected. Each device has a **DNS mode**:

| Mode | Internet lookups | Local names (`*.wbhomelab`) | Notes |
|---|---|---|---|
| **Nord DNS** (default) | Nord's DNS, inside the tunnel | do not resolve | most private |
| **Local names via Pi-hole** | Nord's DNS, inside the tunnel | Pi-holes | needs systemd-resolved; allowlists port 53 |
| **Pi-hole for everything** | Pi-holes (lookups leave via home) | Pi-holes | ad blocking while connected; allowlists port 53 |

Why it is not just `nordvpn set dns 192.168.1.53` (checked against the Nord Linux client 5.4.0 source and live tests):

* Nord's firewall drops port 53 to private/LAN addresses while connected, and a subnet allowlist does not lift it: only **allowlisting port 53** does.
  That also sends *all* port-53 traffic outside the tunnel (an app that talks DNS straight to `8.8.8.8` would bypass the VPN), which is why it is only done in the two Pi-hole modes.
* On **systemd-resolved** hosts, Nord applies custom DNS to its own tunnel link, so resolved sends the query *into the tunnel* where a LAN address does not exist. The agent therefore never uses `set dns` there; it steers resolved per link instead (`resolvectl domain`, `default-route`).
  Hosts without resolved (most servers and LXCs) write `/etc/resolv.conf` directly, so Nord's custom DNS works there once port 53 is allowed.
* The mode is applied after the connect, checked (DNS, internet and, if `LOCAL_CHECK` is set, a local name), reverted on failure and undone on disconnect.
  Per-device settings in `/etc/wbs-vpn-agent.env`: `LOCAL_DOMAINS` (default `wbhomelab,1.168.192.in-addr.arpa`), `LOCAL_CHECK` (a local name that must resolve, optional), `PIHOLE_DNS`.
* On resolved hosts the installer adds a polkit rule that lets the agent user change per-link DNS routing (`set-domains`, `set-default-route`, `flush-caches`) and nothing else.

Ad blocking in the Pi-hole modes is only as good as the resolver list the machine receives. If your DHCP server also hands out a non-filtering resolver (some routers add themselves as a third DNS server), the machine can still pick that one; fix it at the DHCP server, or pin the connection's DNS.

## Safety (the network must not go down)

* Before every connect the agent allowlists your LAN (`192.168.1.0/24`) and Tailscale (`100.64.0.0/10`) in the Nord client.
* After connecting it checks the panel, DNS and the internet. If any check fails within 40 s it **rolls back** (kill switch off, disconnect).
* The kill switch cannot be enabled while disconnected, and disconnecting turns it off first.
* **DNS modes** (above) are verified after they are applied and revert themselves if DNS stops working.
* Nord throttles rapid reconnects; on a "too many connection attempts / session limit" error the agent backs off for 10 minutes.
* Adding a device shows its token once; only a hash is stored. Tokens can be rotated; removing a device kills its access.

## Run the panel

```sh
cp .env.example .env          # set API_KEY (openssl rand -hex 24) and PUBLIC_URL
docker compose up -d          # panel on :3010
```

## Containers behind Gluetun (servers and Docker hosts)

Do not run the Nord client on a Proxmox host or a Docker host: while connected, Nord's firewall drops forwarded traffic (published container ports,
VM bridges), and a full tunnel is wrong for servers anyway. Put only the apps that need a VPN behind a [Gluetun](https://github.com/qdm12/gluetun)
container instead (`examples/gluetun-qbittorrent`: qBittorrent shares Gluetun's network, so it has no route except the tunnel).
The panel controls Gluetun directly through its HTTP API, no agent needed:

* **Add Gluetun** in the panel (or `POST /api/v1/devices` with `{"name","kind":"gluetun","url","api_key"}`). The URL must be a private address; it is checked at add time and on every call.
* **Connect / Switch** sets the country (`PUT /v1/vpn/settings`, no container recreate) and waits until the tunnel is up in that country; **Stop VPN** stops the tunnel, and the container then has no internet.
* Status (connected, country, exit IP) is polled every 5 s. Kill switch, Tailscale and DNS modes do not apply and are not offered.
* Nord offers no port forwarding, so incoming peer connections do not work behind it; outgoing traffic is normal.
* `devices.json` holds the Gluetun API keys, so it is mode 0600 and keys are never returned by the API.

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
| `POST /api/v1/devices/{id}/command` | `{"type":"connect","country":"Germany"}`, `disconnect`, `killswitch` / `tailscale` with `"value":"on\|off"`, `dns_mode` with `"value":"nord\|split\|pihole"` |
| `POST /api/v1/devices/{id}/token` | rotate token |
| `DELETE /api/v1/devices/{id}` | remove |

## Develop

```sh
go test ./...
docker build -t wb20244/wbs-vpn-dashboard:dev .
```
