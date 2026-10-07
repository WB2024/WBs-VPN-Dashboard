package main

// installTemplate is served at /install.sh. Run as: curl -fsSL <panel>/install.sh | sudo TOKEN=<token> sh
// It never touches the Nord login; it only installs the agent binary and a service that runs it.
const installTemplate = `#!/bin/sh
set -eu
PANEL="@PANEL@"
[ -n "${TOKEN:-}" ] || { echo "TOKEN is required (copy the full command from the panel)"; exit 1; }
[ "$(id -u)" = 0 ] || { echo "run as root (use sudo)"; exit 1; }
case "$(uname -m)" in
  x86_64|amd64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) echo "unsupported architecture $(uname -m)"; exit 1 ;;
esac
echo "==> downloading agent ($ARCH)"
curl -fsSL "$PANEL/dl/wbs-vpn-agent-linux-$ARCH" -o /usr/local/bin/wbs-vpn-agent.new
chmod 755 /usr/local/bin/wbs-vpn-agent.new
mv /usr/local/bin/wbs-vpn-agent.new /usr/local/bin/wbs-vpn-agent
umask 077
cat > /etc/wbs-vpn-agent.env <<EOF2
PANEL_URL=$PANEL
TOKEN=$TOKEN
EOF2
umask 022
command -v nordvpn >/dev/null 2>&1 || echo "NOTE: the nordvpn CLI is not installed on this machine; the agent will report that until it is."
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
  id wbs-vpn >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin wbs-vpn
  getent group nordvpn >/dev/null 2>&1 && usermod -aG nordvpn wbs-vpn
  chown root:wbs-vpn /etc/wbs-vpn-agent.env && chmod 640 /etc/wbs-vpn-agent.env
  cat > /etc/systemd/system/wbs-vpn-agent.service <<EOF2
[Unit]
Description=WB's VPN Dashboard agent
After=network-online.target nordvpnd.service
Wants=network-online.target

[Service]
User=wbs-vpn
StateDirectory=wbs-vpn
Environment=HOME=/var/lib/wbs-vpn
EnvironmentFile=/etc/wbs-vpn-agent.env
ExecStart=/usr/local/bin/wbs-vpn-agent
Restart=always
RestartSec=5
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF2
  if command -v resolvectl >/dev/null 2>&1 && [ -d /etc/polkit-1/rules.d ]; then
    # lets the agent adjust per-link DNS routing in systemd-resolved (nothing else), used by the DNS modes
    cat > /etc/polkit-1/rules.d/50-wbs-vpn-agent.rules <<'EOF2'
polkit.addRule(function(action, subject) {
  if (subject.user == "wbs-vpn" &&
      (action.id == "org.freedesktop.resolve1.set-domains" ||
       action.id == "org.freedesktop.resolve1.set-default-route" ||
       action.id == "org.freedesktop.resolve1.flush-caches")) {
    return polkit.Result.YES;
  }
});
EOF2
  fi
  systemctl daemon-reload
  systemctl enable wbs-vpn-agent >/dev/null 2>&1
  systemctl restart wbs-vpn-agent
  echo "==> agent installed and running (systemctl status wbs-vpn-agent)"
else
  echo "==> no systemd here: run it yourself with: set -a; . /etc/wbs-vpn-agent.env; set +a; /usr/local/bin/wbs-vpn-agent"
fi
`
