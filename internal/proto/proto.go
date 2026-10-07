// Package proto holds the wire types shared by the panel and the device agent.
package proto

// Command types the agent is allowed to execute. Anything else is rejected by both ends.
const (
	CmdConnect    = "connect"    // Value unused, Country required
	CmdDisconnect = "disconnect" //
	CmdKillSwitch = "killswitch" // Value: on|off
	CmdPiholeDNS  = "pihole_dns" // Value: on|off  (Nord uses the Pi-holes while connected)
	CmdTailscale  = "tailscale"  // Value: on|off
)

// Status is what an agent reports about its device on every poll.
type Status struct {
	NordInstalled bool   `json:"nord_installed"`
	Connected     bool   `json:"connected"`
	Country       string `json:"country,omitempty"`
	City          string `json:"city,omitempty"`
	Server        string `json:"server,omitempty"`
	IP            string `json:"ip,omitempty"`
	Technology    string `json:"technology,omitempty"`
	KillSwitch    bool   `json:"kill_switch"`
	PiholeDNS     bool   `json:"pihole_dns"`
	Tailscale     string `json:"tailscale"` // up | down | absent
	Version       string `json:"version,omitempty"`
	Hostname      string `json:"hostname,omitempty"`
	AgentVersion  string `json:"agent_version,omitempty"`
	Error         string `json:"error,omitempty"`
}

// Command is one queued instruction for a device.
type Command struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Country string `json:"country,omitempty"`
	Value   string `json:"value,omitempty"`
	Created int64  `json:"created"`
}

// Result is the outcome of a command, reported on the agent's next poll.
type Result struct {
	CommandID string `json:"command_id"`
	Type      string `json:"type"`
	OK        bool   `json:"ok"`
	Message   string `json:"message"`
	At        int64  `json:"at"`
}

// PollRequest is POSTed by the agent. LastResult is nil unless a command just finished.
type PollRequest struct {
	Status     Status  `json:"status"`
	LastResult *Result `json:"last_result,omitempty"`
}

// PollResponse carries at most one command.
type PollResponse struct {
	Command *Command `json:"command,omitempty"`
}
