# CLAUDE.md -- Switch VLAN Monitor

## Project Overview

Flask web application that monitors office network switches in real-time via Telnet. Displays a 52-port grid with VLAN color coding, MAC addresses, and resolved IP/hostnames.

## Architecture

- **Single-file backend** (`app.py`) -- Flask app with telnet connection logic, switch parsers, and IP resolution
- **Single-file frontend** (`templates/index.html`) -- Self-contained HTML/CSS/JS, no build tools or external CDN dependencies
- **SQLite** (`switches.db`) -- Stores switch credentials, scan results, and metadata; auto-created on first run
- **Port**: 5050

## Key Design Decisions

- **Raw socket telnet** instead of `telnetlib` (deprecated in Python 3.11+). The `SwitchConnection` class handles IAC negotiation, login, paging ("More" prompts), and command execution manually.
- **Synchronous scanning** -- each scan opens a new TCP connection, runs commands sequentially, then closes. Counter fetching is a separate connection to avoid timeout issues on Edge-Core.
- **Three IP resolution sources** chained: Windows DHCP (pypsrp PowerShell remoting), SonicWall REST API, local ARP. DHCP results take priority over ARP.
- **No authentication on the web UI** -- intended for internal network use only.

## Switch Parsers

Each vendor has its own class inheriting from `SwitchConnection`:

- `EdgeCoreSwitch` -- Parses `show vlan`, `show interfaces switchport`, `show interfaces status`, `show mac-address-table`. Also fetches per-port `show interfaces counters` in a second telnet session.
- `HPComwareSwitch` -- Parses `display vlan brief`, `display interface brief`, `display version`. Does not fetch MAC table or counters currently.
- `CiscoSwitch` -- Parses `show vlan brief`, `show interfaces status`, `show version`. Uses `enable` command for privilege escalation.

## Code Map

- `app.py:SwitchConnection` -- Base class with `telnet_exec()` raw socket implementation
- `app.py:EdgeCoreSwitch` -- Edge-Core ECS parser (~180 lines)
- `app.py:HPComwareSwitch` -- HP Comware parser (~80 lines)
- `app.py:CiscoSwitch` -- Cisco IOS parser (~60 lines)
- `app.py:get_dhcp_leases()` -- Windows DHCP + SonicWall DHCP resolution
- `app.py:get_local_arp()` -- Local ARP table parser
- `app.py:detect_switch_type()` -- Auto-detection from telnet banner

## Environment Variables

Set `DHCP_PASS` and `SONICWALL_PASS` for IP resolution to work. Without them, MAC addresses are shown without IP/hostname.

## Known Limitations

- HP Comware parser does not fetch MAC address table or traffic counters
- Cisco parser does not fetch traffic counters
- Telnet timeouts are hardcoded (15s connection, 3-5s per command read)
- No concurrent scanning -- each switch is scanned sequentially
- SonicWall DHCP uses `requests` library (separate from the dashboard project which uses `httpx`)
- Edge-Core counter fetching opens a second telnet session which may fail if the switch limits concurrent sessions

## Testing

Test files (`test_counters.py`, `test_edgecore.py`, etc.) are manual telnet tests, not automated unit tests.

## Build and Run

```bash
docker build -t switch-monitor .
docker run -p 5050:5050 -e DHCP_PASS=xxx -e SONICWALL_PASS=xxx switch-monitor
```
