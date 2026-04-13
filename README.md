# Switch VLAN Monitor

Real-time switch port, VLAN, MAC address, and IP monitoring web application for office network switches.

![Python](https://img.shields.io/badge/Python-3.12-blue) ![Flask](https://img.shields.io/badge/Flask-3.1-green) ![Docker](https://img.shields.io/badge/Docker-ready-blue)

## Features

- **Live Port Monitoring** -- 52-port grid showing UP/DOWN status, speed, and duplex per port
- **VLAN Map** -- Color-coded VLAN assignments with 30+ distinct colors for visual identification
- **MAC Address Table** -- Lists all MAC addresses learned on each port
- **IP Resolution** -- Resolves MAC addresses to IP and hostname via Windows DHCP Server (pypsrp), SonicWall DHCP API, and local ARP table
- **TX/RX Traffic Counters** -- Per-port traffic statistics in GB/MB/KB
- **SQLite Persistence** -- Switch configurations and scan results survive restarts
- **Multi-Switch** -- Monitor multiple switches simultaneously from one dashboard
- **Multi-Vendor** -- Supports Edge-Core ECS, HP/H3C Comware, and Cisco IOS
- **Auto-Detection** -- Identifies switch vendor from telnet banner automatically

## Supported Switches

| Vendor | Models | Protocol |
|--------|--------|----------|
| Edge-Core | ECS4510, ECS4620 series | Telnet (raw socket) |
| HP / H3C | A5800, Comware series | Telnet (raw socket) |
| Cisco | Catalyst 2960, 3750 series | Telnet (raw socket) |

## Quick Start

### Docker (Recommended)

```bash
docker build -t switch-monitor .
docker run -d --name switch-monitor --restart unless-stopped \
  -p 5050:5050 \
  -e DHCP_SERVER=10.10.11.245 \
  -e DHCP_USER=administrator \
  -e DHCP_PASS=your_password \
  -e SONICWALL_IP=172.20.10.254 \
  -e SONICWALL_USER=admin \
  -e SONICWALL_PASS=your_password \
  switch-monitor
```

Open `http://localhost:5050` in your browser.

### Manual

```bash
pip install -r requirements.txt
python app.py
```

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DHCP_SERVER` | `10.10.11.245` | Windows DHCP Server IP |
| `DHCP_USER` | `administrator` | DHCP Server username |
| `DHCP_PASS` | *(empty)* | DHCP Server password |
| `SONICWALL_IP` | `172.20.10.254` | SonicWall firewall IP |
| `SONICWALL_USER` | `admin` | SonicWall username |
| `SONICWALL_PASS` | *(empty)* | SonicWall password |

### IP Resolution Sources

The application resolves MAC addresses to IP/hostname using three sources (in priority order):

1. **Windows DHCP Server** -- PowerShell remoting via `pypsrp` to query `Get-DhcpServerv4Lease`
2. **SonicWall DHCP** -- REST API at `https://<ip>:444/api/sonicos/reporting/dhcp-server/ipv4/leases`
3. **Local ARP** -- Host machine ARP table via `arp -a`

## API

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Web UI |
| `/api/scan` | POST | Scan a switch -- `{"ip", "username", "password", "model"}` |
| `/api/switches` | GET | List all saved switches |
| `/api/switches/<ip>` | DELETE | Remove a switch |
| `/api/arp` | GET | Local ARP table |

### Scan Request Example

```bash
curl -X POST http://localhost:5050/api/scan \
  -H "Content-Type: application/json" \
  -d '{"ip": "10.10.10.198", "username": "admin", "password": "secret", "model": "edgecore"}'
```

Model values: `edgecore`, `hp_comware`, `cisco`, or empty for auto-detection.

### Scan Response

```json
{
  "hostname": "SW-FINANCE",
  "model": "Edge-Core ECS4620-28F",
  "vlans": {"1": "default", "49": "FINANCE", "39": "ALIEN"},
  "ports": [
    {
      "num": 1, "name": "Eth1/1", "status": "active",
      "vlan": "49", "mode": "access", "speed": "1000",
      "tx_bytes": 475891234567, "rx_bytes": 118534567890,
      "macs": [{"mac": "E8-FF-1E-AA-BB-CC", "ip": "10.10.49.54", "hostname": "PC-FIN01"}]
    }
  ]
}
```

## Project Structure

```
switch_monitor/
  app.py              # Flask backend + telnet parsers (EdgeCore, HP, Cisco)
  requirements.txt    # Python dependencies
  Dockerfile          # Docker build
  .dockerignore
  .gitignore
  switches.db         # SQLite database (auto-created)
  templates/
    index.html        # Single-page frontend (no external dependencies)
```

## License

MIT
