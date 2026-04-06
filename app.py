from flask import Flask, render_template, jsonify, request
from flask_cors import CORS
import asyncio
import re
import json
import sqlite3
import os
import subprocess
import socket

app = Flask(__name__)
CORS(app)

DB_PATH = os.path.join(os.path.dirname(__file__), 'switches.db')


# ─── SQLite ──────────────────────────────────────────────────────────

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS switches (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT UNIQUE NOT NULL,
        username TEXT,
        password TEXT,
        model TEXT,
        hostname TEXT,
        last_scan TEXT,
        data TEXT
    )''')
    conn.commit()
    conn.close()

def save_switch(ip, username, password, model, hostname, data):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''INSERT OR REPLACE INTO switches (ip, username, password, model, hostname, last_scan, data)
                 VALUES (?, ?, ?, ?, ?, datetime('now'), ?)''',
              (ip, username, password, model, hostname, json.dumps(data, default=str)))
    conn.commit()
    conn.close()

def load_switches():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT ip, username, password, model, hostname, last_scan, data FROM switches ORDER BY ip')
    rows = c.fetchall()
    conn.close()
    return [{"ip": r[0], "username": r[1], "password": r[2], "model": r[3],
             "hostname": r[4], "last_scan": r[5], "data": json.loads(r[6]) if r[6] else {}} for r in rows]

def delete_switch_db(ip):
    conn = sqlite3.connect(DB_PATH)
    conn.execute('DELETE FROM switches WHERE ip = ?', (ip,))
    conn.commit()
    conn.close()

init_db()


# ─── Telnet Base ─────────────────────────────────────────────────────

class SwitchConnection:
    def __init__(self, ip, username, password, port=23):
        self.ip = ip
        self.username = username
        self.password = password
        self.port = port
        self.commands_output = {}

    def telnet_exec(self, commands, enable_cmd=None, more_pattern="---- More ----"):
        """Raw socket telnet with IAC negotiation handling"""
        import time

        IAC = 255; DONT = 254; DO = 253; WONT = 252; WILL = 251; SB = 250; SE = 240

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(15)
        sock.connect((self.ip, self.port))
        time.sleep(1)

        def strip_telnet_negotiation(data):
            """Remove telnet IAC sequences and auto-respond"""
            clean = b""
            i = 0
            while i < len(data):
                if data[i] == IAC and i + 2 < len(data):
                    cmd = data[i + 1]
                    opt = data[i + 2]
                    if cmd == DO:
                        sock.sendall(bytes([IAC, WONT, opt]))
                    elif cmd == WILL:
                        sock.sendall(bytes([IAC, DONT, opt]))
                    i += 3
                elif data[i] == IAC and i + 1 < len(data) and data[i + 1] == SB:
                    # Skip subnegotiation
                    end = data.find(bytes([IAC, SE]), i)
                    i = end + 2 if end != -1 else len(data)
                else:
                    clean += bytes([data[i]])
                    i += 1
            return clean

        def recv_all(timeout=3):
            sock.settimeout(timeout)
            data = b""
            while True:
                try:
                    chunk = sock.recv(65535)
                    if not chunk:
                        break
                    data += strip_telnet_negotiation(chunk)
                except socket.timeout:
                    break
                except Exception:
                    break
            sock.settimeout(15)
            return data.decode('utf-8', errors='ignore')

        def send(text):
            sock.sendall(text.encode('utf-8'))

        # Read banner and login
        banner = recv_all(5)

        # Send username
        send(self.username + "\r\n")
        time.sleep(1)
        recv_all(2)

        # Send password
        send(self.password + "\r\n")
        time.sleep(2)
        recv_all(3)

        # Enable mode
        if enable_cmd:
            send(enable_cmd + "\r\n")
            time.sleep(1)
            out = recv_all(2)
            if "assword" in out:
                send(self.password + "\r\n")
                time.sleep(1)
                recv_all(2)

        # Disable paging
        for cmd in ["terminal length 0", "screen-length disable", "terminal pager 0"]:
            send(cmd + "\r\n")
            time.sleep(1)
            recv_all(2)

        # Execute commands
        results = {}
        for cmd in commands:
            send(cmd + "\r\n")
            # Longer wait for heavy commands
            wait = 5 if "counters" in cmd or "mac-address" in cmd else 2
            time.sleep(wait)

            output = ""
            for _ in range(200):
                chunk = recv_all(4)
                if not chunk:
                    break
                output += chunk
                if more_pattern.lower() in chunk.lower() or "-- more --" in chunk.lower():
                    send(" ")
                    time.sleep(0.5)
                elif "#" in chunk[-30:] or ">" in chunk[-30:]:
                    break

            results[cmd] = output

        try:
            send("quit\r\n")
            sock.close()
        except Exception:
            pass
        return results


# ─── Edge-Core ECS Parser ───────────────────────────────────────────

class EdgeCoreSwitch(SwitchConnection):
    def get_commands(self):
        return [
            "show vlan",
            "show interfaces switchport",
            "show interfaces status",
            "show mac-address-table",
        ]

    def scan(self):
        self.commands_output = self.telnet_exec(
            self.get_commands(), more_pattern="--More--")
        result = self.parse()
        # Fetch counters for active ports via separate connection
        try:
            active_ports = [p for p in result["ports"] if p["status"] == "active"]
            if active_ports:
                counter_cmds = [f"show interfaces counters ethernet {p['name'].replace('Eth','').replace('/','/').strip()}"
                                for p in active_ports]
                counter_output = self.telnet_exec(counter_cmds, more_pattern="--More--")
                for p in active_ports:
                    cmd_key = f"show interfaces counters ethernet {p['name'].replace('Eth','').strip()}"
                    raw = counter_output.get(cmd_key, "")
                    # Clean
                    raw = re.sub(r'\x1b\[[0-9;]*[A-Za-z]', '', raw).replace('\r', '')
                    tx = rx = tx_pkts = rx_pkts = 0
                    for line in raw.split('\n'):
                        line = line.strip()
                        # Only match "NNN Octets Input" NOT "NNN Octets Input in kbits"
                        if rx == 0:
                            m = re.match(r'(\d+)\s+Octets\s+Input\s*$', line)
                            if m: rx = int(m.group(1))
                        if tx == 0:
                            m = re.match(r'(\d+)\s+Octets\s+Output\s*$', line)
                            if m: tx = int(m.group(1))
                        if rx_pkts == 0:
                            m = re.match(r'(\d+)\s+Unicast\s+Input\s*$', line)
                            if m: rx_pkts = int(m.group(1))
                        if tx_pkts == 0:
                            m = re.match(r'(\d+)\s+Unicast\s+Output\s*$', line)
                            if m: tx_pkts = int(m.group(1))
                    p["tx_bytes"] = tx
                    p["rx_bytes"] = rx
                    p["tx_packets"] = tx_pkts
                    p["rx_packets"] = rx_pkts
        except Exception as e:
            print(f"Counter fetch error: {e}")
        return result

    def parse(self):
        vlans = self._parse_vlans()
        switchport_map = self._parse_switchport()
        mac_map = self._parse_mac_table()
        ports = self._parse_ports(vlans, switchport_map)

        for p in ports:
            pn = p["name"]
            p["tx_bytes"] = 0
            p["rx_bytes"] = 0
            p["tx_packets"] = 0
            p["rx_packets"] = 0
            p["macs"] = mac_map.get(pn, [])

        return {
            "hostname": self._parse_hostname(),
            "model": self._parse_model(),
            "uptime": "N/A",
            "vlans": vlans,
            "ports": ports,
            "logs": [
                {"type": "info", "msg": f"Telnet baglantisi kuruldu: {self.ip}"},
                {"type": "ok", "msg": f"{len(vlans)} VLAN, {len(ports)} port, {sum(len(v) for v in mac_map.values())} MAC"},
            ]
        }

    def _parse_hostname(self):
        for output in self.commands_output.values():
            m = re.search(r'(\S+)#', output)
            if m and m.group(1) not in ['show', 'display']:
                return m.group(1)
        return self.ip

    def _parse_model(self):
        for output in self.commands_output.values():
            if "ECS" in output:
                m = re.search(r'(ECS\S+)', output)
                if m:
                    return f"Edge-Core {m.group(1)}"
        return "Edge-Core Switch"

    def _parse_vlans(self):
        vlans = {}
        vlan_out = self.commands_output.get("show vlan", "")
        current_vlan = None
        for line in vlan_out.split('\n'):
            line = line.strip()
            m = re.match(r'VLAN\s+ID\s*:\s*(\d+)', line)
            if m:
                current_vlan = m.group(1)
                continue
            m = re.match(r'Name\s*:\s*(.+)', line)
            if m and current_vlan:
                vlans[current_vlan] = m.group(1).strip()
                current_vlan = None
        return vlans or {"1": "default"}

    def _parse_switchport(self):
        sw_map = {}
        sp_out = self.commands_output.get("show interfaces switchport", "")
        blocks = re.split(r'Information of (Eth\s*\S+)', sp_out)
        for i in range(1, len(blocks), 2):
            port_name = blocks[i].strip().replace(" ", "")
            block = blocks[i + 1] if i + 1 < len(blocks) else ""
            mode = "access"
            native_vlan = "1"
            for line in block.split('\n'):
                line = line.strip()
                m = re.match(r'VLAN Membership Mode\s*:\s*(\S+)', line)
                if m:
                    mode = m.group(1).lower()
                m = re.match(r'Native VLAN\s*:\s*(\d+)', line)
                if m:
                    native_vlan = m.group(1)
            is_trunk = mode in ("trunk", "hybrid")
            sw_map[port_name] = {"mode": "trunk" if is_trunk else "access", "vlan": native_vlan}
        return sw_map

    def _parse_ports(self, vlans, switchport_map):
        ports = []
        intf_out = self.commands_output.get("show interfaces status", "")
        blocks = re.split(r'Information of (Eth\s*\S+)', intf_out)
        port_num = 0
        for i in range(1, len(blocks), 2):
            port_name = blocks[i].strip().replace(" ", "")
            block = blocks[i + 1] if i + 1 < len(blocks) else ""
            port_num += 1
            desc = ""
            link_status = "Down"
            speed_duplex = ""
            port_type = "copper"

            for line in block.split('\n'):
                line = line.strip()
                m = re.match(r'Name\s*:\s*(.+)', line)
                if m:
                    desc = m.group(1).strip()
                m = re.match(r'Link Status\s*:\s*(\S+)', line)
                if m:
                    link_status = m.group(1)
                m = re.match(r'Operation Speed-duplex\s*:\s*(\S+)', line)
                if m:
                    speed_duplex = m.group(1)
                m = re.match(r'Port Type\s*:\s*(.+)', line)
                if m:
                    pt = m.group(1).lower()
                    if "sfp" in pt or "10g" in pt:
                        port_type = "sfp"

            is_active = link_status.upper() == "UP"
            speed, duplex = "", "auto"
            if speed_duplex:
                sm = re.match(r'(\d+)(full|half)?', speed_duplex, re.IGNORECASE)
                if sm:
                    speed = sm.group(1)
                    duplex = (sm.group(2) or "full").lower()

            sp = switchport_map.get(port_name, {})
            vlan = sp.get("vlan", "1")
            mode = sp.get("mode", "access")

            ports.append({
                "num": port_num, "name": port_name, "desc": desc,
                "status": "active" if is_active else "inactive",
                "duplex": duplex if is_active else "auto",
                "speed": speed if is_active else "",
                "vlan": vlan, "mode": mode, "type": port_type,
            })
        return ports

    def _parse_mac_table(self):
        mac_map = {}
        mac_out = self.commands_output.get("show mac-address-table", "")
        for line in mac_out.split('\n'):
            m = re.match(
                r'\s*Eth\s+(\d+/\s*\d+)\s+'
                r'([0-9A-Fa-f]{2}-[0-9A-Fa-f]{2}-[0-9A-Fa-f]{2}-[0-9A-Fa-f]{2}-[0-9A-Fa-f]{2}-[0-9A-Fa-f]{2})\s+'
                r'(\d+)\s+(\S+)', line)
            if m:
                port_name = f"Eth{m.group(1).replace(' ', '')}"
                mac_map.setdefault(port_name, []).append({
                    "mac": m.group(2), "vlan": m.group(3), "type": m.group(4)})
        return mac_map


# ─── HP Comware Parser ──────────────────────────────────────────────

class HPComwareSwitch(SwitchConnection):
    def get_commands(self):
        return ["display vlan brief", "display interface brief", "display version"]

    def scan(self):
        self.commands_output = self.telnet_exec(
            self.get_commands(), more_pattern="---- More ----")
        return self.parse()

    def parse(self):
        vlans = self._parse_vlans()
        ports = self._parse_ports()
        return {
            "hostname": self._parse_hostname(),
            "model": self._parse_model(),
            "uptime": self._parse_uptime(),
            "vlans": vlans, "ports": ports,
            "logs": [
                {"type": "info", "msg": f"Telnet baglantisi kuruldu: {self.ip}"},
                {"type": "ok", "msg": f"{len(vlans)} VLAN, {len(ports)} port"},
            ]
        }

    def _parse_hostname(self):
        for output in self.commands_output.values():
            m = re.search(r'<([^>]+)>', output)
            if m: return m.group(1)
        return self.ip

    def _parse_model(self):
        v = self.commands_output.get("display version", "")
        m = re.search(r'(HP|H3C|HPE)\s+([^\r\n]+)', v)
        return m.group(0).strip() if m else "HP Comware Switch"

    def _parse_uptime(self):
        v = self.commands_output.get("display version", "")
        m = re.search(r'uptime is\s+([^\r\n]+)', v, re.IGNORECASE)
        return m.group(1).strip() if m else "N/A"

    def _parse_vlans(self):
        vlans = {}
        out = self.commands_output.get("display vlan brief", "")
        current_vlan = None
        for line in out.split('\n'):
            line = line.strip()
            m = re.match(r'VLAN\s+ID\s*:\s*(\d+)', line)
            if m:
                current_vlan = m.group(1)
            m = re.match(r'Name\s*:\s*(.+)', line)
            if m and current_vlan:
                vlans[current_vlan] = m.group(1).strip()
                current_vlan = None
            # Also try tabular: "1    default_vlan  ..."
            m = re.match(r'^(\d+)\s+(\S+)\s', line)
            if m and m.group(1).isdigit() and 1 <= int(m.group(1)) <= 4094:
                vlans[m.group(1)] = m.group(2)
        return vlans or {"1": "Default"}

    def _parse_ports(self):
        ports = []
        out = self.commands_output.get("display interface brief", "")
        port_num = 0
        for line in out.split('\n'):
            m = re.match(r'^(GE|XGE|FE|GigabitEthernet|Ten-GigabitEthernet)(\S+)\s+(UP|DOWN|ADM)\s+(\S+)', line, re.IGNORECASE)
            if m:
                port_num += 1
                prefix, port_id, link = m.group(1), m.group(2), m.group(3).upper()
                speed = "10000" if prefix.upper() in ["XGE", "TEN-GIGABITETHERNET"] else "1000"
                ptype = "sfp" if prefix.upper() in ["XGE", "TEN-GIGABITETHERNET"] else "copper"
                ports.append({
                    "num": port_num, "name": f"{prefix}{port_id}", "desc": "",
                    "status": "active" if link == "UP" else "inactive",
                    "duplex": "full" if link == "UP" else "auto",
                    "speed": speed if link == "UP" else "",
                    "vlan": "1", "mode": "access", "type": ptype,
                    "tx_bytes": 0, "rx_bytes": 0, "tx_packets": 0, "rx_packets": 0, "macs": [],
                })
        return ports


# ─── Cisco Parser ───────────────────────────────────────────────────

class CiscoSwitch(SwitchConnection):
    def get_commands(self):
        return ["show vlan brief", "show interfaces status", "show version"]

    def scan(self):
        self.commands_output = self.telnet_exec(
            self.get_commands(), enable_cmd="enable", more_pattern="--More--")
        return self.parse()

    def parse(self):
        vlans = self._parse_vlans()
        ports = self._parse_ports()
        return {
            "hostname": self._parse_hostname(),
            "model": self._parse_model(),
            "uptime": "N/A",
            "vlans": vlans, "ports": ports,
            "logs": [
                {"type": "info", "msg": f"Telnet baglantisi kuruldu: {self.ip}"},
                {"type": "ok", "msg": f"{len(vlans)} VLAN, {len(ports)} port"},
            ]
        }

    def _parse_hostname(self):
        for o in self.commands_output.values():
            m = re.search(r'(\S+)[#>]', o)
            if m: return m.group(1)
        return self.ip

    def _parse_model(self):
        v = self.commands_output.get("show version", "")
        m = re.search(r'[Cc]isco\s+(\S+)', v)
        return f"Cisco {m.group(1)}" if m else "Cisco Switch"

    def _parse_vlans(self):
        vlans = {}
        for line in self.commands_output.get("show vlan brief", "").split('\n'):
            m = re.match(r'^(\d+)\s+(\S+)\s+(active|act/unsup)', line)
            if m: vlans[m.group(1)] = m.group(2)
        return vlans or {"1": "default"}

    def _parse_ports(self):
        ports = []
        port_num = 0
        for line in self.commands_output.get("show interfaces status", "").split('\n'):
            m = re.match(r'^(Gi|Fa|Te)(\S+)\s+(.*?)\s+(connected|notconnect)\s+(\S+)\s+(\S+)\s+(\S+)', line)
            if m:
                port_num += 1
                prefix, pid, desc, status, vlan = m.group(1), m.group(2), m.group(3).strip(), m.group(4), m.group(5)
                mode = "trunk" if vlan.lower() == "trunk" else "access"
                ports.append({
                    "num": port_num, "name": f"{prefix}{pid}", "desc": desc,
                    "status": "active" if status == "connected" else "inactive",
                    "duplex": "full", "speed": "1000", "vlan": vlan, "mode": mode,
                    "type": "sfp" if prefix == "Te" else "copper",
                    "tx_bytes": 0, "rx_bytes": 0, "tx_packets": 0, "rx_packets": 0, "macs": [],
                })
        return ports


# ─── MAC -> IP Resolution ───────────────────────────────────────────

def get_local_arp():
    arp = {}
    try:
        result = subprocess.run(['arp', '-a'], capture_output=True, text=True, timeout=5)
        for line in result.stdout.split('\n'):
            m = re.match(r'\s*([\d.]+)\s+([\da-fA-F-]{17})\s+\S+', line)
            if m:
                arp[m.group(2).upper()] = m.group(1)
    except Exception:
        pass
    return arp

def get_dhcp_leases():
    mac_ip = {}
    # Windows DHCP Server
    try:
        from pypsrp.client import Client
        dhcp_ip = os.environ.get('DHCP_SERVER', '10.10.11.245')
        dhcp_user = os.environ.get('DHCP_USER', 'administrator')
        dhcp_pass = os.environ.get('DHCP_PASS', '')
        if not dhcp_pass:
            return mac_ip
        client = Client(dhcp_ip, username=dhcp_user, password=dhcp_pass, ssl=False)
        output, _, _ = client.execute_ps('''
            Get-DhcpServerv4Scope | ForEach-Object {
                Get-DhcpServerv4Lease -ScopeId $_.ScopeId
            } | Select-Object @{N='ip';E={$_.IPAddress.IPAddressToString}}, @{N='mac';E={$_.ClientId}}, HostName | ConvertTo-Json -Compress
        ''')
        leases = json.loads(output)
        if not isinstance(leases, list):
            leases = [leases]
        for l in leases:
            mac = (l.get('mac') or '').upper().replace(':', '-')
            ip = l.get('ip') or ''
            hostname = l.get('HostName') or ''
            if hostname and '.' in hostname:
                hostname = hostname.split('.')[0]
            if mac and ip:
                mac_ip[mac] = {"ip": ip, "hostname": hostname}
    except Exception as e:
        print(f"DHCP error: {e}")

    # SonicWall fallback
    try:
        import requests
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        s = requests.Session()
        s.verify = False
        sw_ip = os.environ.get('SONICWALL_IP', '172.20.10.254')
        sw_user = os.environ.get('SONICWALL_USER', 'admin')
        sw_pass = os.environ.get('SONICWALL_PASS', '')
        if not sw_pass:
            raise Exception("No SonicWall password")
        r = s.post(f"https://{sw_ip}:444/api/sonicos/auth",
                    json={"user": sw_user, "password": sw_pass, "override": True}, timeout=10)
        if r.ok:
            r = s.get(f"https://{sw_ip}:444/api/sonicos/reporting/dhcp-server/ipv4/leases", timeout=10)
            if r.ok:
                for l in r.json():
                    mac = l.get("mac_address", "").upper().replace(":", "-")
                    ip = l.get("ip_address", "")
                    vendor = l.get("vendor") or ""
                    if mac and ip and mac not in mac_ip:
                        mac_ip[mac] = {"ip": ip, "hostname": "", "vendor": vendor}
    except Exception:
        pass
    return mac_ip


# ─── Auto-detect ────────────────────────────────────────────────────

def detect_switch_type(ip):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(8)
        sock.connect((ip, 23))
        import time; time.sleep(2)
        sock.settimeout(5)
        data = b""
        try:
            data = sock.recv(4096)
        except socket.timeout:
            pass
        sock.close()
        banner = data.decode('utf-8', errors='ignore').lower()
        if any(k in banner for k in ["comware", "h3c", "hpe", "hewlett"]):
            return "hp_comware"
        elif any(k in banner for k in ["edge-core", "ecs", "accton"]):
            return "edgecore"
        elif any(k in banner for k in ["cisco", "ios"]):
            return "cisco"
        return "edgecore"
    except Exception:
        return "edgecore"


# ─── Flask Routes ───────────────────────────────────────────────────

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/switches', methods=['GET'])
def get_switches():
    return jsonify(load_switches())

@app.route('/api/switches/<path:ip>', methods=['DELETE'])
def remove_switch(ip):
    delete_switch_db(ip)
    return jsonify({"status": "ok"})

@app.route('/api/scan', methods=['POST'])
def scan_switch():
    data = request.json
    ip = data.get('ip', '').strip()
    user = data.get('username', 'admin').strip()
    pwd = data.get('password', '').strip()
    model = data.get('model', '').strip().lower()

    if not ip:
        return jsonify({"error": "IP gerekli"}), 400

    try:
        if "cisco" in model:
            sw_type = "cisco"
        elif any(k in model for k in ["hp", "h3c", "comware", "a5800"]):
            sw_type = "hp_comware"
        elif any(k in model for k in ["edge", "ecs", "accton"]):
            sw_type = "edgecore"
        else:
            sw_type = detect_switch_type(ip)

        sw_cls = {"cisco": CiscoSwitch, "hp_comware": HPComwareSwitch}.get(sw_type, EdgeCoreSwitch)
        sw = sw_cls(ip, user, pwd)
        result = sw.scan()

        result["logs"].insert(0, {"type": "info", "msg": f"Switch tipi: {sw_type}"})

        # Enrich with IP/hostname
        arp = get_local_arp()
        dhcp = get_dhcp_leases()
        for port in result.get("ports", []):
            for mac_entry in port.get("macs", []):
                mu = mac_entry["mac"].upper().replace(":", "-")
                if mu in dhcp:
                    mac_entry["ip"] = dhcp[mu]["ip"]
                    mac_entry["hostname"] = dhcp[mu].get("hostname", "")
                    mac_entry["vendor"] = dhcp[mu].get("vendor", "")
                elif mu in arp:
                    mac_entry["ip"] = arp[mu]

        save_switch(ip, user, pwd, model, result.get("hostname", ip), result)
        return jsonify(result)

    except Exception as e:
        err_result = {
            "error": str(e), "hostname": ip, "model": model or "?",
            "uptime": "N/A", "vlans": {}, "ports": [],
            "logs": [{"type": "err", "msg": f"Hata: {e}"}]
        }
        return jsonify(err_result), 500


if __name__ == '__main__':
    print("=" * 50)
    print("  Switch VLAN Monitor - http://0.0.0.0:5050")
    print("=" * 50)
    app.run(host='0.0.0.0', port=5050, debug=False)
