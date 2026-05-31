"""
=============================================================
  Network Threat Detection & Mitigation Simulation
  Author : Kevin Lugue
=============================================================
  Simulates an IDS/IPS system that:
    - Generates normal background network traffic
    - Launches randomized cyber attacks
    - Detects threats via signature + anomaly detection
    - Applies automated mitigation responses
    - Logs all events with timestamps and severity
=============================================================
"""

import time
import random
import threading
import ipaddress
import hashlib
import datetime
from collections import deque, defaultdict
from colorama import Fore, Back, Style, init

init(autoreset=True)

# ─────────────────────────────────────────────────────────────
#  CONSTANTS & CONFIG
# ─────────────────────────────────────────────────────────────

BANNER = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗
║       NETWORK THREAT DETECTION & MITIGATION SYSTEM          ║
║       IDS/IPS Simulation  ·  v1.0.0                         ║
╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""

NORMAL_PPS_MIN   = 500
NORMAL_PPS_MAX   = 2_000
DETECTION_WINDOW = 10        # seconds of traffic to analyse
ANOMALY_THRESHOLD = 3.5      # std-devs above baseline = anomaly
AUTO_BLOCK_CHANCE = 0.80     # 80% auto-mitigation success rate

# Known malicious signatures (simplified pattern strings)
SIGNATURES = {
    "SQL_INJECT_1": "' OR '1'='1",
    "SQL_INJECT_2": "UNION SELECT",
    "XSS_BASIC":    "<script>alert(",
    "XSS_IMG":      "<img src=x onerror=",
    "CMD_INJECT":   "; /bin/sh",
    "PATH_TRAV":    "../../etc/passwd",
    "C2_BEACON":    "Mozilla/4.0 (compatible; MSIE 6.0)",   # classic C2 UA
    "SHELLCODE":    r"\x90\x90\x90\x90",                    # NOP sled
}

# Attack definitions
ATTACKS = {
    "ddos": {
        "name":        "DDoS Volumetric Flood",
        "type":        "volumetric",
        "pps_mult":    random.randint(40, 80),
        "duration":    random.randint(8, 14),
        "severity":    "CRITICAL",
        "description": "Massive UDP/ICMP flood overwhelming bandwidth",
        "mitigation":  "Null-route applied; upstream scrubbing centre alerted",
        "ports":       [80, 443, 53],
    },
    "bruteforce": {
        "name":        "SSH Brute-force",
        "type":        "auth",
        "pps_mult":    3,
        "duration":    random.randint(6, 12),
        "severity":    "CRITICAL",
        "description": "Repeated failed SSH authentication attempts",
        "mitigation":  "Source IP blocked; fail2ban rule inserted; auth locked",
        "ports":       [22],
    },
    "sqlinject": {
        "name":        "SQL Injection",
        "type":        "payload",
        "pps_mult":    1.3,
        "duration":    random.randint(4, 8),
        "severity":    "HIGH",
        "description": "Malicious SQL payloads targeting web application DB",
        "mitigation":  "WAF rule matched; connection reset; payload logged",
        "ports":       [80, 443, 3306],
        "signature":   "SQL_INJECT_1",
    },
    "portscan": {
        "name":        "Stealth Port Scan",
        "type":        "reconnaissance",
        "pps_mult":    1.8,
        "duration":    random.randint(5, 10),
        "severity":    "MEDIUM",
        "description": "SYN scan probing open ports across host range",
        "mitigation":  "Port scan detected; source quarantined; scan logged",
        "ports":       list(range(1, 1025)),
    },
    "xss": {
        "name":        "XSS Payload Injection",
        "type":        "payload",
        "pps_mult":    1.2,
        "duration":    random.randint(3, 7),
        "severity":    "HIGH",
        "description": "Cross-site scripting payloads in HTTP parameters",
        "mitigation":  "Input sanitised; response blocked; session invalidated",
        "ports":       [80, 443],
        "signature":   "XSS_BASIC",
    },
    "c2": {
        "name":        "C2 Beaconing",
        "type":        "exfiltration",
        "pps_mult":    1.5,
        "duration":    random.randint(10, 16),
        "severity":    "CRITICAL",
        "description": "Compromised host beaconing to command-and-control server",
        "mitigation":  "Outbound C2 traffic blocked; endpoint isolated; IR started",
        "ports":       [443, 8080, 4444],
        "signature":   "C2_BEACON",
    },
    "ransomware": {
        "name":        "Ransomware Lateral Movement",
        "type":        "intrusion",
        "pps_mult":    2.5,
        "duration":    random.randint(8, 15),
        "severity":    "CRITICAL",
        "description": "Ransomware spreading laterally via SMB/RDP",
        "mitigation":  "SMB/RDP blocked; host isolated; snapshot initiated",
        "ports":       [445, 3389, 139],
    },
}


# ─────────────────────────────────────────────────────────────
#  COLOUR HELPERS
# ─────────────────────────────────────────────────────────────

SEV_COLOR = {
    "CRITICAL": Fore.RED + Style.BRIGHT,
    "HIGH":     Fore.YELLOW + Style.BRIGHT,
    "MEDIUM":   Fore.YELLOW,
    "LOW":      Fore.CYAN,
    "INFO":     Fore.WHITE,
    "BLOCK":    Fore.GREEN + Style.BRIGHT,
    "DETECT":   Fore.MAGENTA + Style.BRIGHT,
}

def sev_tag(level: str) -> str:
    color = SEV_COLOR.get(level, Fore.WHITE)
    return f"{color}[{level:<8}]{Style.RESET_ALL}"

def ts() -> str:
    return datetime.datetime.now().strftime("%H:%M:%S.%f")[:11]

def rand_ip(private: bool = False) -> str:
    if private:
        subnets = ["192.168.1.", "10.0.0.", "172.16.0."]
        return random.choice(subnets) + str(random.randint(1, 254))
    subnets = ["203.0.113.", "198.51.100.", "185.220.101.", "91.108.4.", "45.33.32."]
    return random.choice(subnets) + str(random.randint(1, 254))

def rand_port() -> int:
    return random.choice([80, 443, 22, 53, 8080, 3306, 25, 110, 3389, 445])

def fake_hash() -> str:
    return hashlib.md5(str(random.random()).encode()).hexdigest()[:12]


# ─────────────────────────────────────────────────────────────
#  PACKET SIMULATION
# ─────────────────────────────────────────────────────────────

PROTOCOLS = ["TCP", "UDP", "ICMP", "HTTP", "HTTPS", "DNS"]

class Packet:
    """Represents a simulated network packet."""
    def __init__(self, src_ip=None, dst_ip=None, protocol=None,
                 dst_port=None, payload="", size=None):
        self.src_ip   = src_ip   or rand_ip(private=False)
        self.dst_ip   = dst_ip   or rand_ip(private=True)
        self.protocol = protocol or random.choice(PROTOCOLS)
        self.dst_port = dst_port or rand_port()
        self.payload  = payload
        self.size     = size     or random.randint(64, 1500)
        self.timestamp = time.time()
        self.flagged  = False

    def __repr__(self):
        return (f"{self.protocol} {self.src_ip}:{random.randint(1024,65535)}"
                f" → {self.dst_ip}:{self.dst_port}  [{self.size}B]")


# ─────────────────────────────────────────────────────────────
#  DETECTION ENGINE
# ─────────────────────────────────────────────────────────────

class DetectionEngine:
    """
    Hybrid IDS combining:
      1. Signature-based detection  — matches known attack patterns
      2. Anomaly-based detection    — statistical deviation from baseline
      3. Rate-based detection       — packets-per-second threshold
      4. Heuristic detection        — port scan, brute-force pattern
    """

    def __init__(self):
        self.baseline_pps   = NORMAL_PPS_MAX / 2
        self.traffic_window = deque(maxlen=DETECTION_WINDOW)
        self.ip_counters    = defaultdict(int)      # packets per source IP
        self.auth_failures  = defaultdict(int)      # failed auths per IP
        self.port_hits      = defaultdict(set)      # ports touched per IP
        self.alerts         = []

    def update_baseline(self, pps: float):
        self.traffic_window.append(pps)
        if len(self.traffic_window) >= 5:
            self.baseline_pps = sum(self.traffic_window) / len(self.traffic_window)

    def signature_check(self, packet: Packet) -> tuple[bool, str]:
        """Check payload against known attack signatures."""
        for sig_name, pattern in SIGNATURES.items():
            if pattern.lower() in packet.payload.lower():
                return True, sig_name
        return False, ""

    def anomaly_check(self, current_pps: float) -> tuple[bool, float]:
        """Detect statistical anomaly in traffic rate."""
        if len(self.traffic_window) < 5:
            return False, 0.0
        mean = self.baseline_pps
        variance = sum((x - mean) ** 2 for x in self.traffic_window) / len(self.traffic_window)
        std_dev  = variance ** 0.5 or 1
        z_score  = (current_pps - mean) / std_dev
        return z_score > ANOMALY_THRESHOLD, round(z_score, 2)

    def rate_check(self, src_ip: str, count: int) -> bool:
        """Flag IPs sending too many packets."""
        return count > 500

    def portscan_check(self, src_ip: str) -> bool:
        """Detect if source has touched too many ports."""
        return len(self.port_hits[src_ip]) > 20

    def bruteforce_check(self, src_ip: str) -> bool:
        """Detect repeated auth failures."""
        return self.auth_failures[src_ip] > 5

    def analyse(self, packets: list, current_pps: float) -> list:
        """Run all detection methods; return list of alerts."""
        findings = []

        # Count per-IP traffic
        for pkt in packets:
            self.ip_counters[pkt.src_ip] += 1
            self.port_hits[pkt.src_ip].add(pkt.dst_port)
            if pkt.dst_port == 22 and random.random() < 0.15:
                self.auth_failures[pkt.src_ip] += 1

            # Signature check
            hit, sig = self.signature_check(pkt)
            if hit:
                findings.append({
                    "method": "SIGNATURE",
                    "src_ip": pkt.src_ip,
                    "detail": f"Signature match: {sig} on port {pkt.dst_port}",
                    "severity": "HIGH",
                })

        # Anomaly check
        is_anomaly, z = self.anomaly_check(current_pps)
        if is_anomaly:
            findings.append({
                "method": "ANOMALY",
                "src_ip": "NETWORK",
                "detail": f"Traffic anomaly — z-score {z} (threshold {ANOMALY_THRESHOLD})",
                "severity": "CRITICAL",
            })

        # Rate-based
        for ip, count in self.ip_counters.items():
            if self.rate_check(ip, count):
                findings.append({
                    "method": "RATE",
                    "src_ip": ip,
                    "detail": f"Rate limit exceeded: {count} pkts from {ip}",
                    "severity": "CRITICAL",
                })

        # Port scan
        for ip in list(self.port_hits):
            if self.portscan_check(ip):
                findings.append({
                    "method": "HEURISTIC",
                    "src_ip": ip,
                    "detail": f"Port scan: {len(self.port_hits[ip])} ports probed by {ip}",
                    "severity": "MEDIUM",
                })

        # Brute-force
        for ip in list(self.auth_failures):
            if self.bruteforce_check(ip):
                findings.append({
                    "method": "HEURISTIC",
                    "src_ip": ip,
                    "detail": f"Brute-force: {self.auth_failures[ip]} failed auths from {ip}",
                    "severity": "CRITICAL",
                })

        self.ip_counters.clear()
        return findings


# ─────────────────────────────────────────────────────────────
#  MITIGATION ENGINE
# ─────────────────────────────────────────────────────────────

class MitigationEngine:
    """
    Applies automated countermeasures based on threat type and severity.
    Tracks blocked IPs, active firewall rules, and quarantined hosts.
    """

    def __init__(self):
        self.blocked_ips     = set()
        self.firewall_rules  = []
        self.quarantined     = set()
        self.mitigated_count = 0

    def block_ip(self, ip: str, reason: str) -> str:
        self.blocked_ips.add(ip)
        rule = f"DROP src={ip} reason='{reason}'"
        self.firewall_rules.append(rule)
        return f"Firewall rule inserted: {rule}"

    def rate_limit(self, ip: str, limit: int = 100) -> str:
        rule = f"RATE_LIMIT src={ip} max={limit}pps"
        self.firewall_rules.append(rule)
        return f"Rate limit applied: {rule}"

    def quarantine_host(self, ip: str) -> str:
        self.quarantined.add(ip)
        return f"Host {ip} moved to quarantine VLAN — traffic isolated"

    def null_route(self, ip: str) -> str:
        return f"Null-route to /dev/null for {ip} — traffic black-holed"

    def waf_block(self, sig: str) -> str:
        return f"WAF rule activated for signature {sig} — requests dropped"

    def mitigate(self, alert: dict, attack_def: dict = None) -> list:
        """Choose and apply the right countermeasure for an alert."""
        actions = []
        ip   = alert["src_ip"]
        meth = alert["method"]

        if random.random() > (1 - AUTO_BLOCK_CHANCE):
            if meth == "ANOMALY" or (attack_def and attack_def["type"] == "volumetric"):
                actions.append(self.null_route(ip if ip != "NETWORK" else rand_ip()))
                actions.append("Upstream scrubbing centre notified via BGP Blackhole")

            elif meth == "RATE":
                actions.append(self.block_ip(ip, "rate-exceeded"))
                actions.append(self.rate_limit(ip))

            elif meth == "SIGNATURE":
                sig = alert["detail"].split("Signature match: ")[1].split(" ")[0] if "Signature match:" in alert["detail"] else "UNKNOWN"
                actions.append(self.waf_block(sig))
                actions.append(self.block_ip(ip, f"signature-{sig}"))

            elif meth == "HEURISTIC":
                if "Brute-force" in alert["detail"]:
                    actions.append(self.block_ip(ip, "brute-force"))
                    actions.append("fail2ban rule updated — IP banned for 24h")
                elif "Port scan" in alert["detail"]:
                    actions.append(self.quarantine_host(ip))

            if attack_def:
                actions.append(f"Incident response: {attack_def['mitigation']}")

            self.mitigated_count += 1
        else:
            actions.append(f"[!] Auto-mitigation failed for {ip} — manual review required")

        return actions


# ─────────────────────────────────────────────────────────────
#  TRAFFIC GENERATOR
# ─────────────────────────────────────────────────────────────

class TrafficGenerator:
    """Generates background and attack traffic packets."""

    def generate_normal(self, count: int) -> list:
        return [Packet() for _ in range(count)]

    def generate_attack(self, attack_key: str, count: int) -> list:
        atk = ATTACKS[attack_key]
        packets = []
        src_ip  = rand_ip(private=False)  # single attacker IP
        for _ in range(count):
            port    = random.choice(atk["ports"]) if atk["ports"] else rand_port()
            payload = ""
            if "signature" in atk:
                sig_pattern = SIGNATURES.get(atk["signature"], "")
                payload = sig_pattern if random.random() < 0.4 else ""
            pkt = Packet(
                src_ip=src_ip,
                protocol=random.choice(PROTOCOLS),
                dst_port=port,
                payload=payload,
                size=random.randint(40, 1500) if atk["type"] != "volumetric" else 1500,
            )
            packets.append(pkt)
        return packets, src_ip


# ─────────────────────────────────────────────────────────────
#  LOGGER
# ─────────────────────────────────────────────────────────────

class Logger:
    def __init__(self):
        self.events = []

    def log(self, level: str, message: str, show: bool = True):
        entry = {"time": ts(), "level": level, "message": message}
        self.events.append(entry)
        if show:
            tag = sev_tag(level)
            print(f"  {Fore.CYAN}{entry['time']}{Style.RESET_ALL}  {tag}  {message}")

    def divider(self, char: str = "─", width: int = 70, color=Fore.CYAN):
        print(f"  {color}{char * width}{Style.RESET_ALL}")

    def section(self, title: str):
        self.divider("═")
        print(f"  {Fore.WHITE + Style.BRIGHT}  {title}{Style.RESET_ALL}")
        self.divider("─")

    def summary(self, stats: dict):
        self.section("SIMULATION SUMMARY")
        for k, v in stats.items():
            print(f"  {Fore.CYAN}{k:<30}{Style.RESET_ALL} {Fore.WHITE + Style.BRIGHT}{v}{Style.RESET_ALL}")
        self.divider("═")


# ─────────────────────────────────────────────────────────────
#  SIMULATION CONTROLLER
# ─────────────────────────────────────────────────────────────

class ThreatDetectionSimulation:
    """
    Orchestrates the full simulation:
      Phase 1 — Baseline monitoring (normal traffic)
      Phase 2 — Attack waves with detection + mitigation
      Phase 3 — Recovery and reporting
    """

    def __init__(self, attack_count: int = 4, tick_delay: float = 0.4):
        self.engine     = DetectionEngine()
        self.mitigator  = MitigationEngine()
        self.generator  = TrafficGenerator()
        self.logger     = Logger()
        self.attack_count  = attack_count
        self.tick_delay    = tick_delay
        self.total_packets = 0
        self.total_alerts  = 0
        self.blocked_count = 0

    # ── Phase 1: Baseline ─────────────────────────────────────
    def run_baseline(self, ticks: int = 6):
        self.logger.section("PHASE 1 — BASELINE MONITORING")
        self.logger.log("INFO", "Initialising IDS/IPS engine...")
        time.sleep(0.2)
        self.logger.log("INFO", f"Loading {len(SIGNATURES)} attack signatures into detection engine")
        self.logger.log("INFO", f"Anomaly detection threshold set to z-score > {ANOMALY_THRESHOLD}")
        self.logger.log("INFO", "Starting network baseline collection...")
        self.logger.divider()

        for i in range(ticks):
            pps = random.randint(NORMAL_PPS_MIN, NORMAL_PPS_MAX)
            packets = self.generator.generate_normal(pps // 10)
            self.engine.update_baseline(pps)
            self.total_packets += len(packets)
            self.logger.log("INFO", f"Tick {i+1}/{ticks} — Traffic: {pps:,} pps  "
                                    f"Baseline: {int(self.engine.baseline_pps):,} pps  "
                                    f"Packets: {self.total_packets:,}")
            time.sleep(self.tick_delay)

        self.logger.divider()
        self.logger.log("INFO", f"Baseline established at {int(self.engine.baseline_pps):,} pps — monitoring active")

    # ── Phase 2: Attack waves ─────────────────────────────────
    def run_attacks(self):
        self.logger.section("PHASE 2 — ATTACK SIMULATION & DETECTION")
        attack_keys = getattr(self, "_selected_attacks", None) or random.sample(list(ATTACKS.keys()), min(self.attack_count, len(ATTACKS)))

        for idx, atk_key in enumerate(attack_keys, 1):
            atk = ATTACKS[atk_key]
            self.logger.divider("─", 70, Fore.RED)
            print(f"\n  {Fore.RED + Style.BRIGHT}[ ATTACK {idx}/{len(attack_keys)} ]  "
                  f"{atk['name'].upper()}{Style.RESET_ALL}\n")

            # ── Attack ramp-up ────────────────────────────────
            pps = int(NORMAL_PPS_MAX * atk["pps_mult"])
            atk_packets, src_ip = self.generator.generate_attack(atk_key, pps // 8)
            self.total_packets += len(atk_packets)

            self.logger.log(atk["severity"],
                f"Attack origin: {src_ip}  |  Type: {atk['type'].upper()}  |  "
                f"Rate: {pps:,} pps  |  Ports: {str(atk['ports'][:4])[1:-1]}...")

            if atk["type"] == "payload" and "signature" in atk:
                sample = SIGNATURES.get(atk["signature"], "")[:40]
                self.logger.log("DETECT", f"Payload fragment intercepted: {Fore.YELLOW}\"{sample}...\"")

            time.sleep(self.tick_delay * 0.6)

            # ── Detection ─────────────────────────────────────
            self.logger.log("INFO", f"Running {4} detection methods against {len(atk_packets)} packets...")
            # Add to engine window so anomaly fires
            self.engine.update_baseline(pps)
            alerts = self.engine.analyse(atk_packets, pps)
            self.total_alerts += len(alerts)

            if alerts:
                self.logger.divider("·", 50, Fore.MAGENTA)
                for alert in alerts[:4]:   # cap output to 4 alerts per attack
                    self.logger.log("DETECT",
                        f"[{alert['method']}] {alert['detail']}")
                    time.sleep(self.tick_delay * 0.3)
            else:
                # Guarantee at least one alert for the simulation narrative
                self.logger.log("DETECT",
                    f"[ANOMALY] z-score exceeded — {atk['name']} pattern identified")
                self.total_alerts += 1

            time.sleep(self.tick_delay * 0.5)

            # ── Mitigation ────────────────────────────────────
            self.logger.divider("·", 50, Fore.GREEN)
            self.logger.log("INFO", "Triggering automated mitigation pipeline...")
            alert_to_mitigate = alerts[0] if alerts else {
                "method": "ANOMALY", "src_ip": src_ip,
                "detail": atk["description"], "severity": atk["severity"]
            }
            actions = self.mitigator.mitigate(alert_to_mitigate, atk)

            for action in actions:
                lvl = "BLOCK" if "fail" not in action.lower() else "HIGH"
                self.logger.log(lvl, action)
                time.sleep(self.tick_delay * 0.25)

            if src_ip in self.mitigator.blocked_ips or src_ip in self.mitigator.quarantined:
                self.blocked_count += 1
                self.logger.log("BLOCK",
                    f"Threat contained — {src_ip} neutralised  "
                    f"[hash:{fake_hash()}]")
            else:
                self.logger.log("HIGH",
                    f"Partial mitigation — {src_ip} flagged for manual review")

            # ── Recovery ticks ────────────────────────────────
            print()
            self.logger.log("INFO", "Monitoring recovery — anomaly score decaying...")
            for t in range(3):
                decay_pps = int(pps * (0.6 - t * 0.2))
                self.engine.update_baseline(decay_pps)
                self.logger.log("INFO",
                    f"  Recovery tick {t+1}/3 — {decay_pps:,} pps  "
                    f"(baseline drift: {abs(decay_pps - int(self.engine.baseline_pps)):,} pps)")
                time.sleep(self.tick_delay * 0.5)

            print()
            time.sleep(self.tick_delay * 0.4)

    # ── Phase 3: Recovery & report ────────────────────────────
    def run_recovery(self):
        self.logger.section("PHASE 3 — SYSTEM RECOVERY")
        self.logger.log("INFO", "Restoring normal traffic baseline...")
        for i in range(4):
            pps = random.randint(NORMAL_PPS_MIN, NORMAL_PPS_MAX)
            self.engine.update_baseline(pps)
            self.logger.log("INFO",
                f"Recovery tick {i+1}/4 — {pps:,} pps — "
                f"{'Stable' if i > 1 else 'Recovering'}")
            time.sleep(self.tick_delay * 0.5)

        self.logger.log("INFO", f"Firewall rules committed: {len(self.mitigator.firewall_rules)}")
        self.logger.log("INFO", f"Quarantined hosts: {len(self.mitigator.quarantined)}")
        self.logger.log("BLOCK", "System returned to NORMAL operating state")

    # ── Summary report ────────────────────────────────────────
    def print_summary(self):
        stats = {
            "Total packets processed":   f"{self.total_packets:,}",
            "Alerts generated":          f"{self.total_alerts}",
            "Attacks simulated":         f"{self.attack_count}",
            "Threats mitigated":         f"{self.mitigator.mitigated_count}",
            "IPs blocked":               f"{len(self.mitigator.blocked_ips)}",
            "Hosts quarantined":         f"{len(self.mitigator.quarantined)}",
            "Firewall rules inserted":   f"{len(self.mitigator.firewall_rules)}",
            "Detection methods used":    "Signature · Anomaly · Rate · Heuristic",
            "Auto-mitigation rate":      f"{AUTO_BLOCK_CHANCE * 100:.0f}%",
            "Signatures loaded":         f"{len(SIGNATURES)}",
            "Final system state":        "NORMAL — all threats contained",
        }
        self.logger.summary(stats)

    # ── Entry point ───────────────────────────────────────────
    def run(self):
        try:
            self.run_baseline()
            print()
            self.run_attacks()
            print()
            self.run_recovery()
            print()
            self.print_summary()
        except KeyboardInterrupt:
            print(f"\n\n  {Fore.YELLOW}[!] Simulation interrupted by user.{Style.RESET_ALL}\n")
            self.print_summary()


# ─────────────────────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────────────────────

def show_menu() -> list:
    """Interactive menu to select one or more attack types."""
    print(BANNER)
    print(f"  {Fore.WHITE + Style.BRIGHT}Select attack type(s) to simulate:{Style.RESET_ALL}\n")

    keys = list(ATTACKS.keys())
    for i, key in enumerate(keys, 1):
        atk = ATTACKS[key]
        sev_color = SEV_COLOR.get(atk["severity"], Fore.WHITE)
        print(f"  {Fore.CYAN}[{i}]{Style.RESET_ALL}  {atk['name']:<30} "
              f"{sev_color}{atk['severity']:<10}{Style.RESET_ALL} "
              f"{Fore.WHITE}{atk['description']}{Style.RESET_ALL}")

    print(f"\n  {Fore.CYAN}[A]{Style.RESET_ALL}  Run ALL attack types")
    print(f"  {Fore.CYAN}[R]{Style.RESET_ALL}  Random selection (original behaviour)")
    print()

    while True:
        raw = input(f"  {Fore.YELLOW}Enter number(s) separated by commas (e.g. 1,3,5), A, or R: {Style.RESET_ALL}").strip().upper()

        if raw == "A":
            selected = keys
            break
        elif raw == "R":
            count = len(keys)
            while True:
                try:
                    n = int(input(f"  {Fore.YELLOW}How many random attacks? (1-{count}): {Style.RESET_ALL}").strip())
                    if 1 <= n <= count:
                        selected = random.sample(keys, n)
                        break
                    print(f"  {Fore.RED}Enter a number between 1 and {count}.{Style.RESET_ALL}")
                except ValueError:
                    print(f"  {Fore.RED}Invalid input.{Style.RESET_ALL}")
            break
        else:
            try:
                indices = [int(x.strip()) for x in raw.split(",")]
                if all(1 <= i <= len(keys) for i in indices):
                    selected = [keys[i - 1] for i in indices]
                    # remove duplicates while preserving order
                    seen = set()
                    selected = [x for x in selected if not (x in seen or seen.add(x))]
                    break
                else:
                    print(f"  {Fore.RED}Please enter numbers between 1 and {len(keys)}.{Style.RESET_ALL}")
            except ValueError:
                print(f"  {Fore.RED}Invalid input — try again.{Style.RESET_ALL}")

    print()
    print(f"  {Fore.GREEN + Style.BRIGHT}Selected attacks:{Style.RESET_ALL} "
          + ", ".join(f"{Fore.CYAN}{ATTACKS[k]['name']}{Style.RESET_ALL}" for k in selected))

    while True:
        try:
            speed = float(input(f"  {Fore.YELLOW}Tick speed? (0.05 = fast, 0.4 = normal, 1.0 = slow) [default 0.4]: {Style.RESET_ALL}").strip() or "0.4")
            if 0 <= speed <= 5:
                break
            print(f"  {Fore.RED}Enter a value between 0 and 5.{Style.RESET_ALL}")
        except ValueError:
            print(f"  {Fore.RED}Invalid input — using default 0.4{Style.RESET_ALL}")
            speed = 0.4
            break

    print()
    return selected, speed


if __name__ == "__main__":
    selected_attacks, tick_speed = show_menu()

    sim = ThreatDetectionSimulation(
        attack_count=len(selected_attacks),
        tick_delay=tick_speed,
    )
    # Override random selection with user's chosen attacks
    sim._selected_attacks = selected_attacks
    sim.run()