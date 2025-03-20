#!/usr/bin/env python3
import asyncio
import logging
import random
import socket
import ssl
import sys
import os
from argparse import ArgumentParser
from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional

import scapy.all as scapy
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from rich.console import Console
from rich.progress import Progress
from rich.table import Table

scapy.conf.verb = 0  # Make Scapy quiet
console = Console()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler("scanner.log"), logging.StreamHandler()],
)

# ---------------------- ENUMS & DATA ------------------------
class ScanType(Enum):
    SYN = "syn"
    SSL = "ssl"
    UDP = "udp"
    ACK = "ack"
    FIN = "fin"
    XMAS = "xmas"
    NULL = "null"
    WINDOW = "window"
    TLSECHO = "tls_echo"  # New TLS Echo Mask scan type

@dataclass
class PortResult:
    tcp_states: Dict[ScanType, str] = field(default_factory=dict)
    udp_state: str = ""
    filtering: str = ""
    service: str = ""
    version: str = ""
    vulns: List[str] = field(default_factory=list)
    cert_info: Optional[Dict] = None
    banner: str = ""
    os_guess: str = ""

# ---------------------- MAIN SCANNER ------------------------
class QuantumScanner:
    def __init__(
        self,
        target: str,
        ports: List[int],
        scan_types: List[ScanType],
        concurrency: int = 100,
        max_rate: int = 500,
        evasions: bool = False,
        verbose: bool = False,
        use_ipv6: bool = False,
        json_output: bool = False,
        shuffle_ports: bool = False,
        timeout_scan: float = 3.0,
        timeout_connect: float = 3.0,
        timeout_banner: float = 3.0
    ):
        self.use_ipv6 = use_ipv6
        self.json_output = json_output
        self.shuffle_ports = shuffle_ports
        self.timeout_scan = timeout_scan
        self.timeout_connect = timeout_connect
        self.timeout_banner = timeout_banner

        # Resolve target IP
        if not self.use_ipv6:
            self.target_ip = socket.gethostbyname(target)
            try:
                # Use the target's IP to get the correct outbound interface/IP
                self.local_ip = scapy.conf.route.route(self.target_ip)[1]
            except Exception:
                self.local_ip = None  # or "0.0.0.0"
        else:
            info = socket.getaddrinfo(target, None, socket.AF_INET6)
            self.target_ip = info[0][4][0]
            self.local_ip = "::"

        if self.shuffle_ports:
            random.shuffle(ports)
        self.ports = ports
        self.scan_types = scan_types
        self.concurrency = concurrency
        self.max_rate = max_rate
        self.evasions = evasions
        self.verbose = verbose

        self.results: Dict[int, PortResult] = {}
        self.adaptation_factor = 1.0
        self.history = deque(maxlen=100)
        self.lock = asyncio.Lock()

        # SSL context
        self.ctx = ssl.create_default_context()
        self.ctx.check_hostname = False
        self.ctx.verify_mode = ssl.CERT_NONE

        if self.evasions and os.geteuid() != 0:
            logging.error("Evasions require root privileges! Exiting.")
            sys.exit(1)

        if self.verbose:
            logging.getLogger().setLevel(logging.DEBUG)

    async def run_scan(self):
        logging.info(f"Starting scan of {self.target_ip}")
        for port in self.ports:
            self.results[port] = PortResult()

        with Progress() as progress:
            total_tasks = len(self.ports) * len(self.scan_types)
            task = progress.add_task("[cyan]Scanning...", total=total_tasks)
            sem = asyncio.Semaphore(self.concurrency)

            tasks = []
            for port in self.ports:
                tasks.append(asyncio.create_task(self.scan_port(port, progress, task, sem)))
            await asyncio.gather(*tasks)

        self.service_fingerprinting()
        self.analyze_vulnerabilities()
        self.generate_report()

    async def scan_port(self, port: int, progress, task, sem: asyncio.Semaphore):
        async with sem:
            for st in self.scan_types:
                if st == ScanType.SYN:
                    await self.syn_scan(port)
                elif st == ScanType.SSL:
                    await self.ssl_probe(port)
                elif st == ScanType.UDP:
                    await self.udp_scan(port)
                elif st == ScanType.ACK:
                    await self.ack_scan(port)
                elif st == ScanType.FIN:
                    await self.fin_scan(port)
                elif st == ScanType.XMAS:
                    await self.xmas_scan(port)
                elif st == ScanType.NULL:
                    await self.null_scan(port)
                elif st == ScanType.WINDOW:
                    await self.window_scan(port)
                elif st == ScanType.TLSECHO:
                    await self.tls_echo_mask_scan(port)

                # If an open TCP port is detected, attempt banner grabbing immediately
                if any(state == "open" for state in self.results[port].tcp_states.values()):
                    await self.banner_grabbing(port)

                await self.adaptive_delay()

        progress.update(task, advance=len(self.scan_types))

    # -------------------- SCAN HELPERS --------------------
    def build_ip_layer(self):
        '''
        Builds an IPv4 or IPv6 layer with the appropriate source and
        destination addresses. If self.local_ip is None, we let Scapy pick.
        '''
        if not self.use_ipv6:
            ip_layer = scapy.IP(dst=self.target_ip)
            if self.local_ip:
                ip_layer.src = self.local_ip
            return ip_layer
        else:
            ip_layer = scapy.IPv6(dst=self.target_ip)
            if self.local_ip and self.local_ip != "::":
                ip_layer.src = self.local_ip
            return ip_layer

    def set_ip_ttl_or_hlim(self, ip_layer) -> None:
        '''Sets TTL (IPv4) or hlim (IPv6) to a default value or random value if evasions are enabled.'''
        if self.use_ipv6:
            ip_layer.hlim = random.choice([64, 128, 255]) if self.evasions else 64
        else:
            ip_layer.ttl = random.choice([64, 128, 255]) if self.evasions else 64

    # -------------------- SCAN METHODS --------------------
    async def syn_scan(self, port: int, max_tries=3):
        '''Performs a SYN scan:
           - Sends a SYN packet.
           - If a SYN/ACK is received, sends an RST to immediately tear down the connection.
           - Marks port as open (if SYN/ACK) or closed (if RST) or filtered (no resp).
        '''
        def do_syn_probe():
            for attempt in range(max_tries):
                ip_layer = self.build_ip_layer()
                self.set_ip_ttl_or_hlim(ip_layer)
                sport = random.randint(1024, 65535)
                seq = random.randint(0, 2**32 - 1)
                tcp_layer = scapy.TCP(dport=port, sport=sport, flags="S", seq=seq)
                pkt = ip_layer / tcp_layer

                resp = scapy.sr1(pkt, timeout=self.timeout_scan, verbose=0)
                if resp is not None and resp.haslayer(scapy.TCP):
                    flags = int(resp[scapy.TCP].flags)
                    # Check for SYN/ACK => open
                    if (flags & 0x12) == 0x12:
                        # Send RST to close half-open connection
                        rst_pkt = ip_layer / scapy.TCP(dport=port, sport=sport, flags="R", seq=seq+1)
                        scapy.send(rst_pkt, verbose=0)
                        return "open", resp
                    # Check for RST => closed
                    elif (flags & 0x04) == 0x04:
                        return "closed", resp
            return "filtered", None

        loop = asyncio.get_running_loop()
        state, resp = await loop.run_in_executor(None, do_syn_probe)
        async with self.lock:
            self.results[port].tcp_states[ScanType.SYN] = state
            if state == "open" and resp is not None:
                self.os_fingerprint(port, resp)

    async def ack_scan(self, port: int):
        def do_ack_probe():
            ip_layer = self.build_ip_layer()
            self.set_ip_ttl_or_hlim(ip_layer)
            tcp_layer = scapy.TCP(
                dport=port,
                sport=random.randint(1024, 65535),
                flags="A",
                seq=random.randint(0, 2**32 - 1)
            )
            pkt = ip_layer / tcp_layer
            resp = scapy.sr1(pkt, timeout=self.timeout_scan, verbose=0)
            if resp and resp.haslayer(scapy.TCP):
                flags = int(resp[scapy.TCP].flags)
                # If RST => port is "unfiltered"
                if (flags & 0x04) == 0x04:
                    return "unfiltered"
            return "filtered"

        loop = asyncio.get_running_loop()
        filtering = await loop.run_in_executor(None, do_ack_probe)
        async with self.lock:
            self.results[port].filtering = filtering

    async def fin_scan(self, port: int):
        def do_fin_probe():
            ip_layer = self.build_ip_layer()
            self.set_ip_ttl_or_hlim(ip_layer)
            tcp_layer = scapy.TCP(
                dport=port,
                sport=random.randint(1024, 65535),
                flags="F",
                seq=random.randint(0, 2**32 - 1)
            )
            pkt = ip_layer / tcp_layer
            resp = scapy.sr1(pkt, timeout=self.timeout_scan, verbose=0)
            if resp and resp.haslayer(scapy.TCP):
                flags = int(resp[scapy.TCP].flags)
                if (flags & 0x04) == 0x04:
                    return "closed"
            return "open|filtered"

        loop = asyncio.get_running_loop()
        state = await loop.run_in_executor(None, do_fin_probe)
        async with self.lock:
            self.results[port].tcp_states[ScanType.FIN] = state

    async def xmas_scan(self, port: int):
        def do_xmas_probe():
            ip_layer = self.build_ip_layer()
            self.set_ip_ttl_or_hlim(ip_layer)
            # Send FIN, PSH, and URG flags (X-mas tree)
            tcp_layer = scapy.TCP(
                dport=port,
                sport=random.randint(1024, 65535),
                flags="FPU",
                seq=random.randint(0, 2**32 - 1)
            )
            pkt = ip_layer / tcp_layer
            resp = scapy.sr1(pkt, timeout=self.timeout_scan, verbose=0)
            if resp and resp.haslayer(scapy.TCP):
                flags = int(resp[scapy.TCP].flags)
                if (flags & 0x04) == 0x04:
                    return "closed"
            return "open|filtered"

        loop = asyncio.get_running_loop()
        state = await loop.run_in_executor(None, do_xmas_probe)
        async with self.lock:
            self.results[port].tcp_states[ScanType.XMAS] = state

    async def null_scan(self, port: int):
        def do_null_probe():
            ip_layer = self.build_ip_layer()
            self.set_ip_ttl_or_hlim(ip_layer)
            # No TCP flags are set
            tcp_layer = scapy.TCP(
                dport=port,
                sport=random.randint(1024, 65535),
                flags=0,
                seq=random.randint(0, 2**32 - 1)
            )
            pkt = ip_layer / tcp_layer
            resp = scapy.sr1(pkt, timeout=self.timeout_scan, verbose=0)
            if resp and resp.haslayer(scapy.TCP):
                flags = int(resp[scapy.TCP].flags)
                if (flags & 0x04) == 0x04:
                    return "closed"
            return "open|filtered"

        loop = asyncio.get_running_loop()
        state = await loop.run_in_executor(None, do_null_probe)
        async with self.lock:
            self.results[port].tcp_states[ScanType.NULL] = state

    async def window_scan(self, port: int):
        def do_window_probe():
            ip_layer = self.build_ip_layer()
            self.set_ip_ttl_or_hlim(ip_layer)
            tcp_layer = scapy.TCP(
                dport=port,
                sport=random.randint(1024, 65535),
                flags="A",
                seq=random.randint(0, 2**32 - 1)
            )
            pkt = ip_layer / tcp_layer
            resp = scapy.sr1(pkt, timeout=self.timeout_scan, verbose=0)
            if resp is None:
                return "filtered"
            if resp.haslayer(scapy.TCP):
                # If window != 0 => "open" in classic Window scan logic
                if resp[scapy.TCP].window != 0:
                    return "open"
                else:
                    return "closed"
            return "filtered"

        loop = asyncio.get_running_loop()
        state = await loop.run_in_executor(None, do_window_probe)
        async with self.lock:
            self.results[port].tcp_states[ScanType.WINDOW] = state

    async def udp_scan(self, port: int):
        def do_udp_probe():
            ip_layer = self.build_ip_layer()
            self.set_ip_ttl_or_hlim(ip_layer)
            udp_layer = scapy.UDP(dport=port, sport=random.randint(1024, 65535))
            pkt = ip_layer / udp_layer / b"probe"
            resp = scapy.sr1(pkt, timeout=self.timeout_scan, verbose=0)
            if resp is None:
                return "open|filtered"
            if resp.haslayer(scapy.UDP):
                return "open"
            if resp.haslayer(scapy.ICMP):
                icmp = resp[scapy.ICMP]
                if icmp.type == 3 and icmp.code == 3:
                    return "closed"
                return "filtered"
            return "filtered"

        loop = asyncio.get_running_loop()
        state = await loop.run_in_executor(None, do_udp_probe)
        async with self.lock:
            self.results[port].udp_state = state

    async def ssl_probe(self, port: int):
        def do_ssl_connect():
            try:
                with socket.create_connection((self.target_ip, port), timeout=self.timeout_connect) as sock:
                    with self.ctx.wrap_socket(sock, server_hostname=self.target_ip) as ssock:
                        cert_bin = ssock.getpeercert(binary_form=True)
                        cert_info = self.parse_certificate(cert_bin) if cert_bin else {}
                        ssl_version = ssock.version()
                        return ("open", cert_info, ssl_version)
            except (ConnectionRefusedError, socket.timeout):
                return ("closed", None, "")
            except Exception as e:
                logging.debug(f"SSL probe error on port {port}: {e}")
                return ("closed", None, "")

        loop = asyncio.get_running_loop()
        state, cert_info, ssl_version = await loop.run_in_executor(None, do_ssl_connect)
        async with self.lock:
            self.results[port].tcp_states[ScanType.SSL] = state
            if state == "open":
                self.results[port].service = "SSL/TLS"
                self.results[port].cert_info = cert_info
                self.results[port].version = ssl_version or ""
                vulns = self.check_ssl_vulnerabilities(cert_info)
                self.results[port].vulns.extend(vulns)

    async def tls_echo_mask_scan(self, port: int):
        '''
        TLS Echo Mask Scan:
        Craft a minimal TLS Server Hello payload, send it in a SYN packet,
        and analyze the response using the same methodology as the SYN scan.
        '''
        def do_tls_echo_mask_probe():
            ip_layer = self.build_ip_layer()
            self.set_ip_ttl_or_hlim(ip_layer)
            tls_payload = (
                b"\x16"      # Content Type: Handshake (22)
                b"\x03\x03"  # Version: TLS 1.2
                b"\x00\x2f"  # Length: 47 bytes
                b"\x02"      # Handshake Type: Server Hello (2)
                b"\x00\x00\x2b"  # Handshake Length: 43 bytes
                b"\x03\x03"  # Version repeated
                + os.urandom(32)  # Random bytes (session ID, etc.)
                + b"\x00"    # Cipher Suite length (minimal)
            )
            sport = random.randint(1024, 65535)
            seq = random.randint(0, 2**32 - 1)
            tcp_layer = scapy.TCP(
                dport=port,
                sport=sport,
                flags="S",
                seq=seq
            )
            pkt = ip_layer / tcp_layer / scapy.Raw(load=tls_payload)
            resp = scapy.sr1(pkt, timeout=self.timeout_scan, verbose=0)
            if resp and resp.haslayer(scapy.TCP):
                flags = int(resp[scapy.TCP].flags)
                if (flags & 0x12) == 0x12:
                    rst_pkt = ip_layer / scapy.TCP(dport=port, sport=sport, flags="R", seq=seq+1)
                    scapy.send(rst_pkt, verbose=0)
                    return "open", resp
                elif (flags & 0x04) == 0x04:
                    return "closed", resp
            return "filtered", None

        loop = asyncio.get_running_loop()
        state, resp = await loop.run_in_executor(None, do_tls_echo_mask_probe)
        async with self.lock:
            self.results[port].tcp_states[ScanType.TLSECHO] = state
            if state == "open" and resp is not None:
                self.os_fingerprint(port, resp)

    # -------------------- OS FINGERPRINTING --------------------
    def os_fingerprint(self, port: int, resp):
        if not resp.haslayer(scapy.TCP):
            return
        ip4 = resp.getlayer(scapy.IP)
        ip6 = resp.getlayer(scapy.IPv6)
        ttl_or_hlim = ip4.ttl if ip4 else ip6.hlim if ip6 else None
        if ttl_or_hlim is None:
            return
        tcp_layer = resp[scapy.TCP]
        options = tcp_layer.options
        os_guess = "Unknown"
        if ttl_or_hlim <= 64:
            os_guess = "Linux/Unix"
        elif ttl_or_hlim <= 128:
            os_guess = "Windows"
        else:
            os_guess = "Solaris/Cisco"
        if options:
            opts = dict((o[0], o[1]) for o in options if isinstance(o, tuple))
            if 'Timestamp' in opts:
                os_guess = "Linux/Unix (Timestamp)"
            elif 'MSS' in opts and opts['MSS'] == 1460:
                os_guess = "Linux/Unix"
        self.results[port].os_guess = os_guess

    async def banner_grabbing(self, port: int):
        def do_banner():
            try:
                with socket.create_connection((self.target_ip, port), timeout=self.timeout_connect) as sock:
                    service_guess = self.results[port].service.lower()
                    if "http" in service_guess:
                        req = f"GET / HTTP/1.1\r\nHost: {self.target_ip}\r\n\r\n".encode()
                    elif "ftp" in service_guess:
                        req = b"USER anonymous\r\n"
                    elif "ssh" in service_guess:
                        req = b"SSH-2.0-QuantumScanner\r\n"
                    else:
                        req = b"HEAD / HTTP/1.0\r\n\r\n"
                    sock.sendall(req)
                    sock.settimeout(self.timeout_banner)
                    banner = sock.recv(1024)
                    return banner.decode(errors="ignore")
            except Exception as e:
                logging.debug(f"Banner grab failed on port {port}: {e}")
                return ""
        loop = asyncio.get_running_loop()
        banner_str = await loop.run_in_executor(None, do_banner)
        if banner_str:
            async with self.lock:
                self.results[port].banner = banner_str[:256]
                if "220" in banner_str and "ftp" in banner_str.lower():
                    self.results[port].service = "FTP"

    async def adaptive_delay(self):
        if len(self.history) > 10:
            avg_delay = sum(self.history) / len(self.history)
            self.adaptation_factor = max(0.5, min(2.0, avg_delay * 1.2))
        base_delay = 1.0 / self.max_rate
        delay = base_delay * self.adaptation_factor
        self.history.append(delay)
        await asyncio.sleep(delay)

    # -------------------- SERVICE FINGERPRINTING, VULNS --------------------
    def service_fingerprinting(self):
        service_map = {
            80: "HTTP",
            443: "HTTPS",
            53: "DNS",
            22: "SSH",
            25: "SMTP",
            3389: "RDP",
        }
        for port, result in self.results.items():
            if not result.service:
                result.service = service_map.get(port, "unknown")
            if result.banner:
                b = result.banner.lower()
                if "ssh" in b:
                    result.service = "SSH"
                elif "http" in b:
                    result.service = "HTTP"

    def analyze_vulnerabilities(self):
        vuln_db = {
            "apache/2.4.49": ["CVE-2021-41773 (Path Traversal)"],
            "openssh_8.0": ["CVE-2021-41617 (SSH Agent Vulnerability)"],
            "iis/10.0": ["CVE-2020-0601 (CurveBall)"],
        }
        for port, result in self.results.items():
            version_lower = result.version.lower()
            banner_lower = result.banner.lower()
            for known_sig, vulns in vuln_db.items():
                if known_sig in version_lower or known_sig in banner_lower:
                    result.vulns.extend(vulns)
            if result.service == "SSL/TLS" and "tlsv1.0" in result.version.lower():
                result.vulns.append("Weak TLS version (TLSv1.0)")

    def parse_certificate(self, cert_bin: bytes) -> Dict:
        try:
            cert_obj = x509.load_der_x509_certificate(cert_bin, default_backend())
            return {
                "subject": cert_obj.subject.rfc4514_string(),
                "issuer": cert_obj.issuer.rfc4514_string(),
                "version": cert_obj.version.name,
                "serial": str(cert_obj.serial_number),
                "not_valid_before": str(cert_obj.not_valid_before),
                "not_valid_after": str(cert_obj.not_valid_after),
                "signature_algorithm": cert_obj.signature_algorithm_oid._name,
            }
        except Exception as e:
            logging.debug(f"parse_certificate error: {e}")
            return {}

    def check_ssl_vulnerabilities(self, cert_info: Dict) -> List[str]:
        vulns = []
        if cert_info.get("signature_algorithm") == "sha1WithRSAEncryption":
            vulns.append("Weak signature (SHA1)")
        return vulns

    # -------------------- REPORTING --------------------
    def generate_report(self):
        table = Table(title="Quantum Scan Results", show_lines=True)
        table.add_column("Port", style="cyan")
        table.add_column("TCP States", style="magenta")
        table.add_column("UDP State", style="magenta")
        table.add_column("Filtering", style="magenta")
        table.add_column("Service", style="green")
        table.add_column("Version")
        table.add_column("Vulnerabilities")
        table.add_column("OS Guess", style="yellow")
        for port, result in sorted(self.results.items()):
            tcp_states_str = ", ".join(f"{st.value}: {val}" for st, val in result.tcp_states.items())
            vulns_str = "\n".join(result.vulns) if result.vulns else ""
            table.add_row(
                str(port),
                tcp_states_str or "",
                result.udp_state,
                result.filtering,
                result.service,
                result.version,
                vulns_str,
                result.os_guess
            )
        console.print(table)
        self.print_statistics()
        if self.json_output:
            self.dump_results_json()

    def print_statistics(self):
        open_tcp_ports = [p for p, r in self.results.items()
                          if any(st == "open" for st in r.tcp_states.values())]
        open_udp_ports = [p for p, r in self.results.items() if r.udp_state == "open"]
        total_vulns = sum(len(r.vulns) for r in self.results.values())
        console.print(f"\n[bold]Scan Statistics:[/]")
        console.print(f"Open TCP ports: {len(open_tcp_ports)} => {open_tcp_ports}")
        console.print(f"Open UDP ports: {len(open_udp_ports)} => {open_udp_ports}")
        console.print(f"Vulnerabilities found: {total_vulns}")

    def dump_results_json(self):
        import json
        out_data = {}
        for port, result in self.results.items():
            out_data[port] = {
                "tcp_states": {k.value: v for k, v in result.tcp_states.items()},
                "udp_state": result.udp_state,
                "filtering": result.filtering,
                "service": result.service,
                "version": result.version,
                "vulns": result.vulns,
                "cert_info": result.cert_info,
                "banner": result.banner,
                "os_guess": result.os_guess,
            }
        with open("scan_results.json", "w") as fh:
            json.dump(out_data, fh, indent=4)
        console.print("[green]Results written to scan_results.json[/green]")

# ---------------------- UTILITIES ------------------------
def parse_ports(port_input: str) -> List[int]:
    ports = []
    if port_input.isdigit():
        p = int(port_input)
        if 1 <= p <= 65535:
            return [p]
        raise ValueError(f"Invalid port: {p}")
    for part in port_input.split(","):
        part = part.strip()
        if "-" in part:
            start, end = map(int, part.split("-"))
            if not (1 <= start <= end <= 65535):
                raise ValueError(f"Invalid range: {part}")
            ports.extend(range(start, end + 1))
        elif part.isdigit():
            p = int(part)
            if 1 <= p <= 65535:
                ports.append(p)
            else:
                raise ValueError(f"Invalid port: {p}")
        else:
            raise ValueError(f"Invalid port spec: {part}")
    return sorted(set(ports))

# ---------------------- MAIN ------------------------
if __name__ == "__main__":
    parser = ArgumentParser(description="Quantum Port Scanner with Improved Scan Methods")
    parser.add_argument("target", help="Target hostname or IP")
    parser.add_argument("-p", "--ports", required=True, help="e.g. 80, 1-100, 22,80")
    parser.add_argument("-s", "--scan-types", nargs="+", default=["syn"],
                        choices=[st.value for st in ScanType],
                        help="scan methods (syn ssl udp ack fin xmas null window tls_echo)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose logging")
    parser.add_argument("-e", "--evasions", action="store_true", help="Enable fragmentation/TTL changes")
    parser.add_argument("--ipv6", action="store_true", help="Use IPv6 scanning")
    parser.add_argument("--json-output", action="store_true", help="Output results to JSON")
    parser.add_argument("--shuffle-ports", action="store_true", help="Randomize port list")
    parser.add_argument("--log-file", default="scanner.log", help="Log file path")
    parser.add_argument("--max-rate", type=int, default=500, help="Max pkts/sec")
    parser.add_argument("--concurrency", type=int, default=100, help="Concurrent tasks")

    # Add timeout configuration
    parser.add_argument("--timeout-scan", type=float, default=3.0, 
                       help="Timeout for scan packets (seconds)")
    parser.add_argument("--timeout-connect", type=float, default=3.0, 
                       help="Timeout for TCP connections (seconds)")
    parser.add_argument("--timeout-banner", type=float, default=3.0, 
                       help="Timeout for banner grabbing (seconds)")

    args = parser.parse_args()
    logging.getLogger().handlers.clear()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        handlers=[logging.FileHandler(args.log_file), logging.StreamHandler()],
    )
    try:
        ports = parse_ports(args.ports)
    except ValueError as exc:
        logging.error(f"Invalid ports: {exc}")
        sys.exit(1)
    scanner = QuantumScanner(
        target=args.target,
        ports=ports,
        scan_types=[ScanType(st) for st in args.scan_types],
        concurrency=args.concurrency,
        max_rate=args.max_rate,
        evasions=args.evasions,
        verbose=args.verbose,
        use_ipv6=args.ipv6,
        json_output=args.json_output,
        shuffle_ports=args.shuffle_ports,
        timeout_scan=args.timeout_scan,
        timeout_connect=args.timeout_connect,
        timeout_banner=args.timeout_banner
    )
    asyncio.run(scanner.run_scan())
