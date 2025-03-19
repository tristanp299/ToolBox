#!/usr/bin/env python3
import asyncio
import logging
import random
import socket
import ssl
import sys
import os
import time
import threading
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
    TLSECHO = "tls_echo"
    # -- New ScanTypes --
    MIMIC = "mimic"  # Protocol Mimic Scan
    FRAG = "frag"    # Advanced Fragmented SYN Scan

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

# A dictionary of protocol "mimic" payloads
MIMIC_PAYLOADS = {
    "HTTP": b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
    "SSH": b"SSH-2.0-OpenSSH_8.2\r\n",
    "FTP": b"220 FTP Server Ready\r\n",
    "SMTP": b"220 mail.example.com ESMTP\r\n",
    "IMAP": b"* OK IMAP4rev1 Service Ready\r\n",
    "POP3": b"+OK POP3 server ready\r\n",
    # Add more if needed
}

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
        timeout_banner: float = 3.0,
        # --- Additional arguments for mimic & fragment scans ---
        mimic_protocol: str = "HTTP",
        frag_min_size: int = 16,
        frag_max_size: int = 64,
        frag_min_delay: float = 0.01,
        frag_max_delay: float = 0.1,
        frag_timeout: int = 10
    ):
        self.use_ipv6 = use_ipv6
        self.json_output = json_output
        self.shuffle_ports = shuffle_ports
        self.timeout_scan = timeout_scan
        self.timeout_connect = timeout_connect
        self.timeout_banner = timeout_banner
        self.mimic_protocol = mimic_protocol
        # Ensure min fragment size is large enough to hold TCP header
        self.frag_min_size = max(frag_min_size, 24)
        self.frag_max_size = max(frag_max_size, self.frag_min_size)
        self.frag_min_delay = frag_min_delay
        self.frag_max_delay = frag_max_delay
        self.frag_timeout = frag_timeout

        # Resolve target IP
        if not self.use_ipv6:
            self.target_ip = socket.gethostbyname(target)
            try:
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
                elif st == ScanType.MIMIC:
                    await self.mimic_scan(port, self.mimic_protocol)
                elif st == ScanType.FRAG:
                    await self.fragmented_syn_scan(
                        port,
                        self.frag_min_size,
                        self.frag_max_size,
                        self.frag_min_delay,
                        self.frag_max_delay,
                        self.frag_timeout
                    )

                # If an open TCP port is detected, attempt banner grabbing immediately
                if any(state == "open" for state in self.results[port].tcp_states.values()):
                    await self.banner_grabbing(port)

                await self.adaptive_delay()

        progress.update(task, advance=len(self.scan_types))

    # -------------------- COMMON BUILDERS --------------------
    def build_ip_layer(self):
        """
        Builds an IPv4 or IPv6 layer with the appropriate source and
        destination addresses. If self.local_ip is None, we let Scapy pick.
        """
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
        """Sets TTL (IPv4) or hlim (IPv6) to a default or random value if evasions are enabled."""
        if self.use_ipv6:
            ip_layer.hlim = random.choice([64, 128, 255]) if self.evasions else 64
        else:
            ip_layer.ttl = random.choice([64, 128, 255]) if self.evasions else 64

    # -------------------- SCAN METHODS --------------------
    async def syn_scan(self, port: int, max_tries=3):
        """Performs a SYN scan."""
        def do_syn_probe():
            for _ in range(max_tries):
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
                        # Send RST to close half-open
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
        """Performs an ACK scan (checks filtering)."""
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
        """Performs a FIN scan."""
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
        """Performs an XMAS scan (FIN+PSH+URG flags)."""
        def do_xmas_probe():
            ip_layer = self.build_ip_layer()
            self.set_ip_ttl_or_hlim(ip_layer)
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
        """Performs a NULL scan (no flags)."""
        def do_null_probe():
            ip_layer = self.build_ip_layer()
            self.set_ip_ttl_or_hlim(ip_layer)
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
        """Performs a Window scan."""
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
        """Performs a basic UDP scan (tries not to rely on ICMP)."""
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
        """Attempts an SSL/TLS connection, capturing the certificate info if successful."""
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
        """TLS Echo Mask Scan: minimal TLS payload in a SYN packet."""
        def do_tls_echo_mask_probe():
            ip_layer = self.build_ip_layer()
            self.set_ip_ttl_or_hlim(ip_layer)
            tls_payload = (
                b"\x16"      # Content Type: Handshake
                b"\x03\x03"  # TLS 1.2
                b"\x00\x2f"  # length
                b"\x02"      # Handshake Type: Server Hello
                b"\x00\x00\x2b"  # Handshake length
                b"\x03\x03"  # Version repeated
                + os.urandom(32)  # Random
                + b"\x00"    # minimal
            )
            sport = random.randint(1024, 65535)
            seq = random.randint(0, 2**32 - 1)
            tcp_layer = scapy.TCP(dport=port, sport=sport, flags="S", seq=seq)
            pkt = ip_layer / tcp_layer / scapy.Raw(load=tls_payload)
            resp = scapy.sr1(pkt, timeout=3.0, verbose=0)
            if resp and resp.haslayer(scapy.TCP):
                flags = int(resp[scapy.TCP].flags)
                if (flags & 0x12) == 0x12:
                    # RST to close
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

    # -------------------- MIMIC SCAN --------------------
    async def mimic_scan(self, port: int, protocol: str, max_tries=3):
        """
        Sends a SYN packet with partial protocol-mimicking data and checks for open/closed/filtered.
        """
        def do_mimic_probe():
            if protocol not in MIMIC_PAYLOADS:
                # Fall back to basic "HTTP" if unknown
                mimic_data = b""
                logging.warning(f"Unknown protocol '{protocol}', using empty payload.")
            else:
                mimic_data = MIMIC_PAYLOADS[protocol]

            ip_layer = self.build_ip_layer()
            self.set_ip_ttl_or_hlim(ip_layer)
            sport = random.randint(1024, 65535)
            seq = random.randint(0, 2**32 - 1)

            for _ in range(max_tries):
                tcp_layer = scapy.TCP(dport=port, sport=sport, flags="S", seq=seq)
                pkt = ip_layer / tcp_layer / scapy.Raw(load=mimic_data[:16])
                resp = scapy.sr1(pkt, timeout=self.timeout_scan, verbose=0)

                if resp and resp.haslayer(scapy.TCP):
                    flags = int(resp[scapy.TCP].flags)
                    if (flags & 0x12) == 0x12:
                        rst_pkt = ip_layer / scapy.TCP(dport=port, sport=sport, flags="R", seq=seq+1)
                        scapy.send(rst_pkt, verbose=0)
                        return "open"
                    elif (flags & 0x04) == 0x04:
                        return "closed"

            return "filtered"

        loop = asyncio.get_running_loop()
        state = await loop.run_in_executor(None, do_mimic_probe)
        async with self.lock:
            self.results[port].tcp_states[ScanType.MIMIC] = state

    # -------------------- FRAGMENTED SYN SCAN (BRANCHED) --------------------
    async def fragmented_syn_scan(
        self,
        port: int,
        min_frag_size: int,
        max_frag_size: int,
        min_delay: float,
        max_delay: float,
        timeout: int,
        max_tries: int = 3
    ):
        """
        Perform a Fragmented SYN Scan. If IPv4, set 'ttl'; if IPv6, set 'hlim'. 
        Attempt multiple tries to reduce misclassifications. 
        """

        def do_frag_scan():
            ip_id = random.randint(1, 65535)
            ip_layer = self.build_ip_layer()
            self.set_ip_ttl_or_hlim(ip_layer)

            # Build a SYN packet with some data
            base_tcp = scapy.TCP(
                dport=port,
                sport=random.randint(1024, 65535),
                flags="S",
                seq=random.randint(0, 2**32 - 1)
            )
            payload_data = b"A" * 200

            # Convert to raw and re-parse so IPv4 sets ihl, etc.
            full_syn = ip_layer / base_tcp / scapy.Raw(load=payload_data)
            raw_syn = bytes(full_syn)

            if not self.use_ipv6:
                parsed_syn = scapy.IP(raw_syn)
                ip_header_len = parsed_syn.ihl * 4
            else:
                parsed_syn = scapy.IPv6(raw_syn)
                ip_header_len = 40  # Standard for IPv6 main header

            # Slice out TCP + data
            ip_payload = raw_syn[ip_header_len:]
            total_size = len(ip_payload)

            final_state = ["filtered"]
            sniff_filter = f"tcp and host {self.target_ip} and port {port}"

            def capture_response(pkt):
                if (pkt.haslayer(scapy.TCP) and
                    pkt[scapy.IP].src == self.target_ip and
                    pkt[scapy.TCP].sport == port):
                    flags = pkt[scapy.TCP].flags
                    if (flags & 0x12) == 0x12:
                        final_state[0] = "open"
                    elif (flags & 0x04) == 0x04:
                        final_state[0] = "closed"

            def send_fragments():
                offset_bytes = 0
                remain = total_size

                while remain > 0:
                    # First fragment must be large enough for TCP header
                    if offset_bytes == 0:
                        frag_size = max(24, random.randint(min_frag_size, max_frag_size))
                    else:
                        frag_size = random.randint(min_frag_size, max_frag_size)

                    if frag_size > remain:
                        frag_size = remain

                    more_frag = "MF" if (frag_size < remain) else 0
                    frag_data = ip_payload[offset_bytes : offset_bytes + frag_size]

                    if not self.use_ipv6:
                        # IPv4 fragment
                        fragment = scapy.IP(
                            dst=ip_layer.dst,
                            src=ip_layer.src,
                            id=ip_id,
                            flags=more_frag,
                            frag=(offset_bytes // 8),
                            ttl=ip_layer.ttl
                        ) / frag_data
                    else:
                        # IPv6 fragment
                        fragment = scapy.IPv6(
                            dst=ip_layer.dst,
                            src=ip_layer.src,
                            hlim=ip_layer.hlim,
                            nh=6,  # TCP
                            fl=0
                        ) / frag_data
                        fragment[scapy.IPv6].frag = (offset_bytes // 8)
                        if frag_size < remain:
                            fragment[scapy.IPv6].flags = 1  # "More fragments" if needed

                    scapy.send(fragment, verbose=0)
                    offset_bytes += frag_size
                    remain -= frag_size
                    time.sleep(random.uniform(min_delay, max_delay))

            for _ in range(max_tries):
                final_state[0] = "filtered"
                sniff_thread = threading.Thread(
                    target=scapy.sniff,
                    kwargs={
                        'filter': sniff_filter,
                        'prn': capture_response,
                        'timeout': timeout,
                        'store': False
                    }
                )
                sniff_thread.start()

                # Send all fragments
                send_fragments()

                sniff_thread.join()
                if final_state[0] in ["open", "closed"]:
                    break

            return final_state[0]

        loop = asyncio.get_running_loop()
        state = await loop.run_in_executor(None, do_frag_scan)
        async with self.lock:
            self.results[port].tcp_states[ScanType.FRAG] = state

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
        """Attempt banner grabbing on an open TCP port."""
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
                # Quick guess to override service if we see known text
                if "220" in banner_str and "ftp" in banner_str.lower():
                    self.results[port].service = "FTP"

    async def adaptive_delay(self):
        """Rate-limits or paces out scanning based on historical timings."""
        if len(self.history) > 10:
            avg_delay = sum(self.history) / len(self.history)
            self.adaptation_factor = max(0.5, min(2.0, avg_delay * 1.2))
        base_delay = 1.0 / self.max_rate
        delay = base_delay * self.adaptation_factor
        self.history.append(delay)
        await asyncio.sleep(delay)

    # -------------------- SERVICE FINGERPRINTING, VULNS --------------------
    def service_fingerprinting(self):
        """Heuristic or known-port mapping to fill in 'service' if none."""
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
        """Basic pattern-based vulnerability matching."""
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
            # Example TLS 1.0 vulnerability
            if result.service == "SSL/TLS" and "tlsv1.0" in result.version.lower():
                result.vulns.append("Weak TLS version (TLSv1.0)")

    def parse_certificate(self, cert_bin: bytes) -> Dict:
        """Parse DER or PEM certificate into a dictionary."""
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
        """Example checks for SSL vulnerabilities."""
        vulns = []
        if cert_info.get("signature_algorithm") == "sha1WithRSAEncryption":
            vulns.append("Weak signature (SHA1)")
        return vulns

    # -------------------- REPORTING --------------------
    def generate_report(self):
        """Display results in a Rich table, then possibly write JSON."""
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
    parser = ArgumentParser(description="Quantum Port Scanner with Additional Scan Methods")
    parser.add_argument("target", help="Target hostname or IP")
    parser.add_argument("-p", "--ports", required=True, help="e.g. 80, 1-100, 22,80")
    parser.add_argument("-s", "--scan-types", nargs="+", default=["syn"],
                        choices=[st.value for st in ScanType],
                        help="scan methods (syn ssl udp ack fin xmas null window tls_echo mimic frag)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose logging")
    parser.add_argument("-e", "--evasions", action="store_true", help="Enable fragmentation/TTL changes")
    parser.add_argument("--ipv6", action="store_true", help="Use IPv6 scanning")
    parser.add_argument("--json-output", action="store_true", help="Output results to JSON")
    parser.add_argument("--shuffle-ports", action="store_true", help="Randomize port list")
    parser.add_argument("--log-file", default="scanner.log", help="Log file path")
    parser.add_argument("--max-rate", type=int, default=500, help="Max pkts/sec")
    parser.add_argument("--concurrency", type=int, default=100, help="Concurrent tasks")

    # Timeout arguments
    parser.add_argument("--timeout-scan", type=float, default=3.0,
                       help="Timeout for scan packets (seconds)")
    parser.add_argument("--timeout-connect", type=float, default=3.0,
                       help="Timeout for TCP connections (seconds)")
    parser.add_argument("--timeout-banner", type=float, default=3.0,
                       help="Timeout for banner grabbing (seconds)")

    # ---------------- NEW FLAGS FOR MIMIC & FRAGMENT SCANS ----------------
    parser.add_argument("--mimic-protocol", default="HTTP",
                        help="Protocol to mimic (HTTP, SSH, FTP, etc.) when using 'mimic' scan type.")

    parser.add_argument("--frag-min-size", type=int, default=16,
                        help="Minimum fragment size in bytes (multiple of 8) for 'frag' scan.")
    parser.add_argument("--frag-max-size", type=int, default=64,
                        help="Maximum fragment size in bytes (multiple of 8) for 'frag' scan.")
    parser.add_argument("--frag-min-delay", type=float, default=0.01,
                        help="Minimum delay (seconds) between sending fragments for 'frag' scan.")
    parser.add_argument("--frag-max-delay", type=float, default=0.1,
                        help="Maximum delay (seconds) between sending fragments for 'frag' scan.")
    parser.add_argument("--frag-timeout", type=int, default=10,
                        help="Sniffing timeout (seconds) for 'frag' scan response capture.")

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
        timeout_banner=args.timeout_banner,
        mimic_protocol=args.mimic_protocol,
        frag_min_size=args.frag_min_size,
        frag_max_size=args.frag_max_size,
        frag_min_delay=args.frag_min_delay,
        frag_max_delay=args.frag_max_delay,
        frag_timeout=args.frag_timeout
    )
    asyncio.run(scanner.run_scan())
