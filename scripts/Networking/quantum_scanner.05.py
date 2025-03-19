#!/usr/bin/env python3
import asyncio
import logging
import random
import socket
import ssl
import sys
import os
import time
from argparse import ArgumentParser
from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional

import scapy.all as scapy
from scapy.all import AsyncSniffer
from scapy.error import Scapy_Exception

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from rich.console import Console
from rich.progress import Progress
from rich.table import Table

# ---------------------- GLOBAL CONFIG -----------------------
scapy.conf.verb = 0  # Make Scapy silent
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
        shuffle_ports: bool = False
    ):
        """
        :param target: Target hostname or IP
        :param ports: List of ports to scan
        :param scan_types: List of scan types (SYN, SSL, etc.)
        :param concurrency: Number of ports to probe concurrently
        :param max_rate: Max packets per second
        :param evasions: Whether to enable packet fragmentation, random TTL, etc.
        :param verbose: Debug-level logging
        :param use_ipv6: Use IPv6 for scanning
        :param json_output: Output results to JSON file upon completion
        :param shuffle_ports: Randomize the order in which ports are scanned
        """
        self.use_ipv6 = use_ipv6
        self.json_output = json_output
        self.shuffle_ports = shuffle_ports
        self.src_ports = {}  # {src_port: target_port} for response matching

        # Resolve target IP
        if not self.use_ipv6:
            self.target_ip = socket.gethostbyname(target)
            try:
                self.local_ip = scapy.conf.route.route("0.0.0.0")[1]
            except Exception:
                self.local_ip = "0.0.0.0"
        else:
            info = socket.getaddrinfo(target, None, socket.AF_INET6)
            self.target_ip = info[0][4][0]
            self.local_ip = "::"

        # Optional random shuffle of ports
        if self.shuffle_ports:
            random.shuffle(ports)
        self.ports = ports

        self.scan_types = scan_types
        self.concurrency = concurrency
        self.max_rate = max_rate
        self.evasions = evasions
        self.verbose = verbose
        self.results: Dict[int, PortResult] = {}

        # Simple adaptive rate-limiting
        self.adaptation_factor = 1.0
        self.history = deque(maxlen=100)
        self.lock = asyncio.Lock()

        # SSL context
        self.ctx = ssl.create_default_context()
        self.ctx.check_hostname = False
        self.ctx.verify_mode = ssl.CERT_NONE

        # Warn if evasions are requested but not running as root
        if self.evasions and os.geteuid() != 0:
            logging.error("Evasion techniques require root privileges! Exiting.")
            sys.exit(1)

        # Set logging level
        if self.verbose:
            logging.getLogger().setLevel(logging.DEBUG)

        # Capture packets in memory
        self.captured_packets: List[scapy.Packet] = []
        self.sniffer: Optional[AsyncSniffer] = None

    # ---------------------- SNIFFER CONTROL ----------------------
    def start_sniffer(self):
        """
        Starts a background sniffer to capture and store packets in self.captured_packets.
        """
        bpf_filter = "(tcp or udp or icmp)"
        def handle_packet(packet):
            self.captured_packets.append(packet)

        # Scapy will pick the default interface automatically
        self.sniffer = AsyncSniffer(
            filter=bpf_filter,
            prn=handle_packet,
            store=False
        )
        self.sniffer.start()

    def stop_sniffing(self):
        """
        Stops the async sniffer if it is running. We do NOT call .join() to avoid hangs
        if the sniffer is in an unsupported or offline state.
        """
        if self.sniffer is not None:
            try:
                self.sniffer.stop()
            except Scapy_Exception as ex:
                logging.warning(f"Error stopping sniffer: {ex}")
            self.sniffer = None

    # ---------------------- MAIN FLOW ----------------------
    async def run_scan(self):
        logging.info(f"Starting scan against {self.target_ip}")
        for port in self.ports:
            self.results[port] = PortResult()

        self.start_sniffer()

        with Progress() as progress:
            total_tasks = len(self.ports) * len(self.scan_types)
            task = progress.add_task("[cyan]Scanning...", total=total_tasks)
            semaphore = asyncio.Semaphore(self.concurrency)

            # Launch tasks for each port
            tasks = []
            for port in self.ports:
                tasks.append(asyncio.create_task(self.scan_port(port, progress, task, semaphore)))
            await asyncio.gather(*tasks)

        self.stop_sniffing()
        self.service_fingerprinting()
        self.analyze_vulnerabilities()
        logging.info("Scan completed. Generating report...")
        self.generate_report()

    async def scan_port(self, port: int, progress, task, semaphore: asyncio.Semaphore):
        async with semaphore:
            for st in self.scan_types:
                if st == ScanType.SYN:
                    await self.syn_scan(port, progress, task)
                elif st == ScanType.SSL:
                    await self.ssl_probe(port, progress, task)
                elif st == ScanType.UDP:
                    await self.udp_scan(port, progress, task)
                elif st == ScanType.ACK:
                    await self.ack_scan(port, progress, task)
                elif st == ScanType.FIN:
                    await self.fin_scan(port, progress, task)
                elif st == ScanType.XMAS:
                    await self.xmas_scan(port, progress, task)
                elif st == ScanType.NULL:
                    await self.null_scan(port, progress, task)
                elif st == ScanType.WINDOW:
                    await self.window_scan(port, progress, task)

                await self.adaptive_delay()

            # If at least one TCP scan found the port open, attempt banner grab
            tcp_states = self.results[port].tcp_states.values()
            if any(state == "open" for state in tcp_states):
                await self.banner_grabbing(port)

    # -------------------- SCAN METHODS -----------------------
    async def syn_scan(self, port: int, progress, task, max_retries=3):
        logging.debug(f"SYN scan on port {port}")
        state = "filtered"
        for attempt in range(max_retries + 1):
            try:
                if self.evasions:
                    await self.send_fragmented_packet(port, "S")
                else:
                    await self.send_packet(port, "S")

                responses = await self.find_responses(port, timeout=5)
                attempt_state = self.determine_syn_state(responses)
                if attempt_state != "filtered":
                    state = attempt_state
                    if state == "open":
                        self.os_fingerprint(port, responses)
                    break
                elif attempt < max_retries:
                    logging.debug(f"Retrying SYN scan on port {port} (attempt {attempt+1})")
                    await asyncio.sleep(1)
            except Exception as e:
                logging.error(f"SYN scan failed on port {port}: {e}")
                break

        async with self.lock:
            self.results[port].tcp_states[ScanType.SYN] = state
        progress.update(task, advance=1)

    async def ack_scan(self, port: int, progress, task):
        logging.debug(f"ACK scan on port {port}")
        try:
            if self.evasions:
                await self.send_fragmented_packet(port, "A")
            else:
                await self.send_packet(port, "A")

            responses = await self.find_responses(port, timeout=3)
            filtering = "filtered"
            for pkt in responses:
                if pkt.haslayer(scapy.TCP):
                    flags = pkt[scapy.TCP].flags
                    # RST => unfiltered
                    if flags & 0x04:
                        filtering = "unfiltered"
                        break
            async with self.lock:
                self.results[port].filtering = filtering
        except Exception as e:
            logging.debug(f"ACK scan error on port {port}: {e}")
        finally:
            progress.update(task, advance=1)

    async def fin_scan(self, port: int, progress, task):
        logging.debug(f"FIN scan on port {port}")
        try:
            if self.evasions:
                await self.send_fragmented_packet(port, "F")
            else:
                await self.send_packet(port, "F")

            responses = await self.find_responses(port, timeout=3)
            state = "open|filtered"
            if responses:
                pkt = responses[0]
                if pkt.haslayer(scapy.TCP) and (pkt[scapy.TCP].flags & 0x04):
                    state = "closed"
            async with self.lock:
                self.results[port].tcp_states[ScanType.FIN] = state
        except Exception as e:
            logging.debug(f"FIN scan error on port {port}: {e}")
        finally:
            progress.update(task, advance=1)

    async def xmas_scan(self, port: int, progress, task):
        logging.debug(f"XMAS scan on port {port}")
        try:
            src_port = random.randint(1024, 65535)
            self.src_ports[src_port] = port
            pkt = self.build_ip_layer()/scapy.TCP(
                sport=src_port,
                dport=port,
                flags="FPU",
                seq=random.randint(0, 2**32 - 1),
                ttl=random.choice([64, 128, 255])
            )
            if self.evasions:
                for frag in scapy.fragment(pkt):
                    scapy.send(frag, verbose=0)
                    await asyncio.sleep(random.uniform(0.01, 0.05))
            else:
                scapy.send(pkt, verbose=0)

            responses = await self.find_responses(port, timeout=3)
            state = "open|filtered"
            if responses:
                pkt = responses[0]
                if pkt.haslayer(scapy.TCP) and (pkt[scapy.TCP].flags & 0x04):
                    state = "closed"
            async with self.lock:
                self.results[port].tcp_states[ScanType.XMAS] = state
        except Exception as e:
            logging.debug(f"XMAS scan error on port {port}: {e}")
        finally:
            progress.update(task, advance=1)

    async def null_scan(self, port: int, progress, task):
        logging.debug(f"NULL scan on port {port}")
        try:
            src_port = random.randint(1024, 65535)
            self.src_ports[src_port] = port
            pkt = self.build_ip_layer()/scapy.TCP(
                sport=src_port,
                dport=port,
                flags=0,
                seq=random.randint(0, 2**32 - 1),
                ttl=random.choice([64, 128, 255])
            )
            if self.evasions:
                for frag in scapy.fragment(pkt):
                    scapy.send(frag, verbose=0)
                    await asyncio.sleep(random.uniform(0.01, 0.05))
            else:
                scapy.send(pkt, verbose=0)

            responses = await self.find_responses(port, timeout=3)
            state = "open|filtered"
            if responses:
                pkt = responses[0]
                if pkt.haslayer(scapy.TCP) and (pkt[scapy.TCP].flags & 0x04):
                    state = "closed"
            async with self.lock:
                self.results[port].tcp_states[ScanType.NULL] = state
        except Exception as e:
            logging.debug(f"NULL scan error on port {port}: {e}")
        finally:
            progress.update(task, advance=1)

    async def window_scan(self, port: int, progress, task):
        logging.debug(f"WINDOW scan on port {port}")
        try:
            await self.send_packet(port, "A")
            responses = await self.find_responses(port, timeout=3)
            state = "filtered"
            for pkt in responses:
                if pkt.haslayer(scapy.TCP):
                    tcp = pkt[scapy.TCP]
                    if tcp.window != 0:
                        state = "open"
                    else:
                        state = "closed"
                    break
            async with self.lock:
                self.results[port].tcp_states[ScanType.WINDOW] = state
        except Exception as e:
            logging.debug(f"WINDOW scan error on port {port}: {e}")
        finally:
            progress.update(task, advance=1)

    async def udp_scan(self, port: int, progress, task):
        logging.debug(f"UDP scan on port {port}")
        try:
            src_port = random.randint(1024, 65535)
            self.src_ports[src_port] = port
            pkt = self.build_ip_layer()/scapy.UDP(sport=src_port, dport=port)/b"probe"
            scapy.send(pkt, verbose=0)
            await asyncio.sleep(random.uniform(0.01, 0.05))

            responses = await self.find_responses(port, timeout=3)
            if not responses:
                async with self.lock:
                    self.results[port].udp_state = "open|filtered"
            else:
                pkt = responses[0]
                if pkt.haslayer(scapy.UDP):
                    async with self.lock:
                        self.results[port].udp_state = "open"
                elif pkt.haslayer(scapy.ICMP):
                    icmp = pkt[scapy.ICMP]
                    if icmp.type == 3 and icmp.code == 3:
                        async with self.lock:
                            self.results[port].udp_state = "closed"
                    else:
                        async with self.lock:
                            self.results[port].udp_state = "filtered"
        except Exception as e:
            logging.debug(f"UDP scan error on port {port}: {e}")
        finally:
            progress.update(task, advance=1)

    async def ssl_probe(self, port: int, progress, task):
        logging.debug(f"SSL probe on port {port}")
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.target_ip, port, ssl=self.ctx, server_hostname=self.target_ip),
                timeout=2
            )
            ssl_obj = writer.get_extra_info("ssl_object")
            if not ssl_obj:
                async with self.lock:
                    self.results[port].tcp_states[ScanType.SSL] = "closed"
                return

            cert_bin = ssl_obj.getpeercert(binary_form=True)
            cert_info = self.parse_certificate(cert_bin) if cert_bin else {}
            vulns = self.check_ssl_vulnerabilities(cert_info)
            ssl_version = writer.get_extra_info("ssl_version")

            async with self.lock:
                self.results[port].tcp_states[ScanType.SSL] = "open"
                self.results[port].service = "SSL/TLS"
                self.results[port].version = ssl_version or ""
                self.results[port].cert_info = cert_info
                self.results[port].vulns.extend(vulns)

            writer.close()
            await writer.wait_closed()
        except (ConnectionRefusedError, asyncio.TimeoutError):
            async with self.lock:
                self.results[port].tcp_states[ScanType.SSL] = "closed"
        except Exception as e:
            logging.debug(f"SSL probe failed on port {port}: {e}")
        finally:
            progress.update(task, advance=1)

    def determine_syn_state(self, responses: List[scapy.Packet]) -> str:
        """
        Determine how to classify the port state based on the sniffed responses
        to a SYN probe.
        """
        if not responses:
            return "filtered"
        for pkt in responses:
            if pkt.haslayer(scapy.TCP):
                tcp = pkt[scapy.TCP]
                # SYN/ACK => open
                if (tcp.flags & 0x12) == 0x12:
                    return "open"
                # RST => closed
                elif (tcp.flags & 0x04) == 0x04:
                    return "closed"
        return "filtered"

    # ------------------ IMPROVED PACKET HANDLING ------------------
    def build_ip_layer(self):
        """
        Constructs either an IPv4 or IPv6 packet base, depending on user config.
        """
        if not self.use_ipv6:
            return scapy.IP(src=self.local_ip, dst=self.target_ip)
        else:
            return scapy.IPv6(src=self.local_ip, dst=self.target_ip)

    async def send_packet(self, port: int, flags: str):
        """
        Sends a single TCP packet with given flags, using a random ephemeral source port.
        """
        src_port = random.randint(1024, 65535)
        self.src_ports[src_port] = port
        pkt = self.build_ip_layer()/scapy.TCP(
            sport=src_port,
            dport=port,
            flags=flags,
            seq=random.randint(0, 2**32 - 1)
        )
        scapy.send(pkt, verbose=0)
        await asyncio.sleep(random.uniform(0.01, 0.05))

    async def send_fragmented_packet(self, port: int, flags: str):
        """
        Sends a fragmented TCP packet (for basic payload-based IDS evasion),
        using a random ephemeral source port.
        """
        src_port = random.randint(1024, 65535)
        self.src_ports[src_port] = port
        pkt = self.build_ip_layer()/scapy.TCP(
            sport=src_port,
            dport=port,
            flags=flags,
            seq=random.randint(0, 2**32 - 1),
            ttl=random.choice([64, 128, 255])
        )
        frags = scapy.fragment(pkt, fragsize=8)
        for frag in frags:
            scapy.send(frag, verbose=0)
            await asyncio.sleep(random.uniform(0.01, 0.05))

    # ------------------ ENHANCED RESPONSE MATCHING -----------------
    async def find_responses(self, port: int, timeout: float = 3.0) -> List[scapy.Packet]:
        """
        Asynchronously searches self.captured_packets for matching
        responses related to 'port'. We do repeated short sleeps to
        yield to the event loop, rather than blocking entirely.
        """
        matched = []
        cutoff = time.time() + timeout
        while time.time() < cutoff:
            new_packets = []
            # Pull all captured packets off the queue
            while self.captured_packets:
                pkt = self.captured_packets.pop(0)
                if self.is_response_packet(pkt, port):
                    matched.append(pkt)
                else:
                    new_packets.append(pkt)
            self.captured_packets = new_packets

            if matched:
                break
            await asyncio.sleep(0.05)  # yield control briefly
        return matched

    def is_response_packet(self, packet: scapy.Packet, port: int) -> bool:
        """
        Checks whether a given sniffed packet is a response to our scanned 'port'.
        """
        ip_layer = packet.getlayer(scapy.IP) or packet.getlayer(scapy.IPv6)
        if not ip_layer or ip_layer.src != self.target_ip:
            return False

        if packet.haslayer(scapy.TCP):
            tcp = packet[scapy.TCP]
            return self.src_ports.get(tcp.dport) == port
        elif packet.haslayer(scapy.ICMP):
            icmp = packet[scapy.ICMP]
            if icmp.type == 3 and hasattr(icmp, 'payload'):
                original_pkt = icmp.payload.getlayer(scapy.TCP)
                if original_pkt:
                    return self.src_ports.get(original_pkt.dport) == port
        return False

    # ------------------ ADVANCED OS FINGERPRINTING -----------------
    def os_fingerprint(self, port: int, responses: List[scapy.Packet]):
        """
        A simple OS guess based on TTL and TCP options. Spawns an async task to
        store results so as not to block other scanning tasks.
        """
        if not responses:
            return
        pkt = responses[0]
        if pkt.haslayer(scapy.TCP) and pkt.haslayer(scapy.IP):
            ip_layer = pkt[scapy.IP]
            tcp_layer = pkt[scapy.TCP]
            ttl = ip_layer.ttl
            options = tcp_layer.options
            os_guess = "Unknown"

            if ttl <= 64:
                os_guess = "Linux/Unix"
            elif ttl <= 128:
                os_guess = "Windows"
            else:
                os_guess = "Solaris/Cisco"

            if options:
                options_dict = dict((o[0], o[1]) for o in options if isinstance(o, tuple))
                if 'Timestamp' in options_dict:
                    os_guess = "Linux/Unix (Timestamp)"
                elif 'MSS' in options_dict and options_dict['MSS'] == 1460:
                    os_guess = "Linux/Unix"

            async def store_guess():
                async with self.lock:
                    self.results[port].os_guess = os_guess
            asyncio.create_task(store_guess())

    # ------------------ ENHANCED BANNER GRABBING -----------------
    async def banner_grabbing(self, port: int):
        """
        Attempt a basic banner grab on a discovered open port. This does not
        use SSL. For SSL, see ssl_probe.
        """
        try:
            reader, writer = await asyncio.open_connection(self.target_ip, port)
            service_guess = self.results[port].service.lower()

            if "http" in service_guess:
                writer.write(f"GET / HTTP/1.1\r\nHost: {self.target_ip}\r\n\r\n".encode())
            elif "ftp" in service_guess:
                writer.write(b"USER anonymous\r\n")
            elif "ssh" in service_guess:
                writer.write(b"SSH-2.0-QuantumScanner\r\n")
            else:
                writer.write(b"HEAD / HTTP/1.0\r\n\r\n")

            await writer.drain()
            banner = await asyncio.wait_for(reader.read(1024), timeout=2.0)
            banner_str = banner.decode(errors="ignore")[:256]

            async with self.lock:
                self.results[port].banner = banner_str
                # If the banner indicates a known service, override
                if "220" in banner_str and "ftp" in banner_str.lower():
                    self.results[port].service = "FTP"

            writer.close()
            await writer.wait_closed()
        except Exception as e:
            logging.debug(f"Banner grab failed on port {port}: {e}")

    # ------------------ ADAPTIVE RATE LIMITING -----------------
    async def adaptive_delay(self):
        """
        Simple adaptive delay that scales with how quickly we’ve been sending
        and receiving responses. If scanning is quick, we remain at 1.0x factor.
        If we see slower responses, we raise up to 2.0 for a slower scan.
        """
        if len(self.history) > 10:
            avg_delay = sum(self.history) / len(self.history)
            self.adaptation_factor = max(0.5, min(2.0, avg_delay * 1.2))
        delay = (1.0 / self.max_rate) * self.adaptation_factor
        self.history.append(delay)
        await asyncio.sleep(delay)

    # ------------------ SERVICE FINGERPRINTING -----------------
    def service_fingerprinting(self):
        """
        Basic guess of service type based on known port numbers and
        any banners already grabbed.
        """
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
                banner_lower = result.banner.lower()
                if "ssh" in banner_lower:
                    result.service = "SSH"
                elif "http" in banner_lower:
                    result.service = "HTTP"

    # ------------------ VULNERABILITY ANALYSIS -----------------
    def analyze_vulnerabilities(self):
        """
        Checks for known version strings or SSL versions. Extend as needed.
        """
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
            if result.service == "SSL/TLS":
                # Example: check for older/weak TLS
                if "tlsv1.0" in result.version.lower():
                    result.vulns.append("Weak TLS version (TLSv1.0)")

    # ------------------ CERTIFICATE HANDLING -----------------
    def parse_certificate(self, cert: bytes) -> Dict:
        """
        Extracts various certificate fields (subject, issuer, etc.).
        """
        try:
            cert_obj = x509.load_der_x509_certificate(cert, default_backend())
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
            logging.debug(f"Certificate parse error: {e}")
            return {}

    def check_ssl_vulnerabilities(self, cert_info: Dict) -> List[str]:
        """
        Checks simple SSL misconfigurations or known weak algorithms.
        """
        vulns = []
        if cert_info.get("signature_algorithm") == "sha1WithRSAEncryption":
            vulns.append("Weak signature (SHA1)")
        return vulns

    # ------------------ REPORT GENERATION -----------------
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
            tcp_states_str = ", ".join(
                f"{st.value}: {state}" for st, state in result.tcp_states.items()
            )
            vulns_str = "\n".join(result.vulns) if result.vulns else ""
            table.add_row(
                str(port),
                tcp_states_str or "",
                result.udp_state or "",
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
        open_tcp_ports = [
            p for p, r in self.results.items()
            if any(s == "open" for s in r.tcp_states.values())
        ]
        open_udp_ports = [
            p for p, r in self.results.items()
            if r.udp_state == "open"
        ]
        total_vulns = sum(len(r.vulns) for r in self.results.values())

        console.print("\n[bold]Scan Statistics:[/]")
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
        port = int(port_input)
        if 1 <= port <= 65535:
            return [port]
        raise ValueError(f"Invalid port: {port}")
    for part in port_input.split(","):
        part = part.strip()
        if "-" in part:
            start, end = map(int, part.split("-"))
            if not (1 <= start <= end <= 65535):
                raise ValueError(f"Invalid range: {part}")
            ports.extend(range(start, end + 1))
        elif part.isdigit():
            port = int(part)
            if 1 <= port <= 65535:
                ports.append(port)
            else:
                raise ValueError(f"Invalid port: {port}")
        else:
            raise ValueError(f"Invalid port spec: {part}")
    return sorted(set(ports))

# ---------------------- MAIN ------------------------
if __name__ == "__main__":
    parser = ArgumentParser(description="Quantum Port Scanner - The Most Advanced Ever")
    parser.add_argument("target", help="Target hostname or IP")
    parser.add_argument("-p", "--ports", required=True, help="Ports (e.g., 80, 1-100, 22,80)")
    parser.add_argument("-s", "--scan-types", nargs="+", default=["syn"],
                        choices=[st.value for st in ScanType],
                        help="Scan types (e.g. syn ssl udp ack fin xmas null window)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging")
    parser.add_argument("-e", "--evasions", action="store_true", help="Enable evasions (requires root)")
    parser.add_argument("-l", "--log-file", default="scanner.log", help="Log file path")
    parser.add_argument("--max-rate", type=int, default=500, help="Max packets per second")
    parser.add_argument("--concurrency", type=int, default=100, help="Concurrent port tasks")
    parser.add_argument("--ipv6", action="store_true", help="Use IPv6 scanning")
    parser.add_argument("--json-output", action="store_true", help="Store results in JSON")
    parser.add_argument("--shuffle-ports", action="store_true", help="Randomize the scan order of ports")
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
        shuffle_ports=args.shuffle_ports
    )

    asyncio.run(scanner.run_scan())
