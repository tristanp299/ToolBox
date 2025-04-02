#!/usr/bin/env python3

# ########################################################################
# Quantum Scanner - Advanced port scanner with evasion capabilities
# 
# This tool performs various network scanning techniques including standard 
# TCP/UDP scans and evasive methods like fragmentation and protocol mimicry.
# It's designed for security professionals conducting authorized testing.
# 
# SECURITY NOTE: Running this tool against systems without permission
# may violate laws and network policies. Always obtain authorization
# before scanning any systems you don't own or manage.
# ########################################################################

import asyncio
import logging
import random
import socket
import ssl
import sys
import os
import time
import threading
import json
import hashlib
import re
from argparse import ArgumentParser
from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple, Any
from datetime import datetime

# Import required libraries 
try:
    import scapy.all as scapy  # Used for low-level packet manipulation
    from cryptography import x509  # For SSL certificate analysis
    from cryptography.hazmat.backends import default_backend
    from rich.console import Console  # For enhanced terminal output
    from rich.progress import Progress
    from rich.table import Table
    from rich import print as rprint
except ImportError as e:
    print(f"Error: Missing required dependency: {e}")
    print("Please install dependencies: pip install scapy cryptography rich")
    sys.exit(1)

# Suppress Scapy warnings to keep output clean
scapy.conf.verb = 0
console = Console()

# ################ ENUMS & DATA STRUCTURES ################
class ScanType(Enum):
    '''
    Defines the various scanning techniques supported by the scanner:
    
    - SYN: Standard TCP SYN scan - efficient and relatively stealthy
    - SSL: Probes for SSL/TLS service information and certificates
    - UDP: Basic UDP port scan with custom payload options
    - ACK: TCP ACK scan to detect firewall filtering rules
    - FIN: Stealthy scan using TCP FIN flags to bypass basic filters
    - XMAS: TCP scan with FIN, URG, and PUSH flags set 
    - NULL: TCP scan with no flags set, may bypass some packet filters
    - WINDOW: Analyzes TCP window size responses to determine port status
    - TLSECHO: Uses fake TLS server responses to evade detection
    - MIMIC: Sends SYN packets with protocol-specific payloads
    - FRAG: Fragments packets to bypass deep packet inspection
    '''
    SYN = "syn"
    SSL = "ssl"
    UDP = "udp"
    ACK = "ack"
    FIN = "fin"
    XMAS = "xmas"
    NULL = "null"
    WINDOW = "window"
    TLSECHO = "tls_echo"
    MIMIC = "mimic"
    FRAG = "frag"

@dataclass
class PortResult:
    '''
    Comprehensive data structure to store scan results for each port.
    
    Fields:
    - tcp_states: Records responses from various TCP scan methods
    - udp_state: Status determined by UDP scan
    - filtering: Firewall filtering status (from ACK scan)
    - service: Identified service name
    - version: Service version if detected
    - vulns: Potential security vulnerabilities
    - cert_info: SSL/TLS certificate details
    - banner: Service banner information
    - os_guess: Operating system fingerprinting results
    - scan_time: When this port was scanned
    '''
    tcp_states: Dict[ScanType, str] = field(default_factory=dict)
    udp_state: str = ""
    filtering: str = ""
    service: str = ""
    version: str = ""
    vulns: List[str] = field(default_factory=list)
    cert_info: Optional[Dict] = None
    banner: str = ""
    os_guess: str = ""
    scan_time: str = field(default_factory=lambda: datetime.now().isoformat())

# Protocol payloads for the mimic scan technique
# These payloads mimic legitimate protocol responses to avoid detection
MIMIC_PAYLOADS = {
    "HTTP": b"HTTP/1.1 200 OK\r\nServer: Apache\r\nContent-Length: 0\r\n\r\n",
    "SSH": b"SSH-2.0-OpenSSH_8.2p1\r\n",
    "FTP": b"220 FTP Server Ready\r\n",
    "SMTP": b"220 mail.example.com ESMTP Postfix\r\n",
    "IMAP": b"* OK IMAP4rev1 Server Ready\r\n",
    "POP3": b"+OK POP3 server ready\r\n",
    "MySQL": b"\x4a\x00\x00\x00\x0a\x35\x2e\x37\x2e\x33\x39\x00",
    "RDP": b"\x03\x00\x00\x13\x0e\xd0\x00\x00\x124\x00\x02\x01\x08\x00\x01\x00\x00\x00",
}

# Common service port mappings for service identification
COMMON_PORTS = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    111: "rpcbind",
    135: "msrpc",
    139: "netbios-ssn",
    143: "imap",
    443: "https",
    445: "microsoft-ds",
    993: "imaps",
    995: "pop3s",
    1723: "pptp",
    3306: "mysql",
    3389: "ms-wbt-server",
    5432: "postgresql",
    5900: "vnc",
    8080: "http-proxy",
    8443: "https-alt",
}

# ################ MAIN SCANNER CLASS ################
class QuantumScanner:
    '''
    The core scanner implementation that orchestrates all scanning operations.
    
    This class handles:
    - Target resolution and validation
    - Concurrent scan execution and rate limiting
    - Various scan techniques implementation
    - Result processing and reporting
    - Evasion technique coordination
    
    Security measures include:
    - Rate limiting to avoid overwhelming target networks
    - Adaptive timing based on network conditions
    - User permission validation for raw socket operations
    - Proper cleanup of connections and temporary resources
    '''
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
        # Mimic scan parameters
        mimic_protocol: str = "HTTP",
        # Fragment scan specific parameters
        frag_min_size: int = 16,
        frag_max_size: int = 64,
        frag_min_delay: float = 0.01,
        frag_max_delay: float = 0.1,
        frag_timeout: int = 10,
        frag_first_min_size: int = 64,
        frag_two_frags: bool = False,
        # Output parameters
        log_file: str = "scanner.log"
    ):
        '''
        Initialize the scanner with configuration parameters.
        
        Parameters:
        - target: Host to scan (hostname or IP address)
        - ports: List of port numbers to check
        - scan_types: Scan techniques to employ
        - concurrency: Maximum simultaneous operations
        - max_rate: Packets per second rate limit
        - evasions: Enable stealth techniques
        - verbose: Enable detailed logging
        - use_ipv6: Use IPv6 addressing
        - json_output: Save results as JSON
        - shuffle_ports: Randomize port order
        - timeout_*: Various timeout settings
        - mimic_protocol: Protocol to mimic in special scans
        - frag_*: Fragment scan configuration
        - log_file: Custom log file location
        '''
        # Configure logging
        self._setup_logging(log_file, verbose)
        
        # Store basic settings
        self.use_ipv6 = use_ipv6
        self.json_output = json_output
        self.shuffle_ports = shuffle_ports
        self.timeout_scan = timeout_scan
        self.timeout_connect = timeout_connect
        self.timeout_banner = timeout_banner
        self.mimic_protocol = mimic_protocol
        self.scan_start_time = datetime.now()
        self.target = target  # Store original target string for logging
        
        # Set up fragmentation settings with reasonable minimums
        self.frag_min_size = max(frag_min_size, 24)  # Need enough space for TCP header
        self.frag_max_size = max(frag_max_size, self.frag_min_size)
        self.frag_min_delay = max(0.001, frag_min_delay)  # Ensure positive delay
        self.frag_max_delay = max(self.frag_min_delay, frag_max_delay)
        self.frag_timeout = frag_timeout
        self.frag_first_min_size = frag_first_min_size
        self.frag_two_frags = frag_two_frags

        # Resolve the target's IP address securely
        try:
            if not self.use_ipv6:
                self.target_ip = socket.gethostbyname(target)
                try:
                    self.local_ip = scapy.conf.route.route(self.target_ip)[1]
                except Exception:
                    self.local_ip = self._get_default_interface_ip()
            else:
                info = socket.getaddrinfo(target, None, socket.AF_INET6)
                self.target_ip = info[0][4][0]
                self.local_ip = "::"
            
            # Log resolution with target details for C2 deconfliction
            logging.info(f"Resolved target {target} to {self.target_ip}")
        except socket.gaierror as e:
            logging.error(f"Could not resolve hostname {target}: {e}")
            raise ValueError(f"Could not resolve hostname {target}")

        # Organize ports and scan settings
        if self.shuffle_ports:
            random.shuffle(ports)
        self.ports = ports
        self.scan_types = scan_types
        self.concurrency = min(concurrency, 500)  # Cap at reasonable value
        self.max_rate = max_rate
        self.evasions = evasions
        self.verbose = verbose

        # Set up results storage and rate limiting
        self.results: Dict[int, PortResult] = {}
        self.adaptation_factor = 1.0
        self.history = deque(maxlen=100)
        self.lock = asyncio.Lock()
        self.packets_sent = 0
        self.successful_scans = 0
        
        # Ports found to be open across any scan type
        self.open_ports: Set[int] = set()
        
        # Set up SSL context for secure connections
        self.ctx = ssl.create_default_context()
        self.ctx.check_hostname = False
        self.ctx.verify_mode = ssl.CERT_NONE
        
        # Check for appropriate privileges
        if self._requires_root() and not self._has_root_privileges():
            logging.error("Root privileges required for raw socket operations")
            raise PermissionError("This scan requires root/administrator privileges")

    def _setup_logging(self, log_file: str, verbose: bool) -> None:
        '''
        Configure the logging system with appropriate handlers and levels.
        
        Args:
            log_file: Path to the log file
            verbose: Whether to enable debug logging
        '''
        log_level = logging.DEBUG if verbose else logging.INFO
        
        # Ensure the log directory exists
        log_dir = os.path.dirname(log_file)
        if log_dir and not os.path.exists(log_dir):
            try:
                os.makedirs(log_dir)
            except OSError as e:
                print(f"Warning: Could not create log directory {log_dir}: {e}")
                log_file = "scanner.log"  # Fall back to current directory
        
        # Configure the root logger
        logging.basicConfig(
            level=log_level,
            format="%(asctime)s - %(levelname)s - %(message)s",
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler() if verbose else logging.NullHandler()
            ],
        )
    
    def _get_default_interface_ip(self) -> str:
        '''
        Retrieve the IP of the default network interface.
        
        Returns:
            IP address as string or None if unavailable
        '''
        try:
            # This creates a temporary socket to determine the IP used for external communication
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))  # Doesn't actually send data
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return None
    
    def _requires_root(self) -> bool:
        '''
        Determines if the current scan configuration requires elevated privileges.
        
        Returns:
            True if root/admin required, False otherwise
        '''
        # These scan types need raw socket access
        raw_socket_scans = {
            ScanType.SYN, ScanType.ACK, ScanType.FIN, 
            ScanType.XMAS, ScanType.NULL, ScanType.WINDOW,
            ScanType.TLSECHO, ScanType.MIMIC, ScanType.FRAG
        }
        
        # Check if any of our scan types need raw sockets
        return any(scan_type in raw_socket_scans for scan_type in self.scan_types)
    
    def _has_root_privileges(self) -> bool:
        '''
        Checks if the script is running with sufficient privileges.
        
        Returns:
            True if we have the privileges we need, False otherwise
        '''
        # For Linux/Unix systems
        if os.name == 'posix':
            return os.geteuid() == 0
        
        # For Windows - assume admin if we can import the appropriate module
        elif os.name == 'nt':
            try:
                import ctypes
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            except:
                # If we can't import or call the function, assume no admin
                return False
                
        # Unknown OS - assume we don't have privileges
        return False

    async def run_scan(self) -> Dict[int, PortResult]:
        '''
        Execute the complete scan process against the target.
        
        This method:
        1. Initializes result structures for each port
        2. Displays a progress bar during scanning
        3. Manages concurrent scan operations with rate limiting
        4. Processes scan results
        5. Generates reports
        
        Returns:
            Dictionary of scan results indexed by port number
        '''
        logging.info(f"Starting scan of {self.target_ip} at {self.scan_start_time.isoformat()}")
        console.print(f"[bold cyan]Starting scan:[/] {self.target_ip} ([italic]{len(self.ports)}[/] ports)")
        
        # Initialize results structure for all ports
        for port in self.ports:
            self.results[port] = PortResult()

        # Set up progress tracking and concurrent execution
        try:
            with Progress() as progress:
                total_tasks = len(self.ports) * len(self.scan_types)
                task = progress.add_task("[cyan]Scanning...", total=total_tasks)
                sem = asyncio.Semaphore(self.concurrency)

                # Create tasks for each port
                tasks = []
                for port in self.ports:
                    tasks.append(asyncio.create_task(
                        self.scan_port(port, progress, task, sem)
                    ))
                await asyncio.gather(*tasks)
        except KeyboardInterrupt:
            console.print("[bold red]Scan interrupted by user[/]")
            logging.info("Scan interrupted by user")
        except Exception as e:
            console.print(f"[bold red]Error during scan:[/] {e}")
            logging.error(f"Error during scan: {e}")
        
        # Post-processing of results
        self.scan_end_time = datetime.now()
        self.service_fingerprinting()
        self.analyze_vulnerabilities()
        self.generate_report()
        
        if self.json_output:
            self.dump_results_json()
            
        return self.results

    async def scan_port(self, port: int, progress, task, sem: asyncio.Semaphore):
        '''
        Scan a single port with all selected techniques.
        
        Args:
            port: The port number to scan
            progress: Progress bar instance
            task: Current progress task
            sem: Semaphore for concurrency control
        '''
        async with sem:
            try:
                for st in self.scan_types:
                    # Execute the appropriate scan method based on type
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

                    # Update the open ports list if any scan showed the port as open
                    port_states = self.results[port].tcp_states
                    if st in port_states and port_states[st] == "open":
                        self.open_ports.add(port)
                    
                    # Apply rate limiting between scans
                    await self.adaptive_delay()
                    
                # After all scans, attempt banner grabbing for open ports
                if port in self.open_ports:
                    await self.banner_grabbing(port)
            except Exception as e:
                logging.error(f"Error scanning port {port}: {e}")
            finally:
                # Always update progress even if there was an error
                progress.update(task, advance=len(self.scan_types))

    # -------------------- IP LAYER HANDLING --------------------
    def build_ip_layer(self):
        '''
        Create the appropriate IP layer based on protocol version.
        
        Returns:
            IPv4 or IPv6 packet layer
        '''
        try:
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
        except Exception as e:
            logging.error(f"Error building IP layer: {e}")
            # Return a basic layer as fallback
            return scapy.IP(dst=self.target_ip) if not self.use_ipv6 else scapy.IPv6(dst=self.target_ip)

    def set_ip_ttl_or_hlim(self, ip_layer) -> None:
        '''
        Configure the TTL or hop limit field with random values for evasion.
        
        Args:
            ip_layer: The IP packet layer to modify
        '''
        try:
            if self.use_ipv6:
                # For IPv6, set the hop limit
                ip_layer.hlim = random.choice([64, 128, 255]) if self.evasions else 64
            else:
                # For IPv4, set the TTL
                ip_layer.ttl = random.choice([64, 128, 255]) if self.evasions else 64
                
                # If using evasions, also consider randomizing IP ID
                if self.evasions:
                    ip_layer.id = random.randint(1, 65535)
        except Exception as e:
            logging.error(f"Error setting TTL/hlim: {e}")

    # -------------------- SCAN METHODS --------------------
    async def syn_scan(self, port: int, max_tries=3):
        '''
        The classic SYN scan - fast and reliable!
        Here's how it works:
        1. Send a SYN packet
        2. Wait for the response
        3. Figure out what it means:
           - Got SYN/ACK? Port is open!
           - Got RST? Port is closed
           - Nothing? Might be filtered
        '''
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
        '''
        Let's check if there's a firewall in the way!
        This scan:
        1. Sends an ACK packet
        2. If we get RST back = no firewall
        3. If nothing = probably filtered
        '''
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
        '''
        Time for some stealth scanning!
        This one:
        1. Sends a FIN packet
        2. If nothing back = might be open
        3. If RST = definitely closed
        '''
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
        '''
        The Christmas tree scan - we set all the flags!
        Similar to FIN scan but more festive:
        1. Send packet with FIN+PSH+URG flags
        2. If nothing back = might be open
        3. If RST = definitely closed
        '''
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
        '''
        The minimalist approach - no flags at all!
        Another stealth technique:
        1. Send packet with no flags
        2. If nothing back = might be open
        3. If RST = definitely closed
        '''
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
        '''
        Let's check those TCP window sizes!
        This scan:
        1. Sends an ACK packet
        2. Looks at the window size in response
        3. Sometimes spots open ports
        '''
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
        '''
        Time to check those UDP ports!
        This scan:
        1. Sends a UDP packet
        2. Waits for response
        3. Checks for ICMP errors
        '''
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
        '''
        Let's check for SSL/TLS services!
        This probe:
        1. Tries to make an SSL connection
        2. Gets certificate info
        3. Checks SSL version
        4. Looks for security issues
        '''
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
        Sneaky TLS detection time!
        This technique:
        1. Sends SYN with minimal TLS data
        2. Can sneak past firewalls
        3. Spots TLS services
        '''
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
        '''
        Let's pretend to be legit traffic!
        This technique:
        1. Sends SYN with protocol-specific data
        2. Looks like normal traffic
        3. Can sneak past IDS/IPS
        '''
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

    # -------------------- FRAGMENTED SYN SCAN --------------------
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
        '''
        Time for some packet splitting action!
        This advanced technique:
        1. Splits SYN packet into pieces
        2. Sneaks past firewalls
        3. Can do two modes:
           - Two fragments (header + data)
           - Multiple random-sized fragments
        '''
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
                ip_header_len = 40  # typically 40 bytes for IPv6 main header

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
                # If user wants exactly two fragments:
                if self.frag_two_frags:
                    # 1) First fragment: at least frag_first_min_size in size
                    first_size = min(total_size, max(self.frag_first_min_size, min_frag_size))
                    remain = total_size - first_size

                    # More fragments flag for the first if there's leftover
                    more_frag = "MF" if remain > 0 else 0
                    first_data = ip_payload[:first_size]

                    if not self.use_ipv6:
                        f1 = scapy.IP(
                            dst=ip_layer.dst,
                            src=ip_layer.src,
                            id=ip_id,
                            flags=more_frag,
                            frag=0,
                            ttl=ip_layer.ttl
                        ) / first_data
                    else:
                        f1 = scapy.IPv6(
                            dst=ip_layer.dst,
                            src=ip_layer.src,
                            hlim=ip_layer.hlim,
                            nh=6,  # TCP
                            fl=0
                        ) / first_data
                        if more_frag:
                            f1[scapy.IPv6].flags = 1

                    scapy.send(f1, verbose=0)
                    time.sleep(random.uniform(min_delay, max_delay))

                    if remain > 0:
                        # 2) Second fragment: whatever is left
                        f2_data = ip_payload[first_size:]
                        # no MF, since it's last
                        if not self.use_ipv6:
                            f2 = scapy.IP(
                                dst=ip_layer.dst,
                                src=ip_layer.src,
                                id=ip_id,
                                flags=0,
                                frag=(first_size // 8),
                                ttl=ip_layer.ttl
                            ) / f2_data
                        else:
                            f2 = scapy.IPv6(
                                dst=ip_layer.dst,
                                src=ip_layer.src,
                                hlim=ip_layer.hlim,
                                nh=6,
                                fl=0
                            ) / f2_data
                            f2[scapy.IPv6].frag = (first_size // 8)

                        scapy.send(f2, verbose=0)
                        time.sleep(random.uniform(min_delay, max_delay))
                else:
                    # Otherwise, do multi-fragment approach
                    offset_bytes = 0
                    remain = total_size

                    while remain > 0:
                        # For the first fragment, ensure >= frag_first_min_size
                        if offset_bytes == 0:
                            frag_size = max(self.frag_first_min_size, random.randint(min_frag_size, max_frag_size))
                        else:
                            frag_size = random.randint(min_frag_size, max_frag_size)

                        if frag_size > remain:
                            frag_size = remain
