#!/usr/bin/env python3

# Let's make this script super efficient and feature-rich!
from scapy.all import *
import datetime
import sys
import logging
import json
import os
from collections import defaultdict, deque
import argparse
import threading
import queue
import signal
from typing import Dict, List, Set, Tuple
import numpy as np
from concurrent.futures import ThreadPoolExecutor
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.cluster import DBSCAN
import joblib

# Set up our logging configuration
def setup_logging(log_file="packet_capture.log"):
    # Create logs directory if it doesn't exist
    os.makedirs("logs", exist_ok=True)
    
    # Set up file logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(f"logs/{log_file}"),
            logging.StreamHandler(sys.stdout)
        ]
    )
    return logging.getLogger(__name__)

class PacketBuffer:
    """Efficient circular buffer for packet analysis"""
    def __init__(self, max_size: int = 1000):
        self.buffer = deque(maxlen=max_size)
        self.lock = threading.Lock()
    
    def add(self, packet) -> None:
        with self.lock:
            self.buffer.append(packet)
    
    def get_window(self, seconds: int) -> List:
        current_time = datetime.datetime.now()
        with self.lock:
            return [p for p in self.buffer 
                   if (current_time - p['timestamp']).total_seconds() <= seconds]

class EnhancedStats:
    """Advanced statistics tracking with efficient data structures"""
    def __init__(self):
        self.total_packets = 0
        self.protocol_stats = defaultdict(int)
        self.port_stats = defaultdict(int)
        self.ip_stats = defaultdict(lambda: {'in': 0, 'out': 0, 'bytes': 0})
        self.tcp_flags = defaultdict(int)
        self.start_time = datetime.datetime.now()
        self.packet_sizes = deque(maxlen=1000)  # Rolling window of packet sizes
        self.connection_tracker = defaultdict(set)  # Track unique connections
        self.lock = threading.Lock()
        
    def update(self, packet) -> None:
        with self.lock:
            self._update_stats(packet)
    
    def _update_stats(self, packet) -> None:
        """Update all statistics atomically"""
        self.total_packets += 1
        
        if IP in packet:
            pkt_size = len(packet)
            self.packet_sizes.append(pkt_size)
            
            # Update IP stats with direction and byte count
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            self.ip_stats[src_ip]['out'] += 1
            self.ip_stats[src_ip]['bytes'] += pkt_size
            self.ip_stats[dst_ip]['in'] += 1
            
            # Track unique connections
            if TCP in packet or UDP in packet:
                proto = 'TCP' if TCP in packet else 'UDP'
                sport = packet[proto].sport
                dport = packet[proto].dport
                conn_tuple = (src_ip, dst_ip, proto, sport, dport)
                self.connection_tracker[src_ip].add(conn_tuple)
            
            # Enhanced protocol tracking
            proto_num = packet[IP].proto
            self.protocol_stats[proto_num] += 1
            
            if TCP in packet:
                self._update_tcp_stats(packet)
            elif UDP in packet:
                self._update_udp_stats(packet)
    
    def _update_tcp_stats(self, packet) -> None:
        """Handle TCP-specific statistics"""
        tcp = packet[TCP]
        self.port_stats[f"TCP:{tcp.sport}"] += 1
        self.port_stats[f"TCP:{tcp.dport}"] += 1
        
        # Track TCP flags combinations
        flag_combo = tcp.flags
        self.tcp_flags[flag_combo] += 1
    
    def _update_udp_stats(self, packet) -> None:
        """Handle UDP-specific statistics"""
        udp = packet[UDP]
        self.port_stats[f"UDP:{udp.sport}"] += 1
        self.port_stats[f"UDP:{udp.dport}"] += 1
    
    def get_summary(self) -> Dict:
        """Get current statistics summary"""
        with self.lock:
            return {
                "total_packets": self.total_packets,
                "avg_packet_size": np.mean(self.packet_sizes) if self.packet_sizes else 0,
                "unique_ips": len(self.ip_stats),
                "total_connections": sum(len(conns) for conns in self.connection_tracker.values()),
                "duration": (datetime.datetime.now() - self.start_time).total_seconds()
            }

class NetworkMonitor:
    """Main monitoring class with improved performance"""
    def __init__(self, interface: str = None):
        self.stats = EnhancedStats()
        self.packet_buffer = PacketBuffer()
        self.alert_queue = queue.Queue()
        self.interface = interface
        self.stop_flag = threading.Event()
        self.executor = ThreadPoolExecutor(max_workers=3)
        
        # Configure logging
        self._setup_logging()
        
        # Initialize alert thresholds
        self.thresholds = {
            'packets_per_sec': 1000,
            'connections_per_ip': 50,
            'bandwidth_mbps': 100
        }
    
    def _setup_logging(self) -> None:
        """Set up enhanced logging with rotation"""
        os.makedirs("logs", exist_ok=True)
        self.logger = logging.getLogger("NetworkMonitor")
        self.logger.setLevel(logging.INFO)
        
        # File handler with rotation
        handler = logging.handlers.RotatingFileHandler(
            "logs/network_monitor.log",
            maxBytes=10_000_000,  # 10MB
            backupCount=5
        )
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
    
    def process_packet(self, packet) -> None:
        """Process a single packet with parallel analysis"""
        if IP not in packet:
            return
        
        # Update stats in parallel
        self.executor.submit(self.stats.update, packet)
        
        # Store packet info in buffer
        packet_info = {
            'timestamp': datetime.datetime.now(),
            'size': len(packet),
            'src': packet[IP].src,
            'dst': packet[IP].dst,
            'proto': packet[IP].proto
        }
        self.packet_buffer.add(packet_info)
        
        # Check for alerts
        self.executor.submit(self._check_alerts, packet_info)
    
    def _check_alerts(self, packet_info: Dict) -> None:
        """Check for various alert conditions"""
        # Get recent packets
        recent_packets = self.packet_buffer.get_window(seconds=1)
        
        # Check packet rate
        packets_per_sec = len(recent_packets)
        if packets_per_sec > self.thresholds['packets_per_sec']:
            self._raise_alert(f"High packet rate detected: {packets_per_sec} pps")
        
        # Check bandwidth usage
        bandwidth = sum(p['size'] for p in recent_packets) * 8 / 1_000_000  # Mbps
        if bandwidth > self.thresholds['bandwidth_mbps']:
            self._raise_alert(f"High bandwidth usage: {bandwidth:.2f} Mbps")
    
    def _raise_alert(self, message: str) -> None:
        """Queue an alert for processing"""
        self.alert_queue.put({
            'timestamp': datetime.datetime.now(),
            'message': message,
            'stats': self.stats.get_summary()
        })
        self.logger.warning(message)
    
    def start(self) -> None:
        """Start the monitoring with graceful shutdown"""
        def signal_handler(signum, frame):
            self.stop_flag.set()
        
        signal.signal(signal.SIGINT, signal_handler)
        
        self.logger.info("Starting network monitor...")
        try:
            sniff(
                iface=self.interface,
                prn=self.process_packet,
                store=0,
                stop_filter=lambda _: self.stop_flag.is_set()
            )
        finally:
            self.cleanup()
    
    def cleanup(self) -> None:
        """Cleanup resources"""
        self.executor.shutdown(wait=True)
        self.save_stats()
        self.logger.info("Monitoring stopped. Final statistics saved.")
    
    def save_stats(self) -> None:
        """Save statistics to JSON with error handling"""
        try:
            stats_file = f"logs/stats_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(stats_file, 'w') as f:
                json.dump(self.stats.get_summary(), f, indent=2, default=str)
        except Exception as e:
            self.logger.error(f"Failed to save statistics: {e}")

def main():
    parser = argparse.ArgumentParser(description='Advanced Network Monitor')
    parser.add_argument('--interface', help='Network interface to monitor')
    parser.add_argument('--threshold-pps', type=int, default=1000,
                       help='Packets per second threshold')
    parser.add_argument('--threshold-bw', type=float, default=100.0,
                       help='Bandwidth threshold (Mbps)')
    args = parser.parse_args()
    
    if os.geteuid() != 0:
        print("This script needs root privileges!")
        sys.exit(1)
    
    monitor = NetworkMonitor(interface=args.interface)
    monitor.thresholds.update({
        'packets_per_sec': args.threshold_pps,
        'bandwidth_mbps': args.threshold_bw
    })
    
    monitor.start()

if __name__ == "__main__":
    main()
