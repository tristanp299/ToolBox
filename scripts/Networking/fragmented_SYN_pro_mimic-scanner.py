from scapy.all import *
import random
import time
import threading

# Ensure Scapy runs without interactive prompts
conf.verb = 0

# Expanded mimic payloads for different protocols
mimic_payloads = {
    "HTTP": b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
    "SSH": b"SSH-2.0-OpenSSH_8.2\r\n",
    "FTP": b"220 FTP Server Ready\r\n",
    "SMTP": b"220 mail.example.com ESMTP\r\n",
    "IMAP": b"* OK IMAP4rev1 Service Ready\r\n",
    "POP3": b"+OK POP3 server ready\r\n",
    # Add more protocols as needed
}

def protocol_mimic_scan(target_ip, target_port, protocol="HTTP", timeout=2):
    """
    Perform a Protocol Mimic Scan by sending a SYN packet with a payload mimicking a protocol response.
    
    Args:
        target_ip (str): Target IP address.
        target_port (int): Target port number.
        protocol (str): Protocol to mimic (default: "HTTP").
        timeout (int): Timeout for response in seconds (default: 2).
    """
    try:
        # Validate the protocol
        if protocol not in mimic_payloads:
            raise ValueError(f"Unknown protocol: {protocol}")
        payload = mimic_payloads[protocol]
        
        # Craft the SYN packet with mimic payload
        packet = IP(dst=target_ip) / TCP(dport=target_port, flags="S") / Raw(load=payload)
        
        # Send the packet and wait for a response
        response = sr1(packet, timeout=timeout, verbose=0)
        
        # Analyze the response
        if response:
            if response.haslayer(TCP):
                if response[TCP].flags & 0x12 == 0x12:  # SYN-ACK
                    print(f"Port {target_port} is OPEN (mimicked as {protocol})")
                elif response[TCP].flags & 0x04 == 0x04:  # RST
                    print(f"Port {target_port} is CLOSED (mimicked as {protocol})")
        else:
            print(f"Port {target_port} is FILTERED or no response (mimicked as {protocol})")
    except Exception as e:
        print(f"Error during Protocol Mimic Scan: {e}")

def advanced_fragmented_syn_scan(target_ip, target_port, min_frag_size=16, max_frag_size=64, min_delay=0.01, max_delay=0.1, timeout=10):
    """
    Perform an advanced Fragmented SYN Scan with randomized fragment sizes and delays.
    
    Args:
        target_ip (str): Target IP address.
        target_port (int): Target port number.
        min_frag_size (int): Minimum fragment payload size in bytes (multiple of 8, default: 16).
        max_frag_size (int): Maximum fragment payload size in bytes (multiple of 8, default: 64).
        min_delay (float): Minimum delay between fragments in seconds (default: 0.01).
        max_delay (float): Maximum delay between fragments in seconds (default: 0.1).
        timeout (int): Sniffing timeout in seconds (default: 10).
    """
    try:
        # Validate fragment sizes
        if min_frag_size % 8 != 0 or max_frag_size % 8 != 0:
            raise ValueError("Fragment sizes must be multiples of 8")
        if min_frag_size > max_frag_size:
            raise ValueError("min_frag_size must be <= max_frag_size")
        
        # Generate random IP ID
        ip_id = random.randint(1, 65535)
        
        # Create SYN packet with payload (1400 bytes of dummy data)
        payload = b"A" * 1400
        syn_packet = IP(dst=target_ip, id=ip_id) / TCP(dport=target_port, flags="S") / Raw(load=payload)
        
        # Get the full IP payload (TCP header + data) as bytes
        full_payload = bytes(syn_packet[IP].payload)
        total_size = len(full_payload)
        
        # Generate randomized fragment sizes
        fragment_sizes = []
        current_size = 0
        while current_size < total_size:
            remaining = total_size - current_size
            if remaining <= min_frag_size:
                fragment_sizes.append(remaining)
                break
            else:
                # Random size in multiples of 8
                k = random.randint(min_frag_size // 8, max_frag_size // 8)
                size = k * 8
                if size > remaining:
                    size = remaining
                fragment_sizes.append(size)
                current_size += size
        
        # Create fragments
        fragments = []
        offset = 0
        for i, size in enumerate(fragment_sizes):
            # Extract the payload part
            payload_part = full_payload[offset * 8 : offset * 8 + size]
            # Set MF flag if not the last fragment
            flags = "MF" if offset * 8 + size < total_size else 0
            # Create the fragment
            fragment = IP(dst=target_ip, id=ip_id, flags=flags, frag=offset) / payload_part
            fragments.append(fragment)
            offset += size // 8  # Offset in 8-byte units
        
        # Function to capture and analyze responses
        def capture_response(pkt):
            if (pkt.haslayer(TCP) and 
                pkt[IP].src == target_ip and 
                pkt[TCP].sport == target_port):
                if pkt[TCP].flags & 0x12 == 0x12:  # SYN-ACK
                    print(f"Port {target_port} is OPEN (fragmented scan)")
                elif pkt[TCP].flags & 0x04 == 0x04:  # RST
                    print(f"Port {target_port} is CLOSED (fragmented scan)")
        
        # Start sniffing in a separate thread
        sniff_filter = f"tcp and host {target_ip} and port {target_port}"
        sniff_thread = threading.Thread(
            target=sniff,
            kwargs={'filter': sniff_filter, 'prn': capture_response, 'timeout': timeout}
        )
        sniff_thread.start()
        
        # Send fragments with random delays
        for frag in fragments:
            send(frag, verbose=0)
            time.sleep(random.uniform(min_delay, max_delay))
        
        # Wait for sniffing to complete
        sniff_thread.join()
        
        print(f"Scan for {target_ip}:{target_port} completed")
    
    except Exception as e:
        print(f"Error during advanced fragmented SYN scan: {e}")

# Example usage
if __name__ == "__main__":
    target_ip = "192.168.1.1"  # Replace with your target IP
    target_port = 80           # Replace with your target port
    
    print("Running Protocol Mimic Scan with HTTP...")
    protocol_mimic_scan(target_ip, target_port, protocol="HTTP")
    
    print("\nRunning Protocol Mimic Scan with SSH...")
    protocol_mimic_scan(target_ip, target_port, protocol="SSH")
    
    print("\nRunning Advanced Fragmented SYN Scan...")
    advanced_fragmented_syn_scan(target_ip, target_port)