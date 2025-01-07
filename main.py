#!/usr/bin/env python3
import socket
import struct
import sys
import time
from datetime import datetime
import threading
import ipaddress
from collections import defaultdict

class PacketSniffer:
    # TCP/IP packets - requires admin privileges
    def __init__(self):
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        except PermissionError:
            print("Error: This program requires admin privileges.")
            sys.exit(1)
        
        # Dictionary to store connection stats
        self.connections = defaultdict(lambda: {'packets': 0, 'bytes': 0})
        
        # Routing table simulation
        self.routing_table = {}
        
    def unpack_ethernet_frame(self, data):
        dst_mac, src_mac, protocol = struct.unpack('! 6s 6s H', data[:14])
        return self.format_mac_address(dst_mac), self.format_mac_address(src_mac), socket.htons(protocol), data[14:]
    
    @staticmethod
    def format_mac_address(mac):
        return ':'.join(map('{:02x}'.format, mac))
    
    def unpack_ipv4_packet(self, data):
        version_header_length = data[0]
        version = version_header_length >> 4
        header_length = (version_header_length & 15) * 4
        ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
        return version, header_length, ttl, proto, \
               ipaddress.IPv4Address(src), ipaddress.IPv4Address(target), data[header_length:]
    
    def unpack_tcp_segment(self, data):
        src_port, dst_port, sequence, ack, offset_flags = struct.unpack('! H H L L H', data[:14])
        offset = (offset_flags >> 12) * 4
        flags = {
            'FIN': bool(offset_flags & 1),
            'SYN': bool((offset_flags >> 1) & 1),
            'RST': bool((offset_flags >> 2) & 1),
            'PSH': bool((offset_flags >> 3) & 1),
            'ACK': bool((offset_flags >> 4) & 1),
            'URG': bool((offset_flags >> 5) & 1)
        }
        return src_port, dst_port, sequence, ack, flags, data[offset:]

    def add_route(self, network, next_hop, metric):
        try:
            network = ipaddress.IPv4Network(network)
            self.routing_table[network] = {'next_hop': next_hop, 'metric': metric}
            print(f"Added route: {network} via {next_hop} (metric: {metric})")
        except ValueError as e:
            print(f"Invalid network address: {e}")

    def find_route(self, ip_address):
        ip = ipaddress.IPv4Address(ip_address)
        matching_routes = []
        
        for network, route_info in self.routing_table.items():
            if ip in network:
                matching_routes.append((network, route_info))
        
        if not matching_routes:
            return None
        
        # Return the most specific route (longest prefix match)
        return max(matching_routes, key=lambda x: x[0].prefixlen)

    def start_capture(self, duration=60):
        start_time = time.time()
        print(f"\nStarting packet capture for {duration} seconds.")
        
        try:
            while time.time() - start_time < duration:
                raw_data, addr = self.socket.recvfrom(65535)
                
                # Parse packet data
                ip_header = raw_data[0:20]
                ip_header = struct.unpack('!BBHHHBBH4s4s', ip_header)
                
                version_ihl = ip_header[0]
                version = version_ihl >> 4
                ihl = version_ihl & 0xF
                iph_length = ihl * 4
                protocol = ip_header[6]
                s_addr = socket.inet_ntoa(ip_header[8])
                d_addr = socket.inet_ntoa(ip_header[9])
                
                # Only process TCP packets
                if protocol == 6:  # TCP
                    tcp_header = raw_data[iph_length:iph_length+20]
                    tcp_header = struct.unpack('!HHLLBBHHH', tcp_header)
                    
                    source_port = tcp_header[0]
                    dest_port = tcp_header[1]
                    sequence = tcp_header[2]
                    acknowledgement = tcp_header[3]
                    
                    # Create connection identifier
                    conn_id = f"{s_addr}:{source_port}-{d_addr}:{dest_port}"
                    
                    # Update connection statistics
                    self.connections[conn_id]['packets'] += 1
                    self.connections[conn_id]['bytes'] += len(raw_data)
                    
                    # Find routing information
                    route = self.find_route(d_addr)
                    route_info = f"Route: {route[0]} via {route[1]['next_hop']}" if route else "No route found"
                    
                    # Print packet information
                    print(f"\nPacket Captured at {datetime.now()}")
                    print(f"Source: {s_addr}:{source_port}")
                    print(f"Destination: {d_addr}:{dest_port}")
                    print(f"Protocol: TCP")
                    print(f"Sequence Number: {sequence}")
                    print(f"Acknowledgement: {acknowledgement}")
                    print(route_info)
                    print("-" * 50)
        
        except KeyboardInterrupt:
            print("\nCapture stopped by user")
        
        self.print_statistics()

    def print_statistics(self):
        print("\nConnection Statistics:")
        print("-" * 50)
        for conn_id, stats in self.connections.items():
            print(f"\nConnection: {conn_id}")
            print(f"Total Packets: {stats['packets']}")
            print(f"Total Bytes: {stats['bytes']}")
        print("-" * 50)

def main():
    analyzer = PacketSniffer()
    
    # Add some example routes
    analyzer.add_route("192.168.1.0/24", "192.168.1.1", 1)
    analyzer.add_route("10.0.0.0/8", "10.0.0.1", 2)
    analyzer.add_route("172.16.0.0/12", "172.16.0.1", 3)
    
    print("\nNetwork Protocol Analyzer")
    print("------------------------")
    print("This program will capture and analyze TCP packets for 60 seconds.")
    print("Note: This program requires root/administrator privileges to run.")
    print("Press Ctrl+C to stop the capture early.")
    
    # Start packet capture
    analyzer.start_capture(60)

if __name__ == "__main__":
    main()