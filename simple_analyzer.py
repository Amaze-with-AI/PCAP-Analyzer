#!/usr/bin/env python3
"""
Simple PCAP Protocol Analyzer with MCP Integration
Analyzes TCP, UDP, HTTP, HTTPS, and QUIC protocols with flow filtering
"""

import json
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from scapy.all import *

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

@dataclass
class FlowInfo:
    """Information about a network flow"""
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    packet_count: int
    total_bytes: int
    first_seen: float
    last_seen: float
    packets: List[Dict] = None

class SimpleProtocolAnalyzer:
    """Simple protocol analyzer for TCP, UDP, HTTP, HTTPS, and QUIC"""
    
    def __init__(self):
        self.flows = {}
        self.protocols_detected = set()
        self.total_packets = 0
        
    def analyze_pcap(self, pcap_file: str) -> Dict[str, Any]:
        """Analyze PCAP file and extract protocol information"""
        logger.info(f"Starting analysis of {pcap_file}")
        
        try:
            packets = rdpcap(pcap_file)
            self.total_packets = len(packets)
            logger.info(f"Loaded {len(packets)} packets")
            
            for i, packet in enumerate(packets):
                self._analyze_packet(packet)
                
                if (i + 1) % 1000 == 0:
                    logger.info(f"Processed {i + 1}/{len(packets)} packets")
            
            logger.info("Analysis complete")
            return self._generate_summary()
            
        except Exception as e:
            logger.error(f"Error analyzing PCAP: {e}")
            return {"error": str(e)}
    
    def _analyze_packet(self, packet):
        """Analyze individual packet"""
        # Extract basic info
        if not packet.haslayer(IP):
            return
            
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        
        # Determine protocol and ports
        protocol = "Unknown"
        src_port = 0
        dst_port = 0
        
        if packet.haslayer(TCP):
            protocol = self._determine_tcp_protocol(packet)
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            self.protocols_detected.add("TCP")
            
        elif packet.haslayer(UDP):
            protocol = self._determine_udp_protocol(packet)
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            self.protocols_detected.add("UDP")
        
        # Create flow key
        flow_key = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}"
        
        # Update flow information
        if flow_key not in self.flows:
            self.flows[flow_key] = FlowInfo(
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=protocol,
                packet_count=0,
                total_bytes=0,
                first_seen=float(packet.time),
                last_seen=float(packet.time),
                packets=[]
            )
        
        flow = self.flows[flow_key]
        flow.packet_count += 1
        flow.total_bytes += len(packet)
        flow.last_seen = float(packet.time)
        
        # Store packet details
        packet_info = {
            'timestamp': float(packet.time),
            'size': len(packet),
            'protocol': protocol
        }
        
        # Add protocol-specific details
        if packet.haslayer(Raw):
            payload = bytes(packet[Raw].load)
            packet_info['payload_size'] = len(payload)
            
            # Check for HTTP
            if protocol in ["HTTP", "HTTPS"]:
                packet_info.update(self._analyze_http_packet(payload))
        
        flow.packets.append(packet_info)
        self.protocols_detected.add(protocol)
    
    def _determine_tcp_protocol(self, packet) -> str:
        """Determine TCP-based protocol"""
        tcp_layer = packet[TCP]
        
        # Common HTTP ports
        if tcp_layer.dport in [80, 8080] or tcp_layer.sport in [80, 8080]:
            return "HTTP"
        elif tcp_layer.dport in [443, 8443] or tcp_layer.sport in [443, 8443]:
            return "HTTPS"
        else:
            return "TCP"
    
    def _determine_udp_protocol(self, packet) -> str:
        """Determine UDP-based protocol"""
        udp_layer = packet[UDP]
        
        # Check for QUIC (usually on port 443)
        if udp_layer.dport == 443 or udp_layer.sport == 443:
            if packet.haslayer(Raw):
                payload = bytes(packet[Raw].load)
                if self._is_quic_packet(payload):
                    return "QUIC"
        
        # DNS
        if udp_layer.dport == 53 or udp_layer.sport == 53:
            return "DNS"
        
        return "UDP"
    
    def _is_quic_packet(self, payload: bytes) -> bool:
        """Simple QUIC packet detection"""
        if len(payload) < 1:
            return False
        
        first_byte = payload[0]
        # Check for QUIC long header (bit 0x80 set)
        return (first_byte & 0x80) != 0
    
    def _analyze_http_packet(self, payload: bytes) -> Dict:
        """Analyze HTTP packet payload"""
        try:
            payload_str = payload.decode('utf-8', errors='ignore')
            
            # HTTP Request
            if payload_str.startswith(('GET ', 'POST ', 'PUT ', 'DELETE ', 'HEAD ')):
                lines = payload_str.split('\r\n')
                if lines:
                    request_parts = lines[0].split(' ')
                    return {
                        'http_method': request_parts[0] if len(request_parts) > 0 else 'Unknown',
                        'http_uri': request_parts[1] if len(request_parts) > 1 else '/',
                        'http_version': request_parts[2] if len(request_parts) > 2 else 'Unknown'
                    }
            
            # HTTP Response
            elif payload_str.startswith('HTTP/'):
                lines = payload_str.split('\r\n')
                if lines:
                    response_parts = lines[0].split(' ')
                    return {
                        'http_version': response_parts[0] if len(response_parts) > 0 else 'Unknown',
                        'http_status': response_parts[1] if len(response_parts) > 1 else '000',
                        'http_reason': ' '.join(response_parts[2:]) if len(response_parts) > 2 else ''
                    }
        except:
            pass
        
        return {}
    
    def filter_by_ip(self, ip_address: str) -> List[FlowInfo]:
        """Filter flows by IP address (source or destination)"""
        matching_flows = []
        for flow in self.flows.values():
            if flow.src_ip == ip_address or flow.dst_ip == ip_address:
                matching_flows.append(flow)
        return matching_flows
    
    def filter_by_port(self, port: int) -> List[FlowInfo]:
        """Filter flows by port (source or destination)"""
        matching_flows = []
        for flow in self.flows.values():
            if flow.src_port == port or flow.dst_port == port:
                matching_flows.append(flow)
        return matching_flows
    
    def filter_by_protocol(self, protocol: str) -> List[FlowInfo]:
        """Filter flows by protocol"""
        matching_flows = []
        for flow in self.flows.values():
            if flow.protocol.upper() == protocol.upper():
                matching_flows.append(flow)
        return matching_flows
    
    def get_flow_sequence(self, src_ip: str = None, dst_ip: str = None, 
                         src_port: int = None, dst_port: int = None) -> List[FlowInfo]:
        """Get complete flow sequence based on filters"""
        matching_flows = []
        
        for flow in self.flows.values():
            match = True
            
            if src_ip and flow.src_ip != src_ip:
                match = False
            if dst_ip and flow.dst_ip != dst_ip:
                match = False
            if src_port and flow.src_port != src_port:
                match = False
            if dst_port and flow.dst_port != dst_port:
                match = False
            
            if match:
                matching_flows.append(flow)
        
        # Sort by first seen timestamp
        matching_flows.sort(key=lambda x: x.first_seen)
        return matching_flows
    
    def _generate_summary(self) -> Dict[str, Any]:
        """Generate analysis summary"""
        return {
            'timestamp': datetime.now().isoformat(),
            'total_packets': self.total_packets,
            'total_flows': len(self.flows),
            'protocols_detected': sorted(list(self.protocols_detected)),
            'flows': {k: asdict(v) for k, v in self.flows.items()},
            'protocol_stats': self._get_protocol_stats()
        }
    
    def _get_protocol_stats(self) -> Dict[str, int]:
        """Get protocol statistics"""
        stats = {}
        for flow in self.flows.values():
            protocol = flow.protocol
            if protocol not in stats:
                stats[protocol] = 0
            stats[protocol] += flow.packet_count
        return stats

def main():
    """Main function for command line usage"""
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python simple_analyzer.py <pcap_file>")
        print("Example: python simple_analyzer.py capture.pcap")
        return
    
    pcap_file = sys.argv[1]
    analyzer = SimpleProtocolAnalyzer()
    
    # Analyze PCAP
    results = analyzer.analyze_pcap(pcap_file)
    
    if 'error' in results:
        print(f"Error: {results['error']}")
        return
    
    # Display summary
    print(f"\n📊 PCAP Analysis Summary")
    print(f"=" * 50)
    print(f"Total Packets: {results['total_packets']}")
    print(f"Total Flows: {results['total_flows']}")
    print(f"Protocols Detected: {', '.join(results['protocols_detected'])}")
    
    print(f"\n📈 Protocol Statistics:")
    for protocol, count in results['protocol_stats'].items():
        print(f"  {protocol}: {count} packets")
    
    print(f"\n🔍 Top 10 Flows by Packet Count:")
    flows_by_packets = sorted(
        [(k, v) for k, v in results['flows'].items()], 
        key=lambda x: x[1]['packet_count'], 
        reverse=True
    )
    
    for i, (flow_key, flow_info) in enumerate(flows_by_packets[:10], 1):
        print(f"  {i}. {flow_key}")
        print(f"     Protocol: {flow_info['protocol']}, Packets: {flow_info['packet_count']}, Bytes: {flow_info['total_bytes']}")

if __name__ == "__main__":
    main()