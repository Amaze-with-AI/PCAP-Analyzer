#!/usr/bin/env python3
"""
MCP Server for Simple PCAP Protocol Analyzer
Provides LLM integration for network flow analysis via Model Context Protocol
"""

import asyncio
import json
import sys
import os
from typing import Any, Dict, List, Optional
from datetime import datetime
import logging

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# MCP Server imports
from mcp.server.fastmcp import FastMCP

from simple_analyzer import SimpleProtocolAnalyzer

# Global analyzer instance with persistence
analyzer = None
current_pcap = None
analysis_results = None

# PCAP files directory
PCAPS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "PCAPs")

def find_pcap_file(filename: str) -> str:
    """Find PCAP file in PCAPs folder or return absolute path if provided"""
    if os.path.isabs(filename) and os.path.exists(filename):
        return filename
    
    # Check in PCAPs directory
    pcap_path = os.path.join(PCAPS_DIR, filename)
    if os.path.exists(pcap_path):
        return pcap_path
    
    # If filename doesn't have extension, try adding .pcap
    if not filename.endswith('.pcap'):
        pcap_with_ext = os.path.join(PCAPS_DIR, f"{filename}.pcap")
        if os.path.exists(pcap_with_ext):
            return pcap_with_ext
    
    return filename  # Return original if not found

# Create FastMCP server
mcp = FastMCP("PCAP Analyzer")

@mcp.tool()
def load_pcap_file(pcap_file: str) -> str:
    """Load and analyze a PCAP file for network flow analysis"""
    global analyzer, current_pcap, analysis_results
    
    # Find the actual PCAP file path
    actual_pcap_path = find_pcap_file(pcap_file)
    
    if not os.path.exists(actual_pcap_path):
        # List available PCAP files in PCAPs directory
        available_files = []
        if os.path.exists(PCAPS_DIR):
            available_files = [f for f in os.listdir(PCAPS_DIR) if f.endswith('.pcap')]
        
        error_msg = f"❌ PCAP file not found: {pcap_file}"
        if available_files:
            error_msg += f"\n\n📁 Available PCAP files in PCAPs folder:"
            for file in available_files:
                error_msg += f"\n  • {file}"
            error_msg += f"\n\n💡 Try: load_pcap_file('filename.pcap')"
        else:
            error_msg += f"\n\n📁 PCAPs folder is empty. Please add PCAP files to: {PCAPS_DIR}"
        
        return error_msg
    
    try:
        analyzer = SimpleProtocolAnalyzer()
        current_pcap = actual_pcap_path
        analysis_results = analyzer.analyze_pcap(actual_pcap_path)
        
        if 'error' in analysis_results:
            return f"❌ Analysis error: {analysis_results['error']}"
        
        results = analysis_results
        summary = f"""✅ PCAP File Loaded Successfully: {os.path.basename(actual_pcap_path)}
{'=' * 60}

📊 Analysis Summary:
  • Total Packets: {results['total_packets']:,}
  • Total Flows: {results['total_flows']:,}
  • Protocols Detected: {', '.join(results['protocols_detected'])}
  • File Size: {os.path.getsize(actual_pcap_path):,} bytes

📈 Protocol Distribution:"""
        
        for protocol, count in results['protocol_stats'].items():
            percentage = (count / results['total_packets'] * 100) if results['total_packets'] > 0 else 0
            summary += f"\n  • {protocol}: {count:,} packets ({percentage:.1f}%)"
        
        summary += f"\n\n🔍 Ready for analysis! You can now:"
        summary += f"\n  • Analyze flows by port: analyze_port_flows"
        summary += f"\n  • Analyze flows by IP: analyze_ip_flows"  
        summary += f"\n  • Analyze by protocol: analyze_protocol_flows"
        
        logger.info(f"Successfully loaded {actual_pcap_path}")
        return summary
        
    except Exception as e:
        error_msg = f"❌ Error loading PCAP: {str(e)}"
        logger.error(error_msg)
        return error_msg

@mcp.tool()
def analyze_port_flows(port: int) -> str:
    """Analyze network flows for a specific port number"""
    global analyzer, current_pcap
    
    if not analyzer:
        return "❌ No PCAP file loaded. Use load_pcap_file first."
    
    try:
        # Get flows matching the port
        matching_flows = analyzer.filter_by_port(port)
        
        if not matching_flows:
            return f"❌ No flows found for port {port} in {os.path.basename(current_pcap)}"
        
        # Build detailed flow analysis
        result = f"🔍 Flow Analysis for Port {port}\n"
        result += f"PCAP File: {os.path.basename(current_pcap)}\n"
        result += f"{'=' * 60}\n\n"
        
        result += f"📊 Summary:\n"
        result += f"  • Found {len(matching_flows)} flows involving port {port}\n"
        
        total_packets = sum(flow.packet_count for flow in matching_flows)
        total_bytes = sum(flow.total_bytes for flow in matching_flows)
        result += f"  • Total packets: {total_packets:,}\n"
        result += f"  • Total bytes: {total_bytes:,}\n\n"
        
        # Analyze each flow in detail
        result += f"🔍 Detailed Flow Analysis:\n\n"
        
        for i, flow in enumerate(matching_flows, 1):
            duration = flow.last_seen - flow.first_seen
            start_time = datetime.fromtimestamp(flow.first_seen).strftime('%H:%M:%S.%f')[:-3]
            end_time = datetime.fromtimestamp(flow.last_seen).strftime('%H:%M:%S.%f')[:-3]
            
            # Determine flow direction
            if flow.src_port == port:
                result += f"Flow {i}: 🔄 Outbound from port {port}\n"
                result += f"  Source: {flow.src_ip}:{flow.src_port} → Destination: {flow.dst_ip}:{flow.dst_port}\n"
            else:
                result += f"Flow {i}: 🔄 Inbound to port {port}\n"
                result += f"  Source: {flow.src_ip}:{flow.src_port} → Destination: {flow.dst_ip}:{flow.dst_port}\n"
            
            result += f"  Protocol: {flow.protocol}\n"
            result += f"  Timeline: {start_time} → {end_time} (Duration: {duration:.3f}s)\n"
            result += f"  Traffic Volume: {flow.packet_count:,} packets, {flow.total_bytes:,} bytes\n"
            
            # Calculate throughput
            if duration > 0:
                pps = flow.packet_count / duration
                bps = flow.total_bytes / duration
                result += f"  Throughput: {pps:.1f} packets/sec, {bps:,.0f} bytes/sec\n"
            
            result += "\n"
        
        # Add flow summary
        result += f"💡 Flow Analysis Summary:\n"
        protocols = set(flow.protocol for flow in matching_flows)
        result += f"  • Protocols involved: {', '.join(protocols)}\n"
        
        # Check for bidirectional flows
        src_ports = set(flow.src_port for flow in matching_flows)
        dst_ports = set(flow.dst_port for flow in matching_flows)
        
        if port in src_ports and port in dst_ports:
            result += f"  • Port {port} appears as both source and destination (bidirectional)\n"
        elif port in src_ports:
            result += f"  • Port {port} is acting as source (outbound traffic)\n"
        else:
            result += f"  • Port {port} is acting as destination (inbound traffic)\n"
        
        return result
        
    except Exception as e:
        return f"❌ Error analyzing flows for port {port}: {str(e)}"

@mcp.tool()
def analyze_ip_flows(ip_address: str) -> str:
    """Analyze network flows for a specific IP address"""
    global analyzer, current_pcap
    
    if not analyzer:
        return "❌ No PCAP file loaded. Use load_pcap_file first."
    
    try:
        matching_flows = analyzer.filter_by_ip(ip_address)
        
        if not matching_flows:
            return f"❌ No flows found for IP address {ip_address} in {os.path.basename(current_pcap)}"
        
        result = f"🔍 Flow Analysis for IP {ip_address}\n"
        result += f"PCAP File: {os.path.basename(current_pcap)}\n"
        result += f"{'=' * 60}\n\n"
        
        result += f"📊 Summary:\n"
        result += f"  • Found {len(matching_flows)} flows involving IP {ip_address}\n"
        
        total_packets = sum(flow.packet_count for flow in matching_flows)
        total_bytes = sum(flow.total_bytes for flow in matching_flows)
        result += f"  • Total packets: {total_packets:,}\n"
        result += f"  • Total bytes: {total_bytes:,}\n\n"
        
        # Analyze flows by direction
        inbound_flows = [f for f in matching_flows if f.dst_ip == ip_address]
        outbound_flows = [f for f in matching_flows if f.src_ip == ip_address]
        
        result += f"📡 Traffic Direction Analysis:\n"
        result += f"  • Inbound flows (to {ip_address}): {len(inbound_flows)}\n"
        result += f"  • Outbound flows (from {ip_address}): {len(outbound_flows)}\n\n"
        
        # Detailed flow analysis
        result += f"🔍 Detailed Flow Analysis:\n\n"
        
        for i, flow in enumerate(matching_flows, 1):
            duration = flow.last_seen - flow.first_seen
            start_time = datetime.fromtimestamp(flow.first_seen).strftime('%H:%M:%S.%f')[:-3]
            end_time = datetime.fromtimestamp(flow.last_seen).strftime('%H:%M:%S.%f')[:-3]
            
            # Determine direction
            if flow.src_ip == ip_address:
                result += f"Flow {i}: 📤 Outbound from {ip_address}\n"
                result += f"  {flow.src_ip}:{flow.src_port} → {flow.dst_ip}:{flow.dst_port}\n"
            else:
                result += f"Flow {i}: 📥 Inbound to {ip_address}\n"
                result += f"  {flow.src_ip}:{flow.src_port} → {flow.dst_ip}:{flow.dst_port}\n"
            
            result += f"  Protocol: {flow.protocol}\n"
            result += f"  Timeline: {start_time} → {end_time} (Duration: {duration:.3f}s)\n"
            result += f"  Traffic: {flow.packet_count:,} packets, {flow.total_bytes:,} bytes\n"
            
            if duration > 0:
                pps = flow.packet_count / duration
                bps = flow.total_bytes / duration
                result += f"  Rate: {pps:.1f} pkt/s, {bps:,.0f} bytes/s\n"
            
            result += "\n"
        
        return result
        
    except Exception as e:
        return f"❌ Error analyzing flows for IP {ip_address}: {str(e)}"

@mcp.tool()
def analyze_protocol_flows(protocol: str) -> str:
    """Analyze flows for a specific protocol (TCP, UDP, HTTP, HTTPS, QUIC)"""
    global analyzer, current_pcap
    
    if not analyzer:
        return "❌ No PCAP file loaded. Use load_pcap_file first."
    
    try:
        matching_flows = analyzer.filter_by_protocol(protocol.upper())
        
        if not matching_flows:
            return f"❌ No {protocol.upper()} flows found in {os.path.basename(current_pcap)}"
        
        result = f"🔍 {protocol.upper()} Protocol Flow Analysis\n"
        result += f"PCAP File: {os.path.basename(current_pcap)}\n"
        result += f"{'=' * 60}\n\n"
        
        # Protocol statistics
        total_packets = sum(flow.packet_count for flow in matching_flows)
        total_bytes = sum(flow.total_bytes for flow in matching_flows)
        total_duration = max(flow.last_seen for flow in matching_flows) - min(flow.first_seen for flow in matching_flows)
        
        result += f"📊 {protocol.upper()} Protocol Summary:\n"
        result += f"  • Flows: {len(matching_flows)}\n"
        result += f"  • Total packets: {total_packets:,}\n"
        result += f"  • Total bytes: {total_bytes:,}\n"
        result += f"  • Time span: {total_duration:.3f} seconds\n\n"
        
        # Flow analysis
        result += f"🔍 Flow Details:\n\n"
        
        # Sort by packet count
        matching_flows.sort(key=lambda x: x.packet_count, reverse=True)
        
        for i, flow in enumerate(matching_flows, 1):
            duration = flow.last_seen - flow.first_seen
            start_time = datetime.fromtimestamp(flow.first_seen).strftime('%H:%M:%S.%f')[:-3]
            end_time = datetime.fromtimestamp(flow.last_seen).strftime('%H:%M:%S.%f')[:-3]
            
            result += f"Flow {i}: {flow.src_ip}:{flow.src_port} → {flow.dst_ip}:{flow.dst_port}\n"
            result += f"  Timeline: {start_time} → {end_time} ({duration:.3f}s)\n"
            result += f"  Traffic: {flow.packet_count:,} packets, {flow.total_bytes:,} bytes\n"
            
            if duration > 0:
                pps = flow.packet_count / duration
                bps = flow.total_bytes / duration
                result += f"  Rate: {pps:.1f} pkt/s, {bps:,.0f} bytes/s\n"
            
            result += "\n"
        
        return result
        
    except Exception as e:
        return f"❌ Error analyzing {protocol} flows: {str(e)}"

@mcp.tool()
def get_pcap_summary() -> str:
    """Get a summary of the currently loaded PCAP file"""
    global analyzer, analysis_results, current_pcap
    
    if not analyzer or not analysis_results:
        return "❌ No PCAP file loaded. Use load_pcap_file first."
    
    results = analysis_results
    summary = f"""📊 PCAP File Summary: {os.path.basename(current_pcap)}
{'=' * 60}

📈 Overview:
  • Total Packets: {results['total_packets']:,}
  • Total Flows: {results['total_flows']:,}
  • Protocols: {', '.join(results['protocols_detected'])}

📊 Protocol Breakdown:"""
    
    for protocol, count in results['protocol_stats'].items():
        percentage = (count / results['total_packets'] * 100) if results['total_packets'] > 0 else 0
        summary += f"\n  • {protocol}: {count:,} packets ({percentage:.1f}%)"
    
    # Top flows summary
    if results['flows']:
        flows_by_packets = sorted(
            [(k, v) for k, v in results['flows'].items()], 
            key=lambda x: x[1]['packet_count'], 
            reverse=True
        )
        
        summary += f"\n\n🔥 Top 3 Flows:"
        for i, (flow_key, flow_info) in enumerate(flows_by_packets[:3], 1):
            summary += f"\n  {i}. {flow_key}"
            summary += f"\n     {flow_info['protocol']}: {flow_info['packet_count']:,} pkts, {flow_info['total_bytes']:,} bytes"
    
    return summary

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--mcp":
        # Run as MCP server
        logger.info("Starting PCAP Analyzer MCP Server...")
        mcp.run()
    else:
        # Show help
        print("🔍 PCAP Analyzer MCP Server")
        print("=" * 40)
        print("Usage:")
        print("  python mcp_server.py --mcp    # Run as MCP server")
        print("  python mcp_server.py          # Show this help")
        print()
        print("When running as MCP server, it provides these tools to LLMs:")
        print("  • load_pcap_file: Load a PCAP file for analysis")
        print("  • analyze_port_flows: Analyze flows for specific port")
        print("  • analyze_ip_flows: Analyze flows for specific IP")
        print("  • analyze_protocol_flows: Analyze flows by protocol")
        print("  • get_pcap_summary: Get summary of loaded PCAP")
        print()
        print("Example LLM interactions:")
        print('  LLM: "Load the PCAP file /path/to/capture.pcap"')
        print('  LLM: "Analyze the flows for port 443"')
        print('  LLM: "Show me flows for IP 192.168.1.1"')
        print('  LLM: "Analyze HTTPS protocol flows"')