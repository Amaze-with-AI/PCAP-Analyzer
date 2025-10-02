# 🔍 PCAP Analyzer with MCP Integration

A powerful network packet analysis tool with **Model Context Protocol (MCP)** integration for seamless LLM interaction. Analyze network traffic using natural language commands through AI assistants like GitHub Copilot, Claude, or ChatGPT.

## 🌟 Features

### 🚀 **Core Analysis Capabilities**
- **Protocol Detection**: TCP, UDP, HTTP, HTTPS, QUIC
- **Flow Analysis**: Bidirectional traffic patterns with timing and throughput
- **Port Analysis**: Detailed analysis of specific ports with security insights
- **IP Analysis**: Inbound/outbound traffic analysis for specific hosts
- **Security Detection**: Automatic identification of scanning, reconnaissance, and anomalous patterns

### 🤖 **MCP Integration**
- **Natural Language Interface**: Ask AI assistants to analyze network traffic
- **VS Code Integration**: Works with GitHub Copilot and other LLM extensions
- **Real-time Analysis**: Interactive PCAP analysis through conversational AI
- **Automated Reporting**: AI-generated security assessments and recommendations

### 🛡️ **Security Features**
- **Threat Detection**: Identifies network scanning and reconnaissance attempts
- **Anomaly Detection**: Flags unusual traffic patterns and failed connections
- **Attack Pattern Recognition**: Detects coordinated scanning campaigns
- **Security Reporting**: Detailed threat analysis with actionable recommendations

## 📋 Prerequisites

- **Python 3.8+**
- **Scapy library** for packet analysis
- **FastMCP framework** for LLM integration
- **VS Code** (optional, for MCP integration)

## 🚀 Quick Start

### 1. **Installation**

```bash
# Clone the repository
git clone <your-repo-url>
cd PCAP_Analyser

# Install dependencies
pip install -r requirements.txt
```

### 2. **Basic Usage**

#### **Direct Python Analysis**
```python
from simple_analyzer import SimpleProtocolAnalyzer

# Create analyzer instance
analyzer = SimpleProtocolAnalyzer()

# Analyze PCAP file
results = analyzer.analyze_pcap('path/to/your/capture.pcap')

# Filter by port
port_flows = analyzer.filter_by_port(443)

# Filter by IP
ip_flows = analyzer.filter_by_ip('192.168.1.1')
```

#### **MCP Server Mode (for AI Integration)**
```bash
# Start MCP server
python3 mcp_server.py --mcp

# The server will listen for LLM requests
```

### 3. **VS Code + AI Integration**

1. **Configure VS Code MCP** (create `.vscode/mcp.json`):
```json
{
  "mcpServers": {
    "pcap-analyzer": {
      "command": "python3",
      "args": ["mcp_server.py", "--mcp"],
      "cwd": "/path/to/PCAP_Analyser",
      "env": {
        "PYTHONPATH": "/path/to/PCAP_Analyser"
      }
    }
  }
}
```

2. **Use with AI Assistant**:
```
"Load the network capture tcp-logs.pcap"
"Analyze flows for port 443"
"Check if there are any security issues with port 51570"
"Show me all HTTPS traffic patterns"
"Is there any scanning activity in this capture?"
```

## 📁 File Structure

```
PCAP_Analyser/
├── README.md                 # This file
├── requirements.txt          # Python dependencies
├── simple_analyzer.py        # Core PCAP analysis engine
├── mcp_server.py            # MCP server for LLM integration
├── mcp_config.json          # MCP configuration
├── PCAPs/                   # Directory for PCAP files
│   ├── tcp.pcap             # Sample TCP logs
```

## 🔧 MCP Tools Available

### **1. load_pcap_file**
```python
# Load PCAP file for analysis
load_pcap_file('capture.pcap')
```

### **2. analyze_port_flows**
```python
# Analyze specific port traffic
analyze_port_flows(443)  # HTTPS traffic
analyze_port_flows(22)   # SSH traffic
```

### **3. analyze_ip_flows**
```python
# Analyze specific IP address
analyze_ip_flows('192.168.1.100')
```

### **4. analyze_protocol_flows**
```python
# Analyze by protocol
analyze_protocol_flows('TCP')
analyze_protocol_flows('HTTPS')
analyze_protocol_flows('QUIC')
```

### **5. get_pcap_summary**
```python
# Get overall PCAP summary
get_pcap_summary()
```

## 🛡️ Security Analysis Examples

### **Network Scanning Detection**
```python
# The analyzer automatically detects:
# - Port scanning attempts
# - Failed connection patterns
# - Reconnaissance activities
# - Coordinated attack campaigns

# Example output:
"""
🚨 SECURITY ISSUE DETECTED for Port 51570
❌ Part of Massive Scanning Campaign
- Same attacker: 10.10.28.14
- Same target: 10.10.28.35:1470
- Pattern: Failed connection attempts
- Duration: 2+ hours of sustained activity
"""
```

### **QUIC Analysis**
```python
# Analyze QUIC version negotiation failures
analyze_protocol_flows('QUIC')

# Detects:
# - Version negotiation failures
# - Protocol compatibility issues
# - Connection establishment problems
```

## 📊 Sample Analysis Output

```
🔍 Flow Analysis for Port 443
PCAP File: network_capture.pcap
============================================================

📊 Summary:
  • Found 2 flows involving port 443
  • Total packets: 28,794
  • Total bytes: 26,966,480

🔍 Detailed Flow Analysis:

Flow 1: 🔄 Outbound from port 443
  Source: 192.168.1.10:41948 → Destination: 192.168.1.20:443
  Protocol: HTTPS
  Timeline: 21:23:11.982 → 21:23:48.572 (Duration: 36.590s)
  Traffic Volume: 9,610 packets, 519,907 bytes
  Throughput: 262.6 packets/sec, 14,209 bytes/sec

💡 Flow Analysis Summary:
  • Protocols involved: HTTPS
  • Normal HTTPS traffic pattern detected
  • No security issues identified
```

## 🎯 Use Cases

### **Network Security Analysis**
- Detect port scanning and network reconnaissance
- Identify failed connection attempts and attack patterns
- Analyze protocol-specific vulnerabilities
- Generate automated security reports

### **Performance Monitoring**
- Analyze network throughput and latency
- Identify bandwidth-heavy applications
- Monitor connection patterns and duration
- Track protocol distribution

### **Troubleshooting**
- Diagnose connection failures
- Analyze protocol negotiation issues
- Identify network bottlenecks
- Debug application communication problems

### **AI-Powered Analysis**
- Natural language network analysis queries
- Automated threat detection with AI insights
- Conversational network forensics
- Intelligent pattern recognition

## 🔮 Advanced Features

### **Custom Protocol Detection**
The analyzer can be extended to detect custom protocols and application-specific patterns.

### **Real-time Analysis**
Process live network traffic or streaming PCAP data.

### **Integration Ready**
- REST API endpoints for web integration
- Command-line interface for automation
- Export capabilities (JSON, CSV, HTML reports)

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Add your enhancements
4. Submit a pull request

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🆘 Support

- **Issues**: Report bugs and request features on GitHub
- **Documentation**: Check the code comments for detailed API documentation
- **Examples**: See the `examples/` directory for usage samples

## 🙏 Acknowledgments

- **Scapy**: Powerful packet manipulation library
- **FastMCP**: Model Context Protocol implementation
- **VS Code**: Excellent MCP integration support

---

**Ready to analyze your network traffic with AI? Get started now!** 🚀