"""
PCAP Analyzer MCP Server - Read and analyze PCAP network capture files.
Generated via Claude Opus 4.5
"""

import json
from mcp.server.fastmcp import FastMCP

from pcap_tools import PCAPAnalyzer

# Initialize the MCP server
mcp = FastMCP("pcap-analyzer")


@mcp.tool()
async def read_pcap_summary(file_path: str) -> str:
    """
    Read a PCAP file and return a summary of its contents.

    Args:
        file_path: Absolute path to the PCAP or PCAPNG file.

    Returns:
        JSON string containing summary statistics including:
        - Total packets and bytes
        - Protocol distribution
        - Top source/destination IPs
        - Top source/destination ports
        - Time range and duration
    """
    try:
        analyzer = PCAPAnalyzer(file_path)
        summary = analyzer.get_summary()
        return json.dumps(summary, indent=2)
    except FileNotFoundError as e:
        return json.dumps({"error": str(e)})
    except Exception as e:
        return json.dumps({"error": f"Failed to analyze PCAP: {str(e)}"})


@mcp.tool()
async def filter_packets(
    file_path: str,
    protocol: str | None = None,
    src_ip: str | None = None,
    dst_ip: str | None = None,
    src_port: int | None = None,
    dst_port: int | None = None,
    limit: int = 100,
) -> str:
    """
    Filter and extract packets from a PCAP file based on specified criteria.

    Args:
        file_path: Absolute path to the PCAP or PCAPNG file.
        protocol: Filter by protocol (TCP, UDP, ICMP, DNS, ARP). Optional.
        src_ip: Filter by source IP address. Optional.
        dst_ip: Filter by destination IP address. Optional.
        src_port: Filter by source port number. Optional.
        dst_port: Filter by destination port number. Optional.
        limit: Maximum number of packets to return (default: 100).

    Returns:
        JSON string containing matching packets with detailed layer information.
    """
    try:
        analyzer = PCAPAnalyzer(file_path)
        packets = analyzer.filter_packets(
            protocol=protocol,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            limit=limit,
        )
        return json.dumps(
            {"count": len(packets), "packets": packets},
            indent=2,
        )
    except FileNotFoundError as e:
        return json.dumps({"error": str(e)})
    except Exception as e:
        return json.dumps({"error": f"Failed to filter packets: {str(e)}"})


@mcp.tool()
async def get_conversations(file_path: str, limit: int = 50) -> str:
    """
    Extract network conversations (communication between IP pairs) from a PCAP file.

    Args:
        file_path: Absolute path to the PCAP or PCAPNG file.
        limit: Maximum number of conversations to return (default: 50).

    Returns:
        JSON string containing conversations sorted by total packets,
        including packet counts and byte counts in each direction.
    """
    try:
        analyzer = PCAPAnalyzer(file_path)
        conversations = analyzer.get_conversations(limit=limit)
        return json.dumps(
            {"count": len(conversations), "conversations": conversations},
            indent=2,
        )
    except FileNotFoundError as e:
        return json.dumps({"error": str(e)})
    except Exception as e:
        return json.dumps({"error": f"Failed to extract conversations: {str(e)}"})


@mcp.tool()
async def extract_dns_queries(file_path: str, limit: int = 100) -> str:
    """
    Extract DNS queries and responses from a PCAP file.

    Args:
        file_path: Absolute path to the PCAP or PCAPNG file.
        limit: Maximum number of DNS entries to return (default: 100).

    Returns:
        JSON string containing DNS queries with query names, types,
        and resolved answers for responses.
    """
    try:
        analyzer = PCAPAnalyzer(file_path)
        dns_queries = analyzer.extract_dns_queries(limit=limit)
        return json.dumps(
            {"count": len(dns_queries), "dns_queries": dns_queries},
            indent=2,
        )
    except FileNotFoundError as e:
        return json.dumps({"error": str(e)})
    except Exception as e:
        return json.dumps({"error": f"Failed to extract DNS queries: {str(e)}"})


@mcp.tool()
async def get_http_requests(file_path: str, limit: int = 100) -> str:
    """
    Extract HTTP requests from a PCAP file.

    Args:
        file_path: Absolute path to the PCAP or PCAPNG file.
        limit: Maximum number of HTTP requests to return (default: 100).

    Returns:
        JSON string containing HTTP requests with method, URI, headers, and host.
    """
    try:
        analyzer = PCAPAnalyzer(file_path)
        http_requests = analyzer.get_http_requests(limit=limit)
        return json.dumps(
            {"count": len(http_requests), "http_requests": http_requests},
            indent=2,
        )
    except FileNotFoundError as e:
        return json.dumps({"error": str(e)})
    except Exception as e:
        return json.dumps({"error": f"Failed to extract HTTP requests: {str(e)}"})


@mcp.tool()
async def detect_anomalies(file_path: str) -> str:
    """
    Detect potential anomalies and security concerns in a PCAP file.

    This tool analyzes the PCAP for suspicious patterns including:
    - Potential port scans (many unique destination ports from one source)
    - Large packets (over 1500 bytes)
    - Suspicious ports (commonly used by malware)
    - High frequency sources (potential DoS or scanning activity)

    Args:
        file_path: Absolute path to the PCAP or PCAPNG file.

    Returns:
        JSON string containing categorized anomalies and security concerns.
    """
    try:
        analyzer = PCAPAnalyzer(file_path)
        anomalies = analyzer.detect_anomalies()
        return json.dumps(anomalies, indent=2)
    except FileNotFoundError as e:
        return json.dumps({"error": str(e)})
    except Exception as e:
        return json.dumps({"error": f"Failed to detect anomalies: {str(e)}"})


def main():
    """Run the MCP server."""
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
