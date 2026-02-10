"""
PCAP Tools - Helper class for parsing and analyzing PCAP files.
"""

import os
from collections import Counter
from datetime import datetime
from typing import Any

from scapy.all import rdpcap, Packet, IP, TCP, UDP, ICMP, DNS, ARP, Ether, Raw


class PCAPAnalyzer:
    """Helper class for PCAP file analysis operations."""

    def __init__(self, file_path: str):
        """
        Initialize the PCAP analyzer with a file path.

        Args:
            file_path: Path to the PCAP or PCAPNG file.
        """
        self.file_path = file_path
        self.packets = None
        self._load_packets()

    def _load_packets(self) -> None:
        """Load packets from the PCAP file."""
        if not os.path.exists(self.file_path):
            raise FileNotFoundError(f"PCAP file not found: {self.file_path}")

        self.packets = rdpcap(self.file_path)

    def get_summary(self) -> dict[str, Any]:
        """
        Get a summary of the PCAP file contents.

        Returns:
            Dictionary containing summary statistics.
        """
        if not self.packets:
            return {"error": "No packets loaded"}

        protocols = Counter()
        src_ips = Counter()
        dst_ips = Counter()
        src_ports = Counter()
        dst_ports = Counter()
        total_bytes = 0

        for pkt in self.packets:
            total_bytes += len(pkt)

            # Count protocols
            if IP in pkt:
                src_ips[pkt[IP].src] += 1
                dst_ips[pkt[IP].dst] += 1

                if TCP in pkt:
                    protocols["TCP"] += 1
                    src_ports[pkt[TCP].sport] += 1
                    dst_ports[pkt[TCP].dport] += 1
                elif UDP in pkt:
                    protocols["UDP"] += 1
                    src_ports[pkt[UDP].sport] += 1
                    dst_ports[pkt[UDP].dport] += 1
                elif ICMP in pkt:
                    protocols["ICMP"] += 1
                else:
                    protocols["Other IP"] += 1
            elif ARP in pkt:
                protocols["ARP"] += 1
            else:
                protocols["Other"] += 1

            if DNS in pkt:
                protocols["DNS"] += 1

        # Get time range
        timestamps = [float(pkt.time) for pkt in self.packets if hasattr(pkt, "time")]
        start_time = datetime.fromtimestamp(min(timestamps)) if timestamps else None
        end_time = datetime.fromtimestamp(max(timestamps)) if timestamps else None
        duration = (max(timestamps) - min(timestamps)) if timestamps else 0

        return {
            "file_path": self.file_path,
            "total_packets": len(self.packets),
            "total_bytes": total_bytes,
            "protocols": dict(protocols.most_common(10)),
            "top_source_ips": dict(src_ips.most_common(10)),
            "top_destination_ips": dict(dst_ips.most_common(10)),
            "top_source_ports": dict(src_ports.most_common(10)),
            "top_destination_ports": dict(dst_ports.most_common(10)),
            "start_time": start_time.isoformat() if start_time else None,
            "end_time": end_time.isoformat() if end_time else None,
            "duration_seconds": round(duration, 2),
        }

    def filter_packets(
        self,
        protocol: str | None = None,
        src_ip: str | None = None,
        dst_ip: str | None = None,
        src_port: int | None = None,
        dst_port: int | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """
        Filter packets based on specified criteria.

        Args:
            protocol: Filter by protocol (TCP, UDP, ICMP, DNS, ARP).
            src_ip: Filter by source IP address.
            dst_ip: Filter by destination IP address.
            src_port: Filter by source port.
            dst_port: Filter by destination port.
            limit: Maximum number of packets to return.

        Returns:
            List of packet dictionaries matching the filter criteria.
        """
        if not self.packets:
            return []

        results = []

        for pkt in self.packets:
            if len(results) >= limit:
                break

            # Protocol filter
            if protocol:
                protocol_upper = protocol.upper()
                if protocol_upper == "TCP" and TCP not in pkt:
                    continue
                elif protocol_upper == "UDP" and UDP not in pkt:
                    continue
                elif protocol_upper == "ICMP" and ICMP not in pkt:
                    continue
                elif protocol_upper == "DNS" and DNS not in pkt:
                    continue
                elif protocol_upper == "ARP" and ARP not in pkt:
                    continue

            # IP filters
            if src_ip and (IP not in pkt or pkt[IP].src != src_ip):
                continue
            if dst_ip and (IP not in pkt or pkt[IP].dst != dst_ip):
                continue

            # Port filters
            if src_port:
                if TCP in pkt and pkt[TCP].sport != src_port:
                    continue
                elif UDP in pkt and pkt[UDP].sport != src_port:
                    continue
                elif TCP not in pkt and UDP not in pkt:
                    continue

            if dst_port:
                if TCP in pkt and pkt[TCP].dport != dst_port:
                    continue
                elif UDP in pkt and pkt[UDP].dport != dst_port:
                    continue
                elif TCP not in pkt and UDP not in pkt:
                    continue

            results.append(self._packet_to_dict(pkt))

        return results

    def _packet_to_dict(self, pkt: Packet) -> dict[str, Any]:
        """
        Convert a Scapy packet to a dictionary representation.

        Args:
            pkt: Scapy Packet object.

        Returns:
            Dictionary representation of the packet.
        """
        result = {
            "timestamp": datetime.fromtimestamp(float(pkt.time)).isoformat()
            if hasattr(pkt, "time")
            else None,
            "length": len(pkt),
            "layers": [],
        }

        # Ethernet layer
        if Ether in pkt:
            result["ethernet"] = {
                "src_mac": pkt[Ether].src,
                "dst_mac": pkt[Ether].dst,
                "type": hex(pkt[Ether].type),
            }
            result["layers"].append("Ethernet")

        # IP layer
        if IP in pkt:
            result["ip"] = {
                "src": pkt[IP].src,
                "dst": pkt[IP].dst,
                "ttl": pkt[IP].ttl,
                "protocol": pkt[IP].proto,
                "length": pkt[IP].len,
            }
            result["layers"].append("IP")

        # TCP layer
        if TCP in pkt:
            result["tcp"] = {
                "src_port": pkt[TCP].sport,
                "dst_port": pkt[TCP].dport,
                "seq": pkt[TCP].seq,
                "ack": pkt[TCP].ack,
                "flags": str(pkt[TCP].flags),
            }
            result["layers"].append("TCP")

        # UDP layer
        if UDP in pkt:
            result["udp"] = {
                "src_port": pkt[UDP].sport,
                "dst_port": pkt[UDP].dport,
                "length": pkt[UDP].len,
            }
            result["layers"].append("UDP")

        # ICMP layer
        if ICMP in pkt:
            result["icmp"] = {
                "type": pkt[ICMP].type,
                "code": pkt[ICMP].code,
            }
            result["layers"].append("ICMP")

        # DNS layer
        if DNS in pkt:
            dns_info = {"id": pkt[DNS].id, "qr": pkt[DNS].qr}
            if pkt[DNS].qd:
                dns_info["query"] = pkt[DNS].qd.qname.decode() if pkt[DNS].qd.qname else None
            result["dns"] = dns_info
            result["layers"].append("DNS")

        # ARP layer
        if ARP in pkt:
            result["arp"] = {
                "op": pkt[ARP].op,
                "src_mac": pkt[ARP].hwsrc,
                "src_ip": pkt[ARP].psrc,
                "dst_mac": pkt[ARP].hwdst,
                "dst_ip": pkt[ARP].pdst,
            }
            result["layers"].append("ARP")

        # Raw payload
        if Raw in pkt:
            payload = pkt[Raw].load
            try:
                # Try to decode as UTF-8 for display
                result["payload_preview"] = payload[:200].decode("utf-8", errors="replace")
            except Exception:
                result["payload_preview"] = payload[:200].hex()
            result["payload_length"] = len(payload)

        return result

    def get_conversations(self, limit: int = 50) -> list[dict[str, Any]]:
        """
        Extract network conversations (IP pairs and their communication).

        Args:
            limit: Maximum number of conversations to return.

        Returns:
            List of conversation dictionaries.
        """
        if not self.packets:
            return []

        conversations = {}

        for pkt in self.packets:
            if IP not in pkt:
                continue

            src = pkt[IP].src
            dst = pkt[IP].dst

            # Create a canonical key (smaller IP first)
            key = tuple(sorted([src, dst]))

            if key not in conversations:
                conversations[key] = {
                    "ip_a": key[0],
                    "ip_b": key[1],
                    "packets_a_to_b": 0,
                    "packets_b_to_a": 0,
                    "bytes_a_to_b": 0,
                    "bytes_b_to_a": 0,
                    "protocols": set(),
                }

            conv = conversations[key]

            if src == key[0]:
                conv["packets_a_to_b"] += 1
                conv["bytes_a_to_b"] += len(pkt)
            else:
                conv["packets_b_to_a"] += 1
                conv["bytes_b_to_a"] += len(pkt)

            if TCP in pkt:
                conv["protocols"].add("TCP")
            elif UDP in pkt:
                conv["protocols"].add("UDP")
            elif ICMP in pkt:
                conv["protocols"].add("ICMP")

        # Convert to list and sort by total packets
        result = []
        for conv in conversations.values():
            conv["protocols"] = list(conv["protocols"])
            conv["total_packets"] = conv["packets_a_to_b"] + conv["packets_b_to_a"]
            conv["total_bytes"] = conv["bytes_a_to_b"] + conv["bytes_b_to_a"]
            result.append(conv)

        result.sort(key=lambda x: x["total_packets"], reverse=True)

        return result[:limit]

    def extract_dns_queries(self, limit: int = 100) -> list[dict[str, Any]]:
        """
        Extract DNS queries from the PCAP file.

        Args:
            limit: Maximum number of DNS queries to return.

        Returns:
            List of DNS query dictionaries.
        """
        if not self.packets:
            return []

        results = []

        for pkt in self.packets:
            if len(results) >= limit:
                break

            if DNS not in pkt:
                continue

            dns_pkt = pkt[DNS]

            entry = {
                "timestamp": datetime.fromtimestamp(float(pkt.time)).isoformat()
                if hasattr(pkt, "time")
                else None,
                "transaction_id": dns_pkt.id,
                "is_response": bool(dns_pkt.qr),
            }

            if IP in pkt:
                entry["src_ip"] = pkt[IP].src
                entry["dst_ip"] = pkt[IP].dst

            # Query section
            if dns_pkt.qd:
                entry["query_name"] = (
                    dns_pkt.qd.qname.decode() if dns_pkt.qd.qname else None
                )
                entry["query_type"] = dns_pkt.qd.qtype

            # Answer section (for responses)
            if dns_pkt.qr and dns_pkt.an:
                answers = []
                for i in range(dns_pkt.ancount):
                    try:
                        an = dns_pkt.an[i]
                        answer = {
                            "name": an.rrname.decode() if hasattr(an, "rrname") else None,
                            "type": an.type,
                            "ttl": an.ttl,
                        }
                        if hasattr(an, "rdata"):
                            rdata = an.rdata
                            if isinstance(rdata, bytes):
                                answer["data"] = rdata.decode(errors="replace")
                            else:
                                answer["data"] = str(rdata)
                        answers.append(answer)
                    except Exception:
                        pass
                entry["answers"] = answers

            results.append(entry)

        return results

    def get_http_requests(self, limit: int = 100) -> list[dict[str, Any]]:
        """
        Extract HTTP requests from the PCAP file.

        Args:
            limit: Maximum number of HTTP requests to return.

        Returns:
            List of HTTP request dictionaries.
        """
        if not self.packets:
            return []

        results = []
        http_methods = [b"GET", b"POST", b"PUT", b"DELETE", b"HEAD", b"OPTIONS", b"PATCH"]

        for pkt in self.packets:
            if len(results) >= limit:
                break

            if Raw not in pkt:
                continue

            payload = pkt[Raw].load

            # Check if it starts with an HTTP method
            is_http = any(payload.startswith(method) for method in http_methods)
            if not is_http:
                continue

            entry = {
                "timestamp": datetime.fromtimestamp(float(pkt.time)).isoformat()
                if hasattr(pkt, "time")
                else None,
            }

            if IP in pkt:
                entry["src_ip"] = pkt[IP].src
                entry["dst_ip"] = pkt[IP].dst

            if TCP in pkt:
                entry["src_port"] = pkt[TCP].sport
                entry["dst_port"] = pkt[TCP].dport

            # Parse HTTP request
            try:
                lines = payload.split(b"\r\n")
                request_line = lines[0].decode(errors="replace")
                parts = request_line.split(" ")

                entry["method"] = parts[0] if len(parts) > 0 else None
                entry["uri"] = parts[1] if len(parts) > 1 else None
                entry["version"] = parts[2] if len(parts) > 2 else None

                # Extract headers
                headers = {}
                for line in lines[1:]:
                    if not line:
                        break
                    try:
                        decoded_line = line.decode(errors="replace")
                        if ": " in decoded_line:
                            key, value = decoded_line.split(": ", 1)
                            headers[key] = value
                    except Exception:
                        pass

                entry["headers"] = headers
                entry["host"] = headers.get("Host", None)

            except Exception as e:
                entry["parse_error"] = str(e)

            results.append(entry)

        return results

    def detect_anomalies(self) -> dict[str, Any]:
        """
        Detect potential anomalies and security concerns in the PCAP.

        Returns:
            Dictionary containing detected anomalies and concerns.
        """
        if not self.packets:
            return {"error": "No packets loaded"}

        anomalies = {
            "port_scans": [],
            "large_packets": [],
            "suspicious_ports": [],
            "unusual_protocols": [],
            "high_frequency_sources": [],
        }

        # Track connections per source IP
        src_connections = Counter()
        dst_port_per_src = {}

        suspicious_ports = {4444, 5555, 6666, 31337, 1337, 12345, 54321}

        for pkt in self.packets:
            if IP not in pkt:
                continue

            src_ip = pkt[IP].src
            src_connections[src_ip] += 1

            # Track destination ports per source
            if src_ip not in dst_port_per_src:
                dst_port_per_src[src_ip] = set()

            # Large packets
            if len(pkt) > 1500:
                anomalies["large_packets"].append(
                    {
                        "src": src_ip,
                        "dst": pkt[IP].dst,
                        "size": len(pkt),
                    }
                )

            # Check for suspicious ports
            if TCP in pkt:
                dst_port = pkt[TCP].dport
                dst_port_per_src[src_ip].add(dst_port)

                if dst_port in suspicious_ports or pkt[TCP].sport in suspicious_ports:
                    anomalies["suspicious_ports"].append(
                        {
                            "src": src_ip,
                            "dst": pkt[IP].dst,
                            "port": dst_port,
                        }
                    )

            elif UDP in pkt:
                dst_port = pkt[UDP].dport
                dst_port_per_src[src_ip].add(dst_port)

                if dst_port in suspicious_ports or pkt[UDP].sport in suspicious_ports:
                    anomalies["suspicious_ports"].append(
                        {
                            "src": src_ip,
                            "dst": pkt[IP].dst,
                            "port": dst_port,
                        }
                    )

        # Detect potential port scans (many unique destination ports from same source)
        for src_ip, ports in dst_port_per_src.items():
            if len(ports) > 20:
                anomalies["port_scans"].append(
                    {
                        "src_ip": src_ip,
                        "unique_ports_scanned": len(ports),
                    }
                )

        # High frequency sources
        for ip, count in src_connections.most_common(5):
            if count > 100:
                anomalies["high_frequency_sources"].append(
                    {
                        "ip": ip,
                        "packet_count": count,
                    }
                )

        # Limit results
        anomalies["large_packets"] = anomalies["large_packets"][:20]
        anomalies["suspicious_ports"] = anomalies["suspicious_ports"][:20]

        return anomalies
