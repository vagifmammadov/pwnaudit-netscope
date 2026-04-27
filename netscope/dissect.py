"""Convert raw scapy packets into one-line summaries and protocol trees."""
from __future__ import annotations

from typing import Any

from scapy.all import (
    Ether, IP, IPv6, TCP, UDP, ARP, ICMP,
    DNS, Raw,
)

try:
    from scapy.layers.inet6 import ICMPv6Unknown, ICMPv6EchoRequest, ICMPv6EchoReply
except Exception:
    ICMPv6Unknown = None
    ICMPv6EchoRequest = None
    ICMPv6EchoReply = None


_TCP_PORT_MAP = {
    20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
    443: "TLS", 465: "SMTPS", 587: "SMTP-Sub",
    993: "IMAPS", 995: "POP3S",
    1433: "MSSQL", 3306: "MySQL", 5432: "PostgreSQL",
    3389: "RDP", 5900: "VNC",
    6379: "Redis", 27017: "MongoDB",
    8080: "HTTP-Alt", 8443: "TLS-Alt", 8000: "HTTP-Alt", 8888: "HTTP-Alt",
}

_UDP_PORT_MAP = {
    53: "DNS", 67: "DHCP", 68: "DHCP", 69: "TFTP",
    123: "NTP", 137: "NetBIOS", 138: "NetBIOS",
    161: "SNMP", 162: "SNMP-Trap",
    500: "ISAKMP", 514: "Syslog",
    1900: "SSDP", 5353: "mDNS", 5355: "LLMNR",
    3478: "STUN", 4500: "IPsec-NAT-T",
}


def _tcp_flag_str(flags) -> str:
    parts = []
    if flags.S: parts.append("SYN")
    if flags.A: parts.append("ACK")
    if flags.F: parts.append("FIN")
    if flags.R: parts.append("RST")
    if flags.P: parts.append("PSH")
    if flags.U: parts.append("URG")
    if flags.E: parts.append("ECE")
    if flags.C: parts.append("CWR")
    return " ".join(parts) if parts else "·"


def summarize(pkt, number: int, rel_time: float) -> dict[str, Any]:
    """Wireshark-style one-line summary of a single packet."""
    src = ""
    dst = ""
    proto = "Unknown"
    info = ""
    length = len(pkt)

    if pkt.haslayer(Ether):
        src = pkt[Ether].src
        dst = pkt[Ether].dst
        proto = "Ethernet"

    if pkt.haslayer(ARP):
        arp = pkt[ARP]
        proto = "ARP"
        src = arp.psrc
        dst = arp.pdst
        if arp.op == 1:
            info = f"Who has {arp.pdst}? Tell {arp.psrc}"
        elif arp.op == 2:
            info = f"{arp.psrc} is at {arp.hwsrc}"
        else:
            info = f"ARP op={arp.op}"
    elif pkt.haslayer(IP):
        ip = pkt[IP]
        src = ip.src
        dst = ip.dst
        proto = "IPv4"
    elif pkt.haslayer(IPv6):
        ip6 = pkt[IPv6]
        src = ip6.src
        dst = ip6.dst
        proto = "IPv6"

    if pkt.haslayer(TCP):
        tcp = pkt[TCP]
        proto = "TCP"
        info = (
            f"{tcp.sport} → {tcp.dport} [{_tcp_flag_str(tcp.flags)}] "
            f"Seq={tcp.seq} Ack={tcp.ack} Win={tcp.window} Len={length}"
        )
        named = _TCP_PORT_MAP.get(tcp.dport) or _TCP_PORT_MAP.get(tcp.sport)
        if named:
            proto = named
        if pkt.haslayer(Raw):
            raw = bytes(pkt[Raw].load)[:8]
            if raw[:4] in (b"GET ", b"POST", b"PUT ", b"HEAD", b"DELE", b"PATC"):
                proto = "HTTP"
                try:
                    line = bytes(pkt[Raw].load).split(b"\r\n", 1)[0].decode("ascii", errors="replace")
                    info = line[:200]
                except Exception:
                    pass
            elif raw[:5] == b"HTTP/":
                proto = "HTTP"
                try:
                    line = bytes(pkt[Raw].load).split(b"\r\n", 1)[0].decode("ascii", errors="replace")
                    info = line[:200]
                except Exception:
                    pass
            elif raw[:1] == b"\x16" and len(raw) >= 3 and raw[1] == 0x03:
                proto = "TLS"
                ver = raw[2]
                ver_label = {0x01: "1.0", 0x02: "1.1", 0x03: "1.2", 0x04: "1.3"}.get(ver, f"0x{ver:02x}")
                info = f"TLSv{ver_label} Handshake — {tcp.sport} → {tcp.dport}"
    elif pkt.haslayer(UDP):
        udp = pkt[UDP]
        proto = "UDP"
        info = f"{udp.sport} → {udp.dport} Len={udp.len}"
        named = _UDP_PORT_MAP.get(udp.dport) or _UDP_PORT_MAP.get(udp.sport)
        if named:
            proto = named

        if pkt.haslayer(DNS):
            dns = pkt[DNS]
            proto = "DNS"
            try:
                qname = ""
                if dns.qd:
                    qn = dns.qd.qname
                    qname = qn.decode("utf-8", errors="ignore").rstrip(".") if isinstance(qn, (bytes, bytearray)) else str(qn)
                if dns.qr == 0:
                    info = f"Standard query 0x{dns.id:04x} {qname}"
                else:
                    info = f"Standard response 0x{dns.id:04x} {qname}"
            except Exception:
                info = f"DNS id=0x{dns.id:04x}"
    elif pkt.haslayer(ICMP):
        icmp = pkt[ICMP]
        proto = "ICMP"
        types = {0: "Echo Reply", 8: "Echo Request", 3: "Destination Unreachable", 11: "Time Exceeded", 5: "Redirect"}
        type_name = types.get(icmp.type, f"Type {icmp.type}")
        try:
            info = f"{type_name} (id={icmp.id}, seq={icmp.seq})"
        except Exception:
            info = type_name
    elif ICMPv6EchoRequest is not None and pkt.haslayer(ICMPv6EchoRequest):
        proto = "ICMPv6"
        info = "Echo (ping) request"
    elif ICMPv6EchoReply is not None and pkt.haslayer(ICMPv6EchoReply):
        proto = "ICMPv6"
        info = "Echo (ping) reply"

    if not info:
        info = proto

    return {
        "no": number,
        "time": f"{rel_time:.6f}",
        "src": src,
        "dst": dst,
        "proto": proto,
        "length": length,
        "info": info,
    }


def packet_layers(pkt) -> list[dict[str, Any]]:
    """Walk the layer chain and produce a structure for the protocol tree view."""
    layers = []
    layer = pkt
    seen = 0
    while layer is not None and seen < 32:
        if layer.__class__.__name__ in ("NoPayload", "Padding"):
            break
        try:
            summary = layer.summary()
        except Exception:
            summary = layer.name
        fields = []
        try:
            for f in layer.fields_desc:
                try:
                    val = layer.getfieldval(f.name)
                    if isinstance(val, (bytes, bytearray)):
                        val = val.hex() if len(val) <= 64 else val[:64].hex() + f"... ({len(val)} bytes)"
                    fields.append((f.name, str(val)))
                except Exception:
                    pass
        except Exception:
            pass
        layers.append({
            "name": layer.name,
            "summary": summary,
            "fields": fields,
        })
        layer = layer.payload
        seen += 1
    return layers
