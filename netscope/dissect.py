"""Convert raw scapy packets into one-line summaries and protocol trees.

The summary row carries TWO kinds of data:
  * Human-readable columns (no/time/src/dst/proto/length/info) — for the table.
  * A ``fields`` dict — structured Wireshark-style field accessors used by the
    display filter language ('tcp.port == 443', 'dns.qry.name contains foo').

Adding a new dissector?  Populate both — the human Info string for the eye,
and the structured fields for the filter engine.
"""
from __future__ import annotations

from typing import Any, Optional

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
    443: "QUIC",
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


# ── DNS record-type names ────────────────────────────────────────────────
_DNS_TYPES = {
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX",
    16: "TXT", 28: "AAAA", 33: "SRV", 41: "OPT", 43: "DS",
    46: "RRSIG", 47: "NSEC", 48: "DNSKEY", 50: "NSEC3", 65: "HTTPS",
    255: "ANY",
}

# TLS handshake message types — see RFC 8446 §4.
_TLS_HANDSHAKE_TYPES = {
    0x01: "Client Hello",
    0x02: "Server Hello",
    0x04: "New Session Ticket",
    0x05: "End of Early Data",
    0x08: "Encrypted Extensions",
    0x0b: "Certificate",
    0x0c: "Server Key Exchange",
    0x0d: "Certificate Request",
    0x0e: "Server Hello Done",
    0x0f: "Certificate Verify",
    0x10: "Client Key Exchange",
    0x14: "Finished",
    0x15: "Certificate Status",
    0x18: "Key Update",
    0x16: "Server Configuration",  # legacy
}

_TLS_VERSIONS = {0x0301: "1.0", 0x0302: "1.1", 0x0303: "1.2", 0x0304: "1.3"}
_TLS_CONTENT_TYPES = {
    0x14: "ChangeCipherSpec", 0x15: "Alert", 0x16: "Handshake",
    0x17: "Application Data", 0x18: "Heartbeat",
}


def _parse_tls(raw: bytes) -> Optional[dict[str, Any]]:
    """Best-effort dissect of one TLS record (we only look at the first).
    Returns a dict of structured fields, or None if it doesn't look like TLS.
    """
    if len(raw) < 5:
        return None
    ctype = raw[0]
    if ctype not in _TLS_CONTENT_TYPES:
        return None
    if raw[1] != 0x03:
        # Not TLS 1.x family
        return None
    legacy_ver = (raw[1] << 8) | raw[2]
    rec_len = (raw[3] << 8) | raw[4]
    out: dict[str, Any] = {
        "tls.record.content_type": ctype,
        "tls.record.content_type_name": _TLS_CONTENT_TYPES.get(ctype, f"0x{ctype:02x}"),
        "tls.record.version": _TLS_VERSIONS.get(legacy_ver, f"0x{legacy_ver:04x}"),
        "tls.record.length": rec_len,
    }
    if ctype != 0x16 or len(raw) < 9:
        return out
    # Handshake message
    hs_type = raw[5]
    out["tls.handshake.type"] = hs_type
    out["tls.handshake.type_name"] = _TLS_HANDSHAKE_TYPES.get(hs_type, f"0x{hs_type:02x}")
    if hs_type != 0x01:  # only Client Hello reveals SNI in plaintext
        return out
    # ClientHello: 4-byte hs header, then 2-byte version, 32 random, 1 sid_len, sid,
    # 2 cs_len, cipher_suites, 1 cm_len, cms, 2 ext_len, extensions
    try:
        i = 9  # skip record header (5) + handshake header (4)
        if i + 2 > len(raw):
            return out
        ch_ver = (raw[i] << 8) | raw[i + 1]
        out["tls.handshake.version"] = _TLS_VERSIONS.get(ch_ver, f"0x{ch_ver:04x}")
        i += 2 + 32  # version + random
        if i >= len(raw):
            return out
        sid_len = raw[i]; i += 1 + sid_len
        if i + 2 > len(raw):
            return out
        cs_len = (raw[i] << 8) | raw[i + 1]; i += 2 + cs_len
        if i + 1 > len(raw):
            return out
        cm_len = raw[i]; i += 1 + cm_len
        if i + 2 > len(raw):
            return out
        ext_total = (raw[i] << 8) | raw[i + 1]; i += 2
        end = min(len(raw), i + ext_total)
        while i + 4 <= end:
            ext_type = (raw[i] << 8) | raw[i + 1]
            ext_len = (raw[i + 2] << 8) | raw[i + 3]
            i += 4
            if ext_type == 0x00 and ext_len >= 5:  # server_name
                # SNI: list_len(2) entry_type(1) name_len(2) name
                j = i + 3  # skip list_len + entry type
                if j + 2 <= len(raw):
                    name_len = (raw[j] << 8) | raw[j + 1]
                    j += 2
                    if j + name_len <= len(raw):
                        try:
                            out["tls.handshake.extensions_server_name"] = (
                                raw[j:j + name_len].decode("ascii", errors="replace")
                            )
                        except Exception:
                            pass
            elif ext_type == 0x10:  # ALPN
                # list_len(2) then repeated [proto_len(1) proto]
                if ext_len >= 3:
                    j = i + 2
                    if j + 1 <= len(raw):
                        proto_len = raw[j]
                        if j + 1 + proto_len <= len(raw):
                            try:
                                out["tls.handshake.extensions.alpn"] = (
                                    raw[j + 1:j + 1 + proto_len].decode("ascii", errors="replace")
                                )
                            except Exception:
                                pass
            i += ext_len
    except Exception:
        pass
    return out


def _looks_like_quic(raw: bytes) -> bool:
    """Heuristic: QUIC long-header packet (Initial/Handshake/0-RTT) starts
    with a byte where bit 7 is 1 and the next 4 bytes are a known version
    (currently RFC 9000 v1 = 0x00000001, plus drafts and v2)."""
    if len(raw) < 5:
        return False
    if not (raw[0] & 0x80):
        # Short header — can't reliably distinguish from random UDP without state.
        # Be conservative and don't flag short-header by content.
        return False
    ver = (raw[1] << 24) | (raw[2] << 16) | (raw[3] << 8) | raw[4]
    return ver in (0x00000001, 0x6b3343cf, 0xff00001d, 0xff00001c, 0xff00001b)


def _parse_quic(raw: bytes) -> dict[str, Any]:
    """Extract a few QUIC long-header fields for the filter engine + Info column."""
    out: dict[str, Any] = {"quic": True}
    if len(raw) < 5 or not (raw[0] & 0x80):
        return out
    type_bits = (raw[0] >> 4) & 0x03
    type_names = {0: "Initial", 1: "0-RTT", 2: "Handshake", 3: "Retry"}
    out["quic.long.packet_type"] = type_bits
    out["quic.long.packet_type_name"] = type_names.get(type_bits, str(type_bits))
    ver = (raw[1] << 24) | (raw[2] << 16) | (raw[3] << 8) | raw[4]
    out["quic.version"] = f"0x{ver:08x}"
    return out


def _parse_dns(dns) -> dict[str, Any]:
    """Pull qname, qtype, and (if response) the first answer record into fields."""
    out: dict[str, Any] = {"dns.id": int(dns.id), "dns.flags.response": int(dns.qr)}
    qname = ""
    qtype: Optional[int] = None
    if dns.qd:
        try:
            qn = dns.qd.qname
            qname = qn.decode("utf-8", errors="ignore").rstrip(".") if isinstance(qn, (bytes, bytearray)) else str(qn).rstrip(".")
            qtype = int(dns.qd.qtype)
        except Exception:
            pass
    if qname:
        out["dns.qry.name"] = qname
    if qtype is not None:
        out["dns.qry.type"] = qtype
        out["dns.qry.type_name"] = _DNS_TYPES.get(qtype, str(qtype))
    # ancount is set lazily by scapy and may read as None even when answers
    # are present — count the answer list directly when we can.
    answer_records: list[Any] = []
    an = getattr(dns, "an", None)
    if an is not None:
        # scapy returns either a list-like _list, a single DNSRR, or a chain
        # via .payload — handle all three.
        try:
            answer_records = list(an)
        except TypeError:
            cur = an
            depth = 0
            while cur is not None and depth < 16 and getattr(cur, "type", None) is not None:
                answer_records.append(cur)
                cur = getattr(cur, "payload", None)
                if cur is None or cur.__class__.__name__ in ("NoPayload", "Padding"):
                    break
                depth += 1
    out["dns.count.answers"] = len(answer_records)
    answers: list[str] = []
    for rec in answer_records[:8]:
        try:
            rdata = getattr(rec, "rdata", None)
            rtype = int(getattr(rec, "type", 0) or 0)
        except Exception:
            continue
        if isinstance(rdata, (bytes, bytearray)):
            try:
                rdata_s = rdata.decode("utf-8", errors="ignore").rstrip(".")
            except Exception:
                rdata_s = rdata.hex()
        else:
            rdata_s = str(rdata).rstrip(".")
        rname = _DNS_TYPES.get(rtype, str(rtype))
        answers.append(f"{rname} {rdata_s}")
        if "dns.a" not in out and rtype == 1:
            out["dns.a"] = rdata_s
        if "dns.aaaa" not in out and rtype == 28:
            out["dns.aaaa"] = rdata_s
        if "dns.cname" not in out and rtype == 5:
            out["dns.cname"] = rdata_s
    if answers:
        out["dns.answers"] = " · ".join(answers[:4])
    return out


def _parse_http(raw: bytes) -> Optional[dict[str, Any]]:
    """Cheap HTTP/1.x parser — first request or response line plus Host header."""
    if not raw:
        return None
    head4 = raw[:4]
    head5 = raw[:5]
    is_req = head4 in (b"GET ", b"POST", b"PUT ", b"HEAD") or raw[:7] in (b"DELETE ", b"OPTIONS", b"PATCH ", b"CONNEC")
    is_resp = head5 == b"HTTP/"
    if not (is_req or is_resp):
        return None
    out: dict[str, Any] = {}
    try:
        first, _, rest = raw.partition(b"\r\n")
        first_s = first.decode("ascii", errors="replace")
    except Exception:
        return None
    if is_req:
        parts = first_s.split(" ", 2)
        if len(parts) >= 1:
            out["http.request.method"] = parts[0]
        if len(parts) >= 2:
            out["http.request.uri"] = parts[1]
        if len(parts) >= 3:
            out["http.request.version"] = parts[2]
    else:
        # "HTTP/1.1 200 OK"
        parts = first_s.split(" ", 2)
        if len(parts) >= 1:
            out["http.response.version"] = parts[0]
        if len(parts) >= 2:
            try:
                out["http.response.code"] = int(parts[1])
            except ValueError:
                pass
        if len(parts) >= 3:
            out["http.response.phrase"] = parts[2]
    out["http.first_line"] = first_s[:200]
    # Host header (only for request, but cheap to scan either way)
    try:
        for line in rest.split(b"\r\n", 32)[:32]:
            if b":" not in line:
                if not line:
                    break
                continue
            name, _, value = line.partition(b":")
            n = name.strip().lower().decode("ascii", errors="ignore")
            v = value.strip().decode("ascii", errors="replace")
            if n == "host":
                out["http.host"] = v
            elif n == "user-agent":
                out["http.user_agent"] = v[:200]
            elif n == "content-type":
                out["http.content_type"] = v[:120]
            elif n == "server":
                out["http.server"] = v[:120]
    except Exception:
        pass
    return out


def summarize(pkt, number: int, rel_time: float) -> dict[str, Any]:
    """Wireshark-style one-line summary of a single packet plus structured fields."""
    src = ""
    dst = ""
    proto = "Unknown"
    info = ""
    length = len(pkt)
    fields: dict[str, Any] = {
        "frame.number": number,
        "frame.time_relative": rel_time,
        "frame.len": length,
    }
    protocols: list[str] = []

    if pkt.haslayer(Ether):
        eth = pkt[Ether]
        src = eth.src
        dst = eth.dst
        proto = "Ethernet"
        protocols.append("eth")
        fields["eth.src"] = eth.src
        fields["eth.dst"] = eth.dst
        try:
            fields["eth.type"] = int(eth.type)
        except Exception:
            pass

    if pkt.haslayer(ARP):
        arp = pkt[ARP]
        proto = "ARP"
        protocols.append("arp")
        src = arp.psrc
        dst = arp.pdst
        fields["arp.opcode"] = int(arp.op)
        fields["arp.src.proto_ipv4"] = arp.psrc
        fields["arp.dst.proto_ipv4"] = arp.pdst
        fields["arp.src.hw_mac"] = arp.hwsrc
        fields["arp.dst.hw_mac"] = arp.hwdst
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
        protocols.append("ip")
        fields["ip.src"] = ip.src
        fields["ip.dst"] = ip.dst
        try:
            fields["ip.proto"] = int(ip.proto)
            fields["ip.ttl"] = int(ip.ttl)
            fields["ip.len"] = int(ip.len)
        except Exception:
            pass
    elif pkt.haslayer(IPv6):
        ip6 = pkt[IPv6]
        src = ip6.src
        dst = ip6.dst
        proto = "IPv6"
        protocols.append("ipv6")
        fields["ipv6.src"] = ip6.src
        fields["ipv6.dst"] = ip6.dst
        try:
            fields["ipv6.nh"] = int(ip6.nh)
            fields["ipv6.hlim"] = int(ip6.hlim)
        except Exception:
            pass

    if pkt.haslayer(TCP):
        tcp = pkt[TCP]
        proto = "TCP"
        protocols.append("tcp")
        fields["tcp.srcport"] = int(tcp.sport)
        fields["tcp.dstport"] = int(tcp.dport)
        try:
            fields["tcp.seq"] = int(tcp.seq)
            fields["tcp.ack"] = int(tcp.ack)
            fields["tcp.window_size"] = int(tcp.window)
            fields["tcp.flags"] = int(tcp.flags)
            fields["tcp.flags.str"] = _tcp_flag_str(tcp.flags)
        except Exception:
            pass
        # Wireshark's tcp.len = TCP segment payload length (not frame length).
        try:
            payload_len = len(tcp.payload) if tcp.payload else 0
        except Exception:
            payload_len = 0
        fields["tcp.len"] = payload_len
        info = (
            f"{tcp.sport} → {tcp.dport} [{_tcp_flag_str(tcp.flags)}] "
            f"Seq={tcp.seq} Ack={tcp.ack} Win={tcp.window} Len={payload_len}"
        )
        named = _TCP_PORT_MAP.get(tcp.dport) or _TCP_PORT_MAP.get(tcp.sport)
        if named:
            proto = named

        # Look at the TCP payload to upgrade the proto label and extract L7 fields
        if pkt.haslayer(Raw):
            raw_payload = bytes(pkt[Raw].load)
        else:
            try:
                raw_payload = bytes(tcp.payload) if tcp.payload else b""
            except Exception:
                raw_payload = b""

        if raw_payload:
            http = _parse_http(raw_payload)
            if http is not None:
                proto = "HTTP"
                protocols.append("http")
                fields.update(http)
                info = http.get("http.first_line", "HTTP")[:200]
            else:
                tls = _parse_tls(raw_payload)
                if tls is not None:
                    proto = "TLS"
                    protocols.append("tls")
                    fields.update(tls)
                    ct_name = tls.get("tls.record.content_type_name", "TLS")
                    ver = tls.get("tls.record.version", "?")
                    if "tls.handshake.type_name" in tls:
                        ht = tls["tls.handshake.type_name"]
                        sni = tls.get("tls.handshake.extensions_server_name")
                        if sni:
                            info = f"TLSv{ver} {ht} (SNI={sni})"
                        else:
                            info = f"TLSv{ver} {ht}"
                    else:
                        info = f"TLSv{ver} {ct_name}"
    elif pkt.haslayer(UDP):
        udp = pkt[UDP]
        proto = "UDP"
        protocols.append("udp")
        fields["udp.srcport"] = int(udp.sport)
        fields["udp.dstport"] = int(udp.dport)
        try:
            fields["udp.length"] = int(udp.len)
        except Exception:
            pass
        info = f"{udp.sport} → {udp.dport} Len={udp.len}"
        named = _UDP_PORT_MAP.get(udp.dport) or _UDP_PORT_MAP.get(udp.sport)
        if named:
            proto = named

        if pkt.haslayer(DNS):
            dns = pkt[DNS]
            proto = "DNS"
            protocols.append("dns")
            dns_fields = _parse_dns(dns)
            fields.update(dns_fields)
            qname = dns_fields.get("dns.qry.name", "")
            qtype = dns_fields.get("dns.qry.type_name", "")
            if dns.qr == 0:
                info = f"Standard query 0x{dns.id:04x} {qtype} {qname}".rstrip()
            else:
                ans = dns_fields.get("dns.answers", "")
                if ans:
                    info = f"Standard response 0x{dns.id:04x} {qtype} {qname} → {ans}"
                else:
                    info = f"Standard response 0x{dns.id:04x} {qtype} {qname}"
        else:
            # QUIC heuristic on udp/443 long-header packets
            try:
                raw_payload = bytes(udp.payload) if udp.payload else b""
            except Exception:
                raw_payload = b""
            if (udp.dport == 443 or udp.sport == 443) and _looks_like_quic(raw_payload):
                proto = "QUIC"
                if "udp" in protocols:
                    protocols.append("quic")
                qfields = _parse_quic(raw_payload)
                fields.update(qfields)
                info = (
                    f"QUIC {qfields.get('quic.long.packet_type_name', '?')} "
                    f"v{qfields.get('quic.version', '?')} "
                    f"{udp.sport} → {udp.dport}"
                )
    elif pkt.haslayer(ICMP):
        icmp = pkt[ICMP]
        proto = "ICMP"
        protocols.append("icmp")
        try:
            fields["icmp.type"] = int(icmp.type)
            fields["icmp.code"] = int(icmp.code)
        except Exception:
            pass
        types = {0: "Echo Reply", 8: "Echo Request", 3: "Destination Unreachable",
                 11: "Time Exceeded", 5: "Redirect"}
        type_name = types.get(icmp.type, f"Type {icmp.type}")
        # Only Echo (type 0/8) carries id/seq.
        if icmp.type in (0, 8):
            try:
                fields["icmp.ident"] = int(icmp.id)
                fields["icmp.seq"] = int(icmp.seq)
                info = f"{type_name} (id={icmp.id}, seq={icmp.seq})"
            except Exception:
                info = type_name
        else:
            info = type_name
    elif ICMPv6EchoRequest is not None and pkt.haslayer(ICMPv6EchoRequest):
        proto = "ICMPv6"
        protocols.append("icmpv6")
        info = "Echo (ping) request"
    elif ICMPv6EchoReply is not None and pkt.haslayer(ICMPv6EchoReply):
        proto = "ICMPv6"
        protocols.append("icmpv6")
        info = "Echo (ping) reply"

    if not info:
        info = proto

    fields["frame.protocols"] = ":".join(protocols) if protocols else proto.lower()
    fields["_proto_label"] = proto
    fields["_info"] = info
    fields["_src"] = src
    fields["_dst"] = dst

    return {
        "no": number,
        "time": f"{rel_time:.6f}",
        "src": src,
        "dst": dst,
        "proto": proto,
        "length": length,
        "info": info,
        "fields": fields,
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
