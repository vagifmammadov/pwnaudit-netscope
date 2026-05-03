"""Wireshark-grade display filter language for NetScope.

Goal: a useful subset of Wireshark's display-filter syntax that runs against
the structured ``fields`` dict produced by :mod:`netscope.dissect`.

Supported syntax
----------------
::

    expr      := or_expr
    or_expr   := and_expr (("or"  | "||") and_expr)*
    and_expr  := not_expr (("and" | "&&") not_expr)*
    not_expr  := ("not" | "!") not_expr
              | "(" expr ")"
              | comparison
              | field_test            -- truthy: "this field exists"
    comparison:= field op value
    field     := IDENT ("." IDENT)*
    op        := == | != | < | <= | > | >= | contains | matches | in
    value     := NUMBER | HEX | STRING | IPV4 | IPV6 | MAC | CIDR | "{" v ("," v)* "}"

Field aliases
-------------
``tcp.port``, ``udp.port``, ``ip.addr``, ``eth.addr`` match either side
(srcport/dstport, src/dst).  ``frame.protocols`` is the colon-joined stack
``eth:ip:tcp:tls`` so ``frame.protocols contains "tls"`` works.

Backwards-compatible fallback
-----------------------------
If the user types something that doesn't parse as an expression, we fall
back to substring search across the row's text columns.  That preserves the
old "type a word, see matching rows" behaviour for casual users.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Any, Callable, Optional


# ── Tokens ──────────────────────────────────────────────────────────────
@dataclass
class _Tok:
    kind: str
    value: Any
    pos: int


_KEYWORDS = {
    "and", "or", "not", "contains", "matches", "in", "true", "false",
}


# Fields produced by netscope.dissect.summarize() — used to distinguish a
# real bareword field test (`tls`, `dns.qry.name`) from a typo / search
# term (`google`).  Anything not in here, when used as a one-token
# expression, will be treated as a substring search needle.  See
# ``DisplayFilter.__init__`` for the fallback logic.
_KNOWN_FIELDS: set[str] = {
    # frame
    "frame.number", "frame.time_relative", "frame.len", "frame.protocols",
    # eth
    "eth.src", "eth.dst", "eth.type", "eth.addr",
    # arp
    "arp.opcode", "arp.src.proto_ipv4", "arp.dst.proto_ipv4",
    "arp.src.hw_mac", "arp.dst.hw_mac", "arp.proto.addr", "arp.hw.addr",
    # ip / ipv6
    "ip.src", "ip.dst", "ip.proto", "ip.ttl", "ip.len", "ip.addr",
    "ipv6.src", "ipv6.dst", "ipv6.nh", "ipv6.hlim", "ipv6.addr",
    # tcp / udp
    "tcp.srcport", "tcp.dstport", "tcp.port", "tcp.seq", "tcp.ack",
    "tcp.window_size", "tcp.flags", "tcp.flags.str", "tcp.len",
    "udp.srcport", "udp.dstport", "udp.port", "udp.length",
    # icmp
    "icmp.type", "icmp.code", "icmp.ident", "icmp.seq",
    # dns
    "dns.id", "dns.flags.response", "dns.qry.name", "dns.qry.type",
    "dns.qry.type_name", "dns.count.answers", "dns.answers",
    "dns.a", "dns.aaaa", "dns.cname",
    # tls
    "tls.record.content_type", "tls.record.content_type_name",
    "tls.record.version", "tls.record.length",
    "tls.handshake.type", "tls.handshake.type_name", "tls.handshake.version",
    "tls.handshake.extensions_server_name", "tls.handshake.extensions.alpn",
    # http
    "http.request.method", "http.request.uri", "http.request.version",
    "http.response.code", "http.response.phrase", "http.response.version",
    "http.first_line", "http.host", "http.user_agent",
    "http.content_type", "http.server",
    # quic
    "quic", "quic.version", "quic.long.packet_type", "quic.long.packet_type_name",
}

# Protocol shorthand names (`tls`, `dns`, `quic`) that match against the
# colon-joined ``frame.protocols`` chain.
_PROTO_SHORTHANDS: set[str] = {
    "eth", "arp", "ip", "ipv6", "tcp", "udp", "icmp", "icmpv6",
    "dns", "tls", "http", "quic",
}


def is_known_bareword(name: str) -> bool:
    """A bareword is a recognised field/proto if either its full path is
    a known field, OR it's a protocol shorthand, OR it's the *prefix* of
    any known field (so `tls` lights up as "any tls.* sub-field present")."""
    if name in _KNOWN_FIELDS or name in _PROTO_SHORTHANDS:
        return True
    prefix = name + "."
    return any(k.startswith(prefix) for k in _KNOWN_FIELDS)


_TOKEN_RE = re.compile(
    r"""
    \s+
  | (?P<STRING>"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')
  | (?P<HEX>0x[0-9A-Fa-f]+)
  | (?P<MAC>[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})
  | (?P<IPV4>\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?)
  | (?P<IPV6>(?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{0,4}(?:/\d{1,3})?)
  | (?P<NUMBER>\d+(?:\.\d+)?)
  | (?P<IDENT>[A-Za-z_][\w.]*)
  | (?P<OP>==|!=|<=|>=|<|>|&&|\|\||!|\(|\)|\{|\}|,)
    """,
    re.VERBOSE,
)


class FilterError(ValueError):
    """Raised when a filter expression cannot be parsed."""


def _tokenize(s: str) -> list[_Tok]:
    toks: list[_Tok] = []
    i = 0
    n = len(s)
    while i < n:
        if s[i].isspace():
            i += 1
            continue
        m = _TOKEN_RE.match(s, i)
        if not m or m.end() == i:
            raise FilterError(f"unexpected character {s[i]!r} at position {i}")
        i = m.end()
        kind = m.lastgroup
        raw = m.group(kind)
        if kind == "STRING":
            toks.append(_Tok("STRING", _unquote(raw), m.start()))
        elif kind == "HEX":
            toks.append(_Tok("NUMBER", int(raw, 16), m.start()))
        elif kind == "MAC":
            toks.append(_Tok("STRING", raw.lower(), m.start()))
        elif kind == "IPV4":
            toks.append(_Tok("STRING", raw, m.start()))
        elif kind == "IPV6":
            toks.append(_Tok("STRING", raw, m.start()))
        elif kind == "NUMBER":
            toks.append(_Tok("NUMBER", float(raw) if "." in raw else int(raw), m.start()))
        elif kind == "IDENT":
            low = raw.lower()
            if low in _KEYWORDS:
                toks.append(_Tok(low.upper(), low, m.start()))
            else:
                toks.append(_Tok("IDENT", raw, m.start()))
        elif kind == "OP":
            mapping = {
                "==": "EQ", "!=": "NE", "<=": "LE", ">=": "GE",
                "<": "LT", ">": "GT",
                "&&": "AND", "||": "OR", "!": "NOT",
                "(": "LP", ")": "RP", "{": "LB", "}": "RB", ",": "COMMA",
            }
            toks.append(_Tok(mapping[raw], raw, m.start()))
    toks.append(_Tok("EOF", None, n))
    return toks


def _unquote(s: str) -> str:
    body = s[1:-1]
    return re.sub(r"\\(.)", lambda m: m.group(1), body)


# ── AST ─────────────────────────────────────────────────────────────────
@dataclass
class Node:
    op: str
    a: Any = None
    b: Any = None
    c: Any = None  # 3rd slot for "in" set or extras

    def eval(self, fields: dict[str, Any], row: dict[str, Any]) -> bool:
        if self.op == "OR":
            return self.a.eval(fields, row) or self.b.eval(fields, row)
        if self.op == "AND":
            return self.a.eval(fields, row) and self.b.eval(fields, row)
        if self.op == "NOT":
            return not self.a.eval(fields, row)
        if self.op == "EXISTS":
            return _exists(fields, self.a)
        if self.op in ("EQ", "NE", "LT", "LE", "GT", "GE",
                       "CONTAINS", "MATCHES", "IN", "CIDR"):
            return _compare(self.op, self.a, self.b, fields)
        raise FilterError(f"internal: unknown node op {self.op}")


# ── Parser ──────────────────────────────────────────────────────────────
class _Parser:
    def __init__(self, toks: list[_Tok]) -> None:
        self.toks = toks
        self.i = 0

    def _peek(self) -> _Tok:
        return self.toks[self.i]

    def _eat(self, kind: str) -> _Tok:
        t = self.toks[self.i]
        if t.kind != kind:
            raise FilterError(f"expected {kind} at position {t.pos}, got {t.kind}")
        self.i += 1
        return t

    def parse(self) -> Node:
        node = self._or()
        if self._peek().kind != "EOF":
            t = self._peek()
            raise FilterError(f"trailing tokens after expression at position {t.pos}")
        return node

    def _or(self) -> Node:
        n = self._and()
        while self._peek().kind == "OR":
            self.i += 1
            n = Node("OR", n, self._and())
        return n

    def _and(self) -> Node:
        n = self._not()
        while self._peek().kind == "AND":
            self.i += 1
            n = Node("AND", n, self._not())
        return n

    def _not(self) -> Node:
        if self._peek().kind == "NOT":
            self.i += 1
            return Node("NOT", self._not())
        return self._primary()

    def _primary(self) -> Node:
        t = self._peek()
        if t.kind == "LP":
            self.i += 1
            n = self._or()
            self._eat("RP")
            return n
        if t.kind == "IDENT":
            field = self._eat("IDENT").value
            op_tok = self._peek()
            if op_tok.kind in ("EQ", "NE", "LT", "LE", "GT", "GE", "CONTAINS", "MATCHES", "IN"):
                self.i += 1
                if op_tok.kind == "IN":
                    self._eat("LB")
                    values: list[Any] = []
                    if self._peek().kind != "RB":
                        values.append(self._value_token())
                        while self._peek().kind == "COMMA":
                            self.i += 1
                            values.append(self._value_token())
                    self._eat("RB")
                    return Node("IN", field, values)
                value = self._value_token()
                return Node(op_tok.kind, field, value)
            # No operator — bare field => existence test
            return Node("EXISTS", field)
        raise FilterError(f"unexpected token {t.kind} at position {t.pos}")

    def _value_token(self) -> Any:
        t = self._peek()
        if t.kind == "NUMBER":
            self.i += 1
            return t.value
        if t.kind == "STRING":
            self.i += 1
            return t.value
        if t.kind == "TRUE":
            self.i += 1
            return True
        if t.kind == "FALSE":
            self.i += 1
            return False
        if t.kind == "IDENT":
            # Bareword like 192.168.1.1, aa:bb:cc, or example.com — treat as string.
            # Allow chains across colons (MAC) and slashes (CIDR) by re-scanning.
            self.i += 1
            return t.value
        raise FilterError(f"expected value, got {t.kind} at position {t.pos}")


# ── Field resolution ────────────────────────────────────────────────────

# Aliases: a logical field maps to a list of concrete fields; the operator
# is broadcast — `tcp.port == 443` becomes `tcp.srcport==443 OR tcp.dstport==443`.
_FIELD_ALIASES = {
    "tcp.port":  ("tcp.srcport", "tcp.dstport"),
    "udp.port":  ("udp.srcport", "udp.dstport"),
    "ip.addr":   ("ip.src", "ip.dst"),
    "ipv6.addr": ("ipv6.src", "ipv6.dst"),
    "eth.addr":  ("eth.src", "eth.dst"),
    "arp.proto.addr": ("arp.src.proto_ipv4", "arp.dst.proto_ipv4"),
    "arp.hw.addr":    ("arp.src.hw_mac", "arp.dst.hw_mac"),
}


def _exists(fields: dict[str, Any], name: str) -> bool:
    if name in fields:
        return fields[name] not in (None, "", [])
    if name in _FIELD_ALIASES:
        return any(_exists(fields, a) for a in _FIELD_ALIASES[name])
    # Special: protocol-name presence ("tcp", "tls", "dns") maps to frame.protocols.
    proto_chain = fields.get("frame.protocols", "")
    if isinstance(proto_chain, str) and proto_chain:
        if name.lower() in proto_chain.lower().split(":"):
            return True
    return False


def _resolve_values(fields: dict[str, Any], name: str) -> list[Any]:
    if name in fields:
        return [fields[name]]
    if name in _FIELD_ALIASES:
        out: list[Any] = []
        for a in _FIELD_ALIASES[name]:
            if a in fields:
                out.append(fields[a])
        return out
    return []


# ── Comparison primitives ───────────────────────────────────────────────
_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?$")
_MAC_RE = re.compile(r"^[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}$")


def _compare(op: str, name: str, value: Any, fields: dict[str, Any]) -> bool:
    candidates = _resolve_values(fields, name)
    if not candidates:
        return False

    # Equality / inequality with IP / MAC / number / string semantics.
    for cand in candidates:
        if _compare_one(op, cand, value):
            return True
    return False


def _compare_one(op: str, lhs: Any, rhs: Any) -> bool:
    # CIDR support for ip.* fields: rhs is "1.2.3.0/24" or plain ip
    if isinstance(rhs, str) and "/" in rhs and _IPV4_RE.match(rhs.split("/")[0] + ("" if "/" not in rhs else "/" + rhs.split("/")[1])):
        try:
            net = ipaddress.ip_network(rhs, strict=False)
            try:
                addr = ipaddress.ip_address(str(lhs))
            except Exception:
                return False
            inside = addr in net
            if op == "EQ":
                return inside
            if op == "NE":
                return not inside
        except Exception:
            pass

    if op == "CONTAINS":
        try:
            return str(rhs).lower() in str(lhs).lower()
        except Exception:
            return False
    if op == "MATCHES":
        try:
            return re.search(str(rhs), str(lhs)) is not None
        except re.error as exc:
            raise FilterError(f"invalid regex: {exc}")

    # Numeric coercion if both sides look numeric
    lhs_n, rhs_n = _maybe_numeric(lhs), _maybe_numeric(rhs)
    if lhs_n is not None and rhs_n is not None:
        a, b = lhs_n, rhs_n
        if op == "EQ": return a == b
        if op == "NE": return a != b
        if op == "LT": return a < b
        if op == "LE": return a <= b
        if op == "GT": return a > b
        if op == "GE": return a >= b

    # Otherwise string compare, case-insensitive for friendly UX
    a, b = str(lhs).lower(), str(rhs).lower()
    if op == "EQ": return a == b
    if op == "NE": return a != b
    if op == "LT": return a < b
    if op == "LE": return a <= b
    if op == "GT": return a > b
    if op == "GE": return a >= b
    if op == "IN":
        return any(_compare_one("EQ", lhs, item) for item in rhs) if isinstance(rhs, list) else False
    return False


def _maybe_numeric(v: Any) -> Optional[float]:
    if isinstance(v, bool):
        return float(v)
    if isinstance(v, (int, float)):
        return float(v)
    if isinstance(v, str):
        try:
            if v.lower().startswith("0x"):
                return float(int(v, 16))
            return float(v)
        except ValueError:
            return None
    return None


# ── Public API ──────────────────────────────────────────────────────────
class DisplayFilter:
    """Compiled filter — call ``matches(fields, row)`` per packet.

    Empty filter matches everything.  An expression that fails to parse is
    treated as a substring search over the row's text columns (Source, Dest,
    Proto, Info) — preserves muscle memory for casual users.
    """

    def __init__(self, expression: str) -> None:
        self.text = expression or ""
        stripped = self.text.strip()
        self._fn: Callable[[dict[str, Any], dict[str, Any]], bool]
        self._mode: str
        self.error: Optional[str] = None

        if not stripped:
            self._mode = "all"
            self._fn = lambda f, r: True
            return

        try:
            toks = _tokenize(stripped)
            ast = _Parser(toks).parse()
        except FilterError as exc:
            self._mode = "substring"
            self.error = str(exc)
            needle = stripped.lower()
            self._fn = lambda f, r, n=needle: _substring_match(r, n)
            return

        # Special case: a single bare IDENT that isn't a known field/proto
        # shorthand is almost certainly a search term, not a field test.
        # Treat it as substring so casual users keep their muscle memory.
        if (
            ast.op == "EXISTS"
            and isinstance(ast.a, str)
            and not is_known_bareword(ast.a)
        ):
            self._mode = "substring"
            needle = stripped.lower()
            self._fn = lambda f, r, n=needle: _substring_match(r, n)
            return

        self._mode = "expr"
        self._fn = lambda f, r: ast.eval(f, r)

    def matches(self, fields: dict[str, Any], row: dict[str, Any]) -> bool:
        try:
            return bool(self._fn(fields, row))
        except FilterError:
            return False
        except Exception:
            return False

    @property
    def mode(self) -> str:
        return self._mode


def _substring_match(row: dict[str, Any], needle: str) -> bool:
    for k in ("src", "dst", "proto", "info"):
        v = row.get(k)
        if v is not None and needle in str(v).lower():
            return True
    return False


# ── Convenience: validate before applying (for live UI underline) ──────
def validate(expression: str) -> Optional[str]:
    """Return None if expression parses, else the error message."""
    if not expression or not expression.strip():
        return None
    try:
        _Parser(_tokenize(expression.strip())).parse()
        return None
    except FilterError as exc:
        return str(exc)
