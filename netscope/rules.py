"""
Detection rules engine — evaluates every captured packet against a list of
rules and fires alerts when thresholds are crossed.

Rule design:
    Each rule is a small dataclass with a ``match(pkt)`` predicate and a
    sliding-window threshold ``count`` per ``window_seconds`` per ``key``.
    When the threshold is crossed, an Alert is emitted.

    "key" is a function that bucket-keys events (e.g. by source IP for
    port-scan detection, by source MAC for deauth flood detection, etc.).
    Without a key, the rule fires globally — useful for once-per-event rules
    like "duplicate IP→MAC mapping detected".

Rules are loaded from:
    1. A built-in set (defined here) — covers the common attacks we want
       to catch out of the box.
    2. ~/.pwnaudit-netscope/rules.json — user-added or overridden rules.

The user's UI talks to ``RuleStore`` to enable/disable rules and add custom
ones; the capture pipeline calls ``RuleEngine.observe(pkt)`` once per packet
on a worker thread.
"""
from __future__ import annotations

import json
import logging
import os
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Callable, Optional, Any

logger = logging.getLogger(__name__)


# ── Severity ─────────────────────────────────────────────────────────
SEVERITY_INFO = "info"
SEVERITY_LOW = "low"
SEVERITY_MEDIUM = "medium"
SEVERITY_HIGH = "high"
SEVERITY_CRITICAL = "critical"

_SEVERITY_ORDER = {
    SEVERITY_INFO: 0,
    SEVERITY_LOW: 1,
    SEVERITY_MEDIUM: 2,
    SEVERITY_HIGH: 3,
    SEVERITY_CRITICAL: 4,
}


@dataclass
class Alert:
    """A single rule firing."""

    rule_id: str
    title: str
    severity: str
    message: str
    timestamp: float = field(default_factory=time.time)
    details: dict[str, Any] = field(default_factory=dict)

    def severity_rank(self) -> int:
        return _SEVERITY_ORDER.get(self.severity, 0)


# ── Built-in rule predicates ─────────────────────────────────────────
# Each takes a scapy packet and returns either ``None`` (no event) or a
# dict that becomes the alert's ``details``.  Bucketing key (string) is
# returned alongside so the engine can de-dupe by source.

# Field-extraction helpers, written defensively because scapy's haslayer
# behaviour varies by packet construction path.
def _has(pkt, layer: str) -> bool:
    try:
        return pkt.haslayer(layer)
    except Exception:
        return False


def _src_ip(pkt) -> Optional[str]:
    try:
        if _has(pkt, "IP"):
            return pkt["IP"].src
        if _has(pkt, "IPv6"):
            return pkt["IPv6"].src
    except Exception:
        pass
    return None


def _dst_ip(pkt) -> Optional[str]:
    try:
        if _has(pkt, "IP"):
            return pkt["IP"].dst
        if _has(pkt, "IPv6"):
            return pkt["IPv6"].dst
    except Exception:
        pass
    return None


def _src_mac(pkt) -> Optional[str]:
    try:
        if _has(pkt, "Ether"):
            return pkt["Ether"].src
        if _has(pkt, "Dot11"):
            return pkt["Dot11"].addr2
    except Exception:
        pass
    return None


def _dst_port(pkt) -> Optional[int]:
    try:
        if _has(pkt, "TCP"):
            return int(pkt["TCP"].dport)
        if _has(pkt, "UDP"):
            return int(pkt["UDP"].dport)
    except Exception:
        pass
    return None


def _tcp_flags(pkt) -> Optional[str]:
    try:
        if _has(pkt, "TCP"):
            return str(pkt["TCP"].flags)
    except Exception:
        pass
    return None


# ── Rule definition ──────────────────────────────────────────────────
@dataclass
class Rule:
    """One detection rule."""

    id: str
    title: str
    description: str
    severity: str
    enabled: bool
    threshold: int
    window_seconds: float
    is_builtin: bool = True
    # Runtime predicates (not serialised) — built-in rules set these in
    # ``builtin_rules()``; user rules use the simple-DSL evaluator below.
    match: Optional[Callable[[Any], Optional[dict[str, Any]]]] = None
    key_fn: Optional[Callable[[Any], Optional[str]]] = None
    # Simple-DSL fields (for user-authored rules — see SimpleRule.compile).
    dsl: Optional["SimpleRule"] = None

    def to_json(self) -> dict[str, Any]:
        out = {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "enabled": self.enabled,
            "threshold": self.threshold,
            "window_seconds": self.window_seconds,
            "is_builtin": self.is_builtin,
        }
        if self.dsl is not None:
            out["dsl"] = asdict(self.dsl)
        return out


# ── Simple DSL ───────────────────────────────────────────────────────
# Lets users write rules without code.  Format:
#
#     {
#       "id": "my-rule",
#       "title": "DNS to public resolver",
#       "severity": "info",
#       "threshold": 100,
#       "window_seconds": 60,
#       "dsl": {
#           "protocol": "DNS",       # one of: TCP, UDP, ICMP, ARP, DNS, DHCP, Dot11
#           "src_ip":   "any",       # exact, prefix/24, or "any"
#           "dst_ip":   "8.8.8.8",
#           "dst_port": null,        # int or null
#           "tcp_flags": null,       # "S" / "SA" / "FA" / null
#           "key_by":   "src_ip"     # one of: src_ip, src_mac, dst_ip, dst_port, none
#       }
#     }
#
# Anything left null/"any" is treated as a wildcard.
@dataclass
class SimpleRule:
    protocol: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = None
    tcp_flags: Optional[str] = None
    key_by: str = "src_ip"

    def compile(self) -> tuple[Callable[[Any], Optional[dict[str, Any]]],
                               Callable[[Any], Optional[str]]]:
        proto = (self.protocol or "").upper() or None
        src_match = (self.src_ip or "any").lower()
        dst_match = (self.dst_ip or "any").lower()
        port_match = self.dst_port
        flags_match = self.tcp_flags
        key_by = (self.key_by or "src_ip").lower()

        def matches_ip(actual: Optional[str], pattern: str) -> bool:
            if pattern in ("any", "*", ""):
                return True
            if actual is None:
                return False
            actual = actual.lower()
            if pattern == actual:
                return True
            if pattern.endswith("/24"):
                return actual.startswith(pattern[:-3].rsplit(".", 1)[0] + ".")
            return False

        def predicate(pkt) -> Optional[dict[str, Any]]:
            if proto and not _has(pkt, proto):
                return None
            sip, dip = _src_ip(pkt), _dst_ip(pkt)
            if not matches_ip(sip, src_match):
                return None
            if not matches_ip(dip, dst_match):
                return None
            if port_match is not None and _dst_port(pkt) != port_match:
                return None
            if flags_match:
                actual_flags = _tcp_flags(pkt) or ""
                if not all(f in actual_flags for f in flags_match):
                    return None
            return {
                "src_ip": sip,
                "dst_ip": dip,
                "dst_port": _dst_port(pkt),
            }

        def key_fn(pkt) -> Optional[str]:
            if key_by == "src_ip":
                return _src_ip(pkt)
            if key_by == "src_mac":
                return _src_mac(pkt)
            if key_by == "dst_ip":
                return _dst_ip(pkt)
            if key_by == "dst_port":
                p = _dst_port(pkt)
                return str(p) if p is not None else None
            return None

        return predicate, key_fn


# ── Built-in rules ───────────────────────────────────────────────────
def _r_syn_flood(pkt) -> Optional[dict[str, Any]]:
    if not _has(pkt, "TCP"):
        return None
    flags = _tcp_flags(pkt) or ""
    if "S" in flags and "A" not in flags:
        return {"src_ip": _src_ip(pkt), "dst_ip": _dst_ip(pkt), "dst_port": _dst_port(pkt)}
    return None


def _r_port_scan(pkt) -> Optional[dict[str, Any]]:
    if not _has(pkt, "TCP"):
        return None
    flags = _tcp_flags(pkt) or ""
    if "S" not in flags or "A" in flags:
        return None
    return {
        "src_ip": _src_ip(pkt),
        "dst_ip": _dst_ip(pkt),
        "dst_port": _dst_port(pkt),
    }


def _r_dns_flood(pkt) -> Optional[dict[str, Any]]:
    if not _has(pkt, "DNS"):
        return None
    return {"src_ip": _src_ip(pkt)}


def _r_arp(pkt) -> Optional[dict[str, Any]]:
    if not _has(pkt, "ARP"):
        return None
    try:
        op = int(pkt["ARP"].op)
    except Exception:
        return None
    # op=2 → ARP reply (typical spoof traffic is unsolicited replies)
    if op == 2:
        return {
            "psrc": getattr(pkt["ARP"], "psrc", None),
            "hwsrc": getattr(pkt["ARP"], "hwsrc", None),
            "pdst": getattr(pkt["ARP"], "pdst", None),
        }
    return None


def _r_icmp_flood(pkt) -> Optional[dict[str, Any]]:
    if not _has(pkt, "ICMP"):
        return None
    try:
        if int(pkt["ICMP"].type) != 8:  # echo request
            return None
    except Exception:
        return None
    return {"src_ip": _src_ip(pkt), "dst_ip": _dst_ip(pkt)}


def _r_deauth(pkt) -> Optional[dict[str, Any]]:
    if not _has(pkt, "Dot11Deauth"):
        return None
    addr1 = getattr(pkt["Dot11"], "addr1", None) if _has(pkt, "Dot11") else None
    addr2 = getattr(pkt["Dot11"], "addr2", None) if _has(pkt, "Dot11") else None
    return {"target": addr1, "from": addr2}


def _r_beacon_flood(pkt) -> Optional[dict[str, Any]]:
    if not _has(pkt, "Dot11Beacon"):
        return None
    bssid = getattr(pkt["Dot11"], "addr3", None) if _has(pkt, "Dot11") else None
    return {"bssid": bssid}


def _key_src_ip(pkt) -> Optional[str]:
    return _src_ip(pkt)


def _key_src_mac(pkt) -> Optional[str]:
    return _src_mac(pkt)


def _key_global(_pkt) -> Optional[str]:
    return "*"


BUILTIN_RULES: list[Rule] = [
    Rule(
        id="builtin.syn-flood",
        title="TCP SYN flood",
        description=(
            "Many half-open SYN packets from one source — classic resource-"
            "exhaustion attack against a server."
        ),
        severity=SEVERITY_HIGH,
        enabled=True,
        threshold=200,
        window_seconds=10,
        match=_r_syn_flood,
        key_fn=_key_src_ip,
    ),
    Rule(
        id="builtin.port-scan",
        title="TCP port scan",
        description=(
            "One source touching many destination ports in a short window — "
            "reconnaissance, possibly nmap."
        ),
        severity=SEVERITY_MEDIUM,
        enabled=True,
        threshold=30,
        window_seconds=10,
        match=_r_port_scan,
        key_fn=_key_src_ip,
    ),
    Rule(
        id="builtin.dns-flood",
        title="DNS query flood",
        description="Excessive DNS queries from one host, typical of DGA malware.",
        severity=SEVERITY_LOW,
        enabled=True,
        threshold=80,
        window_seconds=10,
        match=_r_dns_flood,
        key_fn=_key_src_ip,
    ),
    Rule(
        id="builtin.arp-spoof",
        title="ARP reply storm (possible MITM)",
        description=(
            "Many unsolicited ARP replies from one MAC.  Combined with seeing "
            "the same IP claimed by multiple MACs, this is ARP spoofing."
        ),
        severity=SEVERITY_HIGH,
        enabled=True,
        threshold=20,
        window_seconds=10,
        match=_r_arp,
        key_fn=_key_src_mac,
    ),
    Rule(
        id="builtin.icmp-flood",
        title="ICMP echo flood",
        description="Ping flood — a DoS attempt against a host.",
        severity=SEVERITY_MEDIUM,
        enabled=True,
        threshold=200,
        window_seconds=10,
        match=_r_icmp_flood,
        key_fn=_key_src_ip,
    ),
    Rule(
        id="builtin.wifi-deauth",
        title="802.11 deauthentication frames",
        description=(
            "Bursts of deauth frames — classic Wi-Fi denial-of-service or "
            "evil-twin handshake-capture attack.  Requires monitor mode."
        ),
        severity=SEVERITY_HIGH,
        enabled=True,
        threshold=10,
        window_seconds=5,
        match=_r_deauth,
        key_fn=_key_src_mac,
    ),
    Rule(
        id="builtin.wifi-beacon-flood",
        title="802.11 beacon flood",
        description=(
            "Many distinct BSSID beacons from a small region — beacon-flood "
            "attack to hide a real AP or jam clients.  Requires monitor mode."
        ),
        severity=SEVERITY_MEDIUM,
        enabled=True,
        threshold=80,
        window_seconds=10,
        match=_r_beacon_flood,
        key_fn=_key_global,
    ),
]


# ── Persistence ──────────────────────────────────────────────────────
def _config_dir() -> Path:
    base = os.environ.get("APPDATA") or str(Path.home())
    p = Path(base) / "PWNAudit-NetScope"
    p.mkdir(parents=True, exist_ok=True)
    return p


def _user_rules_path() -> Path:
    return _config_dir() / "rules.json"


# ── Engine ───────────────────────────────────────────────────────────
class RuleEngine:
    """
    Thread-safe rule evaluator.  ``observe(pkt)`` is called from the capture
    callback (worker thread); ``alerts`` is read from the UI thread.
    """

    MAX_ALERTS = 500

    def __init__(self) -> None:
        self._rules: list[Rule] = []
        # rule_id → key → deque[timestamps]
        self._counters: dict[str, dict[str, deque]] = defaultdict(lambda: defaultdict(deque))
        # rule_id → key → last_fired_at  (rate-limit alerts to one per window)
        self._cooldowns: dict[str, dict[str, float]] = defaultdict(dict)
        self._alerts: deque[Alert] = deque(maxlen=self.MAX_ALERTS)
        self._listeners: list[Callable[[Alert], None]] = []
        self._lock = threading.Lock()
        self.reload()

    # ── Public API ────────────────────────────────────────────────
    def reload(self) -> None:
        """Reload rules: built-ins + user overrides."""
        with self._lock:
            self._rules = [Rule(**{**asdict(r), "match": r.match, "key_fn": r.key_fn})
                           for r in BUILTIN_RULES]
            user_rules = self._load_user_rules()
            # User overrides built-in by id; otherwise append.
            by_id = {r.id: r for r in self._rules}
            for r in user_rules:
                by_id[r.id] = r
            self._rules = list(by_id.values())
            self._counters.clear()
            self._cooldowns.clear()

    def rules(self) -> list[Rule]:
        with self._lock:
            return list(self._rules)

    def set_enabled(self, rule_id: str, enabled: bool) -> None:
        with self._lock:
            for r in self._rules:
                if r.id == rule_id:
                    r.enabled = enabled
                    self._persist_user_overrides()
                    return

    def add_user_rule(self, rule: Rule) -> None:
        with self._lock:
            self._rules = [r for r in self._rules if r.id != rule.id]
            self._rules.append(rule)
            self._persist_user_overrides()

    def remove_user_rule(self, rule_id: str) -> None:
        with self._lock:
            target = next((r for r in self._rules if r.id == rule_id and not r.is_builtin), None)
            if target:
                self._rules = [r for r in self._rules if r.id != rule_id]
                self._persist_user_overrides()

    def add_listener(self, fn: Callable[[Alert], None]) -> None:
        with self._lock:
            self._listeners.append(fn)

    def alerts(self) -> list[Alert]:
        with self._lock:
            return list(self._alerts)

    def clear_alerts(self) -> None:
        with self._lock:
            self._alerts.clear()

    def observe(self, pkt) -> None:
        """Called from the capture worker thread, once per packet."""
        try:
            with self._lock:
                rules = list(self._rules)
        except Exception:
            return
        now = time.time()
        for rule in rules:
            if not rule.enabled:
                continue
            try:
                match = rule.match(pkt) if rule.match else None
            except Exception:
                continue
            if match is None:
                continue
            key = (rule.key_fn(pkt) if rule.key_fn else None) or "*"
            self._tick(rule, key, now, match)

    # ── Internals ─────────────────────────────────────────────────
    def _tick(self, rule: Rule, key: str, now: float, details: dict[str, Any]) -> None:
        with self._lock:
            window = self._counters[rule.id][key]
            cutoff = now - rule.window_seconds
            while window and window[0] < cutoff:
                window.popleft()
            window.append(now)
            if len(window) < rule.threshold:
                return
            last = self._cooldowns[rule.id].get(key, 0.0)
            if now - last < rule.window_seconds:
                return
            self._cooldowns[rule.id][key] = now

            alert = Alert(
                rule_id=rule.id,
                title=rule.title,
                severity=rule.severity,
                message=(
                    f"{rule.title}: {len(window)} matching events in last "
                    f"{int(rule.window_seconds)}s (key={key})"
                ),
                timestamp=now,
                details={**details, "key": key, "count": len(window)},
            )
            self._alerts.append(alert)
            listeners = list(self._listeners)
        for fn in listeners:
            try:
                fn(alert)
            except Exception:
                logger.exception("rule listener crashed")

    def _load_user_rules(self) -> list[Rule]:
        path = _user_rules_path()
        if not path.exists():
            return []
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:
            logger.warning("Failed to read user rules: %s", exc)
            return []
        out: list[Rule] = []
        for raw in data.get("rules", []):
            try:
                out.append(self._rule_from_json(raw))
            except Exception as exc:
                logger.warning("Skipping malformed rule %r: %s", raw.get("id"), exc)
        return out

    def _persist_user_overrides(self) -> None:
        # Writes only user-authored or built-ins whose enabled state differs
        # from the default — keeps the JSON file small.
        builtins_default = {r.id: r.enabled for r in BUILTIN_RULES}
        payload = {"rules": []}
        for r in self._rules:
            if r.is_builtin:
                if builtins_default.get(r.id) != r.enabled:
                    payload["rules"].append(
                        {"id": r.id, "enabled": r.enabled, "is_builtin": True}
                    )
            else:
                payload["rules"].append(r.to_json())
        try:
            _user_rules_path().write_text(
                json.dumps(payload, indent=2), encoding="utf-8"
            )
        except Exception as exc:
            logger.warning("Failed to persist rules: %s", exc)

    def _rule_from_json(self, raw: dict[str, Any]) -> Rule:
        rule_id = raw["id"]
        is_builtin = bool(raw.get("is_builtin"))
        if is_builtin:
            base = next((r for r in BUILTIN_RULES if r.id == rule_id), None)
            if base is None:
                raise ValueError(f"unknown built-in rule id {rule_id!r}")
            return Rule(
                id=base.id,
                title=base.title,
                description=base.description,
                severity=base.severity,
                enabled=bool(raw.get("enabled", base.enabled)),
                threshold=int(raw.get("threshold", base.threshold)),
                window_seconds=float(raw.get("window_seconds", base.window_seconds)),
                is_builtin=True,
                match=base.match,
                key_fn=base.key_fn,
            )
        dsl_raw = raw.get("dsl") or {}
        dsl = SimpleRule(
            protocol=dsl_raw.get("protocol"),
            src_ip=dsl_raw.get("src_ip"),
            dst_ip=dsl_raw.get("dst_ip"),
            dst_port=dsl_raw.get("dst_port"),
            tcp_flags=dsl_raw.get("tcp_flags"),
            key_by=dsl_raw.get("key_by", "src_ip"),
        )
        match, key_fn = dsl.compile()
        return Rule(
            id=rule_id,
            title=str(raw.get("title", rule_id)),
            description=str(raw.get("description", "")),
            severity=str(raw.get("severity", SEVERITY_MEDIUM)),
            enabled=bool(raw.get("enabled", True)),
            threshold=int(raw.get("threshold", 50)),
            window_seconds=float(raw.get("window_seconds", 10)),
            is_builtin=False,
            match=match,
            key_fn=key_fn,
            dsl=dsl,
        )
