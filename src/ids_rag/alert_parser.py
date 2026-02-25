# IDS-RAG: Intrusion Detection System with Retrieval-Augmented Generation
# Copyright (C) 2026 - This file is part of IDS-RAG.
# Licensed under GNU General Public License v3.0
# See LICENSE file for details or visit https://www.gnu.org/licenses/gpl-3.0.html

"""
alert_parser.py
---------------
Parses Suricata EVE JSON alerts and converts them into structured objects
ready for semantic retrieval against the knowledge base (Chroma + MITRE/OWASP).

Usage:
    from ids_rag.alert_parser import SuricataAlertParser, SuricataMonitor

    # Parse a single JSON dict (e.g. from an API or message queue)
    alert = SuricataAlertParser.from_dict(eve_json_dict)
    query  = alert.build_retrieval_query()   # string → embed & search
    filter = alert.build_chroma_filter()     # dict   → Chroma metadata filter

    # Tail a live eve.json file
    monitor = SuricataMonitor("/var/log/suricata/eve.json")
    for alert in monitor.follow():
        print(alert.build_retrieval_query())
"""

import json
import time
import os
from dataclasses import dataclass, field
from typing import Any, Dict, Generator, List, Optional


# ---------------------------------------------------------------------------
# Severity label mapping  (Suricata: 1 = highest, 4 = lowest)
# ---------------------------------------------------------------------------
SEVERITY_LABELS: Dict[int, str] = {
    1: "critical",
    2: "high",
    3: "medium",
    4: "low",
}

# ---------------------------------------------------------------------------
# No hardcoded category→tactic mapping.
#
# Rationale: Suricata/Snort classification lists have 40+ categories and
# third-party rulesets (Emerging Threats, etc.) add their own.  Maintaining
# a static mapping is fragile and unnecessary – the embedding model
# (multilingual-e5-large / BGE-M3) resolves semantic similarity at query
# time, so "Attempted Administrator Privilege Gain" will naturally surface
# MITRE T1055/T1078 docs and "Web Application Attack" will surface OWASP
# A03 Injection docs without any explicit wiring.
#
# If you want to add lightweight structured enrichment later, do it as a
# separate optional post-processing step outside of alert_parser.py.
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Well-known destination ports → protocol context strings
# Enriches the retrieval query with human-readable protocol hints.
# ---------------------------------------------------------------------------
PORT_CONTEXT: Dict[int, str] = {
    21:   "FTP",
    22:   "SSH",
    23:   "Telnet",
    25:   "SMTP",
    53:   "DNS",
    80:   "HTTP",
    110:  "POP3",
    143:  "IMAP",
    443:  "HTTPS TLS",
    445:  "SMB",
    1433: "MSSQL",
    1521: "Oracle DB",
    3306: "MySQL",
    3389: "RDP",
    4444: "Metasploit default",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP proxy",
    8443: "HTTPS alternate",
    9200: "Elasticsearch",
    27017:"MongoDB",
}


# ---------------------------------------------------------------------------
# Dataclass
# ---------------------------------------------------------------------------
@dataclass
class SuricataAlert:
    """
    Structured representation of a single Suricata EVE JSON alert event.

    All fields are Optional to handle partial / malformed events gracefully.
    The most important methods for the RAG pipeline are:
        - build_retrieval_query()  → semantic embedding string for Chroma search
        - build_chroma_filter()    → optional Chroma metadata pre-filter (None = full KB)
        - inferred_tactics         → MITRE tactics if the ruleset provides them explicitly

    Generic design: no hardcoded category→tactic mappings. Any Suricata alert
    (regardless of ruleset or category name) is parsed and the embedding model
    handles semantic matching against the full knowledge base at query time.
    """

    # --- Core network tuple ---
    timestamp:      Optional[str]   = None
    src_ip:         Optional[str]   = None
    src_port:       Optional[int]   = None
    dest_ip:        Optional[str]   = None
    dest_port:      Optional[int]   = None
    proto:          Optional[str]   = None
    flow_id:        Optional[int]   = None
    in_iface:       Optional[str]   = None

    # --- Alert fields ---
    signature:      Optional[str]   = None
    signature_id:   Optional[int]   = None
    category:       Optional[str]   = None
    severity:       Optional[int]   = None
    action:         Optional[str]   = None   # allowed | blocked | drop
    gid:            Optional[int]   = None
    rev:            Optional[int]   = None

    # --- Optional application layer context ---
    http_hostname:  Optional[str]   = None
    http_url:       Optional[str]   = None
    http_method:    Optional[str]   = None
    http_status:    Optional[int]   = None
    tls_sni:        Optional[str]   = None
    tls_subject:    Optional[str]   = None
    dns_query:      Optional[str]   = None
    dns_type:       Optional[str]   = None

    # --- Flow stats ---
    flow_bytes_toserver:   Optional[int] = None
    flow_bytes_toclient:   Optional[int] = None
    flow_pkts_toserver:    Optional[int] = None
    flow_pkts_toclient:    Optional[int] = None

    # --- Parsed extras ---
    raw: Dict[str, Any] = field(default_factory=dict, repr=False)

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def severity_label(self) -> str:
        """Human-readable severity string (critical / high / medium / low)."""
        return SEVERITY_LABELS.get(self.severity or 4, "unknown")

    @property
    def inferred_tactics(self) -> List[str]:
        """
        Returns MITRE ATT&CK tactics if Suricata already provides them in the
        raw event (e.g. via enriched rulesets that tag metadata.mitre_tactic).
        Falls back to an empty list – the embedding model handles the semantic
        mapping at retrieval time without needing explicit wiring here.
        """
        metadata = self.raw.get("alert", {}).get("metadata", {})
        # Some rulesets store tactics as a list under 'mitre_tactic'
        tactics = metadata.get("mitre_tactic", [])
        if isinstance(tactics, str):
            tactics = [tactics]
        return [t.lower().replace(" ", "-") for t in tactics]

    @property
    def port_context(self) -> Optional[str]:
        """Returns a human-readable label for the destination port if known."""
        if self.dest_port is not None:
            return PORT_CONTEXT.get(self.dest_port)
        return None

    # ------------------------------------------------------------------
    # RAG interface
    # ------------------------------------------------------------------

    def build_retrieval_query(self) -> str:
        """
        Builds a semantically rich, source-agnostic query string for
        embedding-based retrieval against the full knowledge base
        (MITRE ATT&CK, OWASP Top 10, and any future sources).

        Strategy:
          1. Signature  – most information-dense field (ET rule names are descriptive)
          2. Category   – structural label understood by both MITRE and OWASP embeddings
          3. Port/protocol context – e.g. "SMB port 445", "HTTP port 80"
          4. HTTP/TLS/DNS context – application layer detail (critical for OWASP matching)

        Intentionally excluded:
          - MITRE tactic hints  → would bias the vector toward MITRE docs and away
                                  from equally relevant OWASP docs (e.g. a SQL injection
                                  alert should surface OWASP A03 just as well as T1190)
          - Severity label      → carries no semantic meaning for KB retrieval

        Returns a pipe-separated string suitable for direct embedding.
        """
        parts: List[str] = []

        # 1. Signature (primary signal)
        if self.signature:
            parts.append(self.signature)

        # 2. Category
        if self.category:
            parts.append(self.category)

        # 3. Proto + port context
        proto_str = self.proto or ""
        port_str = ""
        if self.dest_port:
            port_label = self.port_context
            port_str = (
                f"{proto_str} port {self.dest_port} ({port_label})"
                if port_label
                else f"{proto_str} port {self.dest_port}"
            )
        elif proto_str:
            port_str = proto_str
        if port_str:
            parts.append(port_str)

        # 5. Application layer context (best-effort)
        if self.http_url and self.http_hostname:
            parts.append(f"HTTP {self.http_method or 'GET'} {self.http_hostname}{self.http_url}")
        elif self.http_hostname:
            parts.append(f"HTTP host {self.http_hostname}")

        if self.tls_sni:
            parts.append(f"TLS SNI {self.tls_sni}")
        elif self.tls_subject:
            parts.append(f"TLS subject {self.tls_subject}")

        if self.dns_query:
            parts.append(f"DNS query {self.dns_query}")

        return " | ".join(parts) if parts else "(empty alert)"

    def build_chroma_filter(self) -> Optional[Dict[str, Any]]:
        """
        Returns a Chroma metadata pre-filter dict to narrow the search space
        before embedding similarity is computed, or None for a full KB search.

        Default behaviour: always return None (= search across ALL KB sources:
        MITRE ATT&CK, OWASP Top 10, and any future sources).

        The embedding model resolves which KB source is most relevant without
        explicit filtering.  Override this method or pass a manual filter in
        RAGSystem.query() if you need source-scoped retrieval for a specific
        use case (e.g. only OWASP for web-facing alerts).
        """
        return None  # Full KB search – let embedding similarity decide

    def to_dict(self) -> Dict[str, Any]:
        """Serialises the alert to a plain dict (excludes raw field)."""
        return {
            "timestamp":            self.timestamp,
            "src_ip":               self.src_ip,
            "src_port":             self.src_port,
            "dest_ip":              self.dest_ip,
            "dest_port":            self.dest_port,
            "proto":                self.proto,
            "flow_id":              self.flow_id,
            "signature":            self.signature,
            "signature_id":         self.signature_id,
            "category":             self.category,
            "severity":             self.severity,
            "severity_label":       self.severity_label,
            "action":               self.action,
            "inferred_tactics":     self.inferred_tactics,
            "http_hostname":        self.http_hostname,
            "http_url":             self.http_url,
            "http_method":          self.http_method,
            "tls_sni":              self.tls_sni,
            "dns_query":            self.dns_query,
            "retrieval_query":      self.build_retrieval_query(),
            "chroma_filter":        self.build_chroma_filter(),
        }

    def __str__(self) -> str:
        return (
            f"[{self.severity_label.upper()}] "
            f"{self.timestamp or '?'} | "
            f"{self.src_ip}:{self.src_port} → {self.dest_ip}:{self.dest_port} | "
            f"{self.signature or '?'}"
        )


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------
class SuricataAlertParser:
    """Stateless factory methods for constructing SuricataAlert objects."""

    @staticmethod
    def from_dict(eve: Dict[str, Any]) -> Optional["SuricataAlert"]:
        """
        Creates a SuricataAlert from a parsed EVE JSON dict.
        Returns None if the event is not of type 'alert'.
        """
        if eve.get("event_type") != "alert":
            return None

        alert_block = eve.get("alert", {})
        http_block  = eve.get("http", {})
        tls_block   = eve.get("tls", {})
        dns_block   = eve.get("dns", {})
        flow_block  = eve.get("flow", {})

        return SuricataAlert(
            # Network tuple
            timestamp   = eve.get("timestamp"),
            src_ip      = eve.get("src_ip"),
            src_port    = eve.get("src_port"),
            dest_ip     = eve.get("dest_ip"),
            dest_port   = eve.get("dest_port"),
            proto       = eve.get("proto"),
            flow_id     = eve.get("flow_id"),
            in_iface    = eve.get("in_iface"),

            # Alert block
            signature   = alert_block.get("signature"),
            signature_id= alert_block.get("signature_id"),
            category    = alert_block.get("category"),
            severity    = alert_block.get("severity"),
            action      = alert_block.get("action"),
            gid         = alert_block.get("gid"),
            rev         = alert_block.get("rev"),

            # HTTP context
            http_hostname = http_block.get("hostname"),
            http_url      = http_block.get("url"),
            http_method   = http_block.get("http_method"),
            http_status   = http_block.get("status"),

            # TLS context
            tls_sni     = tls_block.get("sni"),
            tls_subject = tls_block.get("subject"),

            # DNS context (Suricata dns block may be nested differently)
            dns_query   = (
                dns_block.get("query", [{}])[0].get("rrname")
                if isinstance(dns_block.get("query"), list)
                else dns_block.get("rrname")
            ),
            dns_type    = (
                dns_block.get("query", [{}])[0].get("rrtype")
                if isinstance(dns_block.get("query"), list)
                else dns_block.get("rrtype")
            ),

            # Flow stats
            flow_bytes_toserver  = flow_block.get("bytes_toserver"),
            flow_bytes_toclient  = flow_block.get("bytes_toclient"),
            flow_pkts_toserver   = flow_block.get("pkts_toserver"),
            flow_pkts_toclient   = flow_block.get("pkts_toclient"),

            raw = eve,
        )

    @staticmethod
    def from_json_line(line: str) -> Optional["SuricataAlert"]:
        """
        Parses a single raw JSON line from eve.json.
        Returns None on parse errors or non-alert events.
        """
        line = line.strip()
        if not line:
            return None
        try:
            eve = json.loads(line)
        except json.JSONDecodeError:
            return None
        return SuricataAlertParser.from_dict(eve)

    @staticmethod
    def from_file(path: str) -> List["SuricataAlert"]:
        """
        Reads an entire EVE JSON file and returns all parsed alert events.
        Useful for batch/offline analysis.
        """
        alerts: List[SuricataAlert] = []
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                alert = SuricataAlertParser.from_json_line(line)
                if alert is not None:
                    alerts.append(alert)
        return alerts


# ---------------------------------------------------------------------------
# Live monitor (tail -f style, mirrors ZeekMonitor interface)
# ---------------------------------------------------------------------------
class SuricataMonitor:
    """
    Tails a Suricata EVE JSON log file and yields parsed SuricataAlert
    objects as they arrive.  Non-alert event types are silently skipped.

    Args:
        log_path:         Path to eve.json (or any EVE JSON log).
        poll_interval:    Sleep duration (seconds) between empty reads.
        from_beginning:   If True, parse the whole file before tailing.
                          Defaults to False (tail only new lines).
    """

    def __init__(
        self,
        log_path: str,
        poll_interval: float = 0.2,
        from_beginning: bool = False,
    ):
        self.log_path       = log_path
        self.poll_interval  = poll_interval
        self.from_beginning = from_beginning
        self._stop_flag     = False

    def follow(self) -> Generator["SuricataAlert", None, None]:
        """
        Generator that yields SuricataAlert objects as new lines appear
        in the EVE JSON file.  Runs until stop() is called.
        """
        if not os.path.exists(self.log_path):
            raise FileNotFoundError(f"EVE log not found: {self.log_path}")

        print(f"[SuricataMonitor] Tailing {self.log_path}")

        with open(self.log_path, "r", encoding="utf-8") as f:
            if not self.from_beginning:
                f.seek(0, 2)  # Jump to end for live tailing

            while not self._stop_flag:
                line = f.readline()
                if line:
                    alert = SuricataAlertParser.from_json_line(line)
                    if alert is not None:
                        yield alert
                else:
                    time.sleep(self.poll_interval)

    def stop(self) -> None:
        self._stop_flag = True


# ---------------------------------------------------------------------------
# Quick self-test / demo  (python -m ids_rag.alert_parser)
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    _EXAMPLE_EVE = {
        "timestamp": "2026-02-25T14:32:10.123456+0000",
        "event_type": "alert",
        "flow_id": 987654321,
        "in_iface": "eth0",
        "src_ip": "192.168.1.100",
        "src_port": 54321,
        "dest_ip": "10.0.0.5",
        "dest_port": 445,
        "proto": "TCP",
        "alert": {
            "action": "allowed",
            "gid": 1,
            "signature_id": 2027865,
            "rev": 2,
            "signature": "ET EXPLOIT Possible ETERNALBLUE MS17-010 Echo Response",
            "category": "Attempted Administrator Privilege Gain",
            "severity": 1,
        },
        "flow": {
            "pkts_toserver": 12,
            "pkts_toclient": 8,
            "bytes_toserver": 9200,
            "bytes_toclient": 4100,
        },
    }

    alert = SuricataAlertParser.from_dict(_EXAMPLE_EVE)
    print("=== Parsed Alert ===")
    print(alert)
    print()
    print("=== Retrieval Query ===")
    print(alert.build_retrieval_query())
    print()
    print("=== Inferred MITRE Tactics ===")
    print(alert.inferred_tactics)
    print()
    print("=== Chroma Filter ===")
    print(alert.build_chroma_filter())
    print()
    print("=== Full Dict ===")
    import pprint
    pprint.pprint(alert.to_dict())
