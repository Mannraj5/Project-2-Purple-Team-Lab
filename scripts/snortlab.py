"""Shared helpers for the Purple Team Lab detection analysis.

Standard library only, so it runs on the Kali sensor without installing
anything. Handles pcap timestamps, alert_fast parsing, and the metrics
derived from them.
"""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

# Magic numbers as they appear on disk, byte for byte. Comparing raw bytes
# rather than unpacked integers avoids getting the endianness backwards.
PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),      # little-endian, microseconds
    b"\xa1\xb2\xc3\xd4": (">", 1_000_000),      # big-endian, microseconds
    b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),  # little-endian, nanoseconds
    b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),  # big-endian, nanoseconds
}
PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"

# 08/13-13:21:10.230686 [**] [1:1000005:1] "LAB-C2 ..." [**] ... {TCP} src -> dst
ALERT_RE = re.compile(
    r"^(?P<ts>\d{2}/\d{2}-\d{2}:\d{2}:\d{2}\.\d+)\s+"
    r"\[\*\*\]\s+\[(?P<gid>\d+):(?P<sid>\d+):(?P<rev>\d+)\]\s+"
    r'"(?P<msg>[^"]*)"'
)


class PcapError(RuntimeError):
    pass


@dataclass
class Alert:
    timestamp: datetime
    sid: int
    rev: int
    msg: str


@dataclass
class CaptureMetrics:
    """Per-rule detection metrics for a single capture."""

    capture: str
    sid: int
    msg: str
    alerts: int
    first_alert: datetime | None
    last_alert: datetime | None
    latency_s: float | None
    benign: bool

    @property
    def verdict(self) -> str:
        """Only false positives can be labelled mechanically.

        A rule firing on the benign control is unambiguously a false positive.
        Deciding whether an alert on an attack capture is a true positive
        requires knowing what the rule was written to catch, which is a
        judgement call — so it is left to the analyst rather than guessed here.
        """
        if self.alerts == 0:
            return "none"
        return "false positive" if self.benign else "alert"


def pcap_start_time(path: Path) -> datetime:
    """Timestamp of the first packet in a classic pcap file.

    Parsed directly rather than shelling out to capinfos, so the script has no
    external dependencies. pcapng is rejected explicitly — Snort's DAQ expects
    classic pcap anyway, so a pcapng here is a mistake worth surfacing loudly.
    """
    with path.open("rb") as fh:
        global_header = fh.read(24)
        if len(global_header) < 24:
            raise PcapError(f"{path.name}: truncated pcap header")

        magic = global_header[:4]
        if magic == PCAPNG_MAGIC:
            raise PcapError(
                f"{path.name}: pcapng, not classic pcap. "
                f"Convert with: editcap -F pcap {path.name} out.pcap"
            )
        if magic not in PCAP_MAGICS:
            raise PcapError(f"{path.name}: unrecognised magic {magic.hex()}")
        endian, ticks_per_second = PCAP_MAGICS[magic]

        packet_header = fh.read(16)
        if len(packet_header) < 16:
            raise PcapError(f"{path.name}: no packets")

        ts_sec, ts_frac = struct.unpack(f"{endian}II", packet_header[:8])
        return datetime.fromtimestamp(ts_sec + ts_frac / ticks_per_second)


def parse_alerts(text: str, year: int) -> list[Alert]:
    """Parse alert_fast output.

    alert_fast omits the year, so it is supplied by the caller from the
    capture's own first-packet timestamp.
    """
    alerts: list[Alert] = []
    for line in text.splitlines():
        match = ALERT_RE.match(line.strip())
        if not match:
            continue
        stamp = datetime.strptime(
            f"{year}/{match.group('ts')}", "%Y/%m/%d-%H:%M:%S.%f"
        )
        alerts.append(
            Alert(
                timestamp=stamp,
                sid=int(match.group("sid")),
                rev=int(match.group("rev")),
                msg=match.group("msg"),
            )
        )
    return alerts


def summarise(
    capture: str,
    alerts: list[Alert],
    capture_start: datetime,
    benign: bool,
    known_sids: dict[int, str] | None = None,
) -> list[CaptureMetrics]:
    """Collapse a capture's alerts into one row per rule.

    Rules in known_sids that never fired are emitted with a zero count, so a
    silent rule is visible in the results rather than simply absent. A rule
    that produced nothing is a finding, not missing data.
    """
    by_sid: dict[int, list[Alert]] = {}
    for alert in alerts:
        by_sid.setdefault(alert.sid, []).append(alert)

    for sid in (known_sids or {}):
        by_sid.setdefault(sid, [])

    rows: list[CaptureMetrics] = []
    for sid in sorted(by_sid):
        fired = sorted(by_sid[sid], key=lambda a: a.timestamp)
        msg = fired[0].msg if fired else (known_sids or {}).get(sid, "")
        first = fired[0].timestamp if fired else None
        last = fired[-1].timestamp if fired else None
        latency = (first - capture_start).total_seconds() if first else None
        rows.append(
            CaptureMetrics(
                capture=capture,
                sid=sid,
                msg=msg,
                alerts=len(fired),
                first_alert=first,
                last_alert=last,
                latency_s=latency,
                benign=benign,
            )
        )
    return rows


def rules_from_file(path: Path) -> dict[int, str]:
    """Extract sid -> msg for every rule in a Snort rules file."""
    text = path.read_text(encoding="utf-8", errors="replace")
    # Rules may span lines; collapse before matching.
    flat = " ".join(
        line for line in text.splitlines() if not line.lstrip().startswith("#")
    )
    found: dict[int, str] = {}
    for msg, sid in re.findall(r'msg:"([^"]*)".*?sid:(\d+)', flat):
        found[int(sid)] = msg
    return found


def markdown_table(rows: list[CaptureMetrics], captures: list[str]) -> str:
    """Render the alert matrix as markdown, ready to paste into the report."""
    sids = sorted({row.sid for row in rows})
    labels = {row.sid: row.msg for row in rows if row.msg}
    counts = {(row.capture, row.sid): row.alerts for row in rows}

    header = "| Rule | " + " | ".join(captures) + " |"
    divider = "|---|" + "---:|" * len(captures)
    lines = [header, divider]
    for sid in sids:
        cells = [str(counts.get((cap, sid), 0)) for cap in captures]
        lines.append(f"| {sid} {labels.get(sid, '')} | " + " | ".join(cells) + " |")
    return "\n".join(lines)
