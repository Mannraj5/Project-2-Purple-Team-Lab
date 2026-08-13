"""Tests for the detection analysis helpers.

Run from the repository root:

    python -m pytest tests/ -v
"""

from __future__ import annotations

import sys
from datetime import datetime
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts"))

from snortlab import (  # noqa: E402
    PcapError,
    markdown_table,
    parse_alerts,
    pcap_start_time,
    rules_from_file,
    summarise,
)

PCAPS = REPO / "pcaps"
RULES = REPO / "rules" / "local.rules"

# Verified against `capinfos` on the sensor. These pin the pcap header parsing:
# an endianness or precision regression shifts them by years, which is exactly
# the bug this guards against.
KNOWN_START_TIMES = {
    "baseline-clean-full.pcap": datetime(2026, 8, 12, 23, 21, 54, 149080),
    "chainA-recon.pcap": datetime(2026, 8, 13, 0, 4, 44, 198505),
    "chainA-exploitation.pcap": datetime(2026, 8, 13, 13, 10, 49, 637944),
    "chainB-run1.pcap": datetime(2026, 8, 13, 13, 42, 34, 370712),
}

SAMPLE_ALERTS = """\
08/13-13:21:10.230686 [**] [1:1000003:1] "LAB-DELIVERY executable requested over HTTP" \
[**] [Priority: 0] {TCP} 192.168.56.20:49158 -> 192.168.56.10:80
08/13-13:21:19.730047 [**] [1:1000005:1] "LAB-C2 Meterpreter callback to TCP 4444 \
(port-specific)" [**] [Priority: 0] {TCP} 192.168.56.20:49159 -> 192.168.56.10:4444
08/13-13:21:19.730318 [**] [1:1000005:1] "LAB-C2 Meterpreter callback to TCP 4444 \
(port-specific)" [**] [Priority: 0] {TCP} 192.168.56.20:49159 -> 192.168.56.10:4444
o")~   Snort exiting
"""


@pytest.mark.parametrize("name,expected", KNOWN_START_TIMES.items())
def test_pcap_start_time_matches_capinfos(name, expected):
    path = PCAPS / name
    if not path.exists():
        pytest.skip(f"{name} not present")
    assert pcap_start_time(path) == expected


def test_pcap_start_time_rejects_missing_file():
    with pytest.raises((PcapError, OSError)):
        pcap_start_time(PCAPS / "does-not-exist.pcap")


def test_parse_alerts_extracts_only_alert_lines():
    alerts = parse_alerts(SAMPLE_ALERTS, year=2026)
    assert len(alerts) == 3
    assert [a.sid for a in alerts] == [1000003, 1000005, 1000005]
    assert alerts[0].timestamp == datetime(2026, 8, 13, 13, 21, 10, 230686)
    assert alerts[0].msg.startswith("LAB-DELIVERY")


def test_parse_alerts_ignores_noise():
    assert parse_alerts("not an alert\n\no\")~ Snort exiting\n", year=2026) == []


def test_rules_file_defines_the_six_lab_rules():
    if not RULES.exists():
        pytest.skip("rules file not present")
    known = rules_from_file(RULES)
    assert set(known) == {1000001, 1000002, 1000003, 1000004, 1000005, 1000006}
    assert "port-specific" in known[1000005]


def test_summarise_reports_silent_rules_as_zero():
    """A rule that never fires must appear with a zero count.

    Silence is a finding — it can mean the rule is wrong or that the sensor
    never saw the traffic. Dropping it from the results hides both.
    """
    start = datetime(2026, 8, 13, 13, 10, 49)
    known = {1000003: "delivery", 1000005: "c2", 1000006: "stage"}
    rows = summarise("cap", parse_alerts(SAMPLE_ALERTS, 2026), start, False, known)

    by_sid = {r.sid: r for r in rows}
    assert by_sid[1000006].alerts == 0
    assert by_sid[1000006].verdict == "none"
    assert by_sid[1000005].alerts == 2


def test_summarise_computes_latency_from_capture_start():
    start = datetime(2026, 8, 13, 13, 21, 0)
    rows = summarise("cap", parse_alerts(SAMPLE_ALERTS, 2026), start, False, None)
    delivery = next(r for r in rows if r.sid == 1000003)
    assert delivery.latency_s == pytest.approx(10.230686, abs=1e-4)


def test_benign_capture_alerts_are_labelled_false_positives():
    start = datetime(2026, 8, 13, 13, 21, 0)
    rows = summarise("baseline", parse_alerts(SAMPLE_ALERTS, 2026), start, True, None)
    assert all(r.verdict == "false positive" for r in rows if r.alerts)


def test_markdown_table_has_a_row_per_rule():
    start = datetime(2026, 8, 13, 13, 21, 0)
    rows = summarise("capA", parse_alerts(SAMPLE_ALERTS, 2026), start, False, None)
    table = markdown_table(rows, ["capA"])
    assert "| Rule | capA |" in table
    assert table.count("\n") == 1 + 1 + len({r.sid for r in rows}) - 1
