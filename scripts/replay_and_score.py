#!/usr/bin/env python3
"""Replay captures through Snort 3 and score the ruleset against them.

Runs every capture through the same ruleset, parses the alerts, and writes a
per-rule metrics table. Reproduces the results in results/detection-matrix.md.

Usage (on the Kali sensor):

    python3 scripts/replay_and_score.py \\
        --pcap-dir /captures \\
        --rules /etc/snort/rules/local.rules \\
        --config /etc/snort/snort.lua \\
        --out results/

Captures whose names contain "baseline" are treated as the benign control, so
alerts against them are labelled false positives.

On offload-affected captures pass --endpoint-capture (the default). Captures
taken after `ethtool -K <if> tx off rx off tso off gso off gro off`, or from an
out-of-band sensor, should use --no-endpoint-capture. See the rules file header
for why this matters — without the compensating flags, Snort silently inspects
a fraction of the traffic and rules return zero alerts indistinguishable from a
genuine non-match.
"""

from __future__ import annotations

import argparse
import csv
import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from snortlab import (  # noqa: E402
    CaptureMetrics,
    PcapError,
    markdown_table,
    parse_alerts,
    pcap_start_time,
    rules_from_file,
    summarise,
)

BENIGN_MARKERS = ("baseline", "clean-control")


def build_command(
    config: Path,
    rules: Path,
    pcap: Path,
    endpoint_capture: bool,
    snaplen: int,
) -> list[str]:
    cmd = [
        "snort",
        "-c", str(config),
        "-R", str(rules),
        "-r", str(pcap),
        "-A", "alert_fast",
        "-q",
    ]
    if endpoint_capture:
        # See module docstring and rules/local.rules header.
        cmd += ["-s", str(snaplen)]
        cmd += ["--lua", "network = { checksum_eval = 'none' }"]
    return cmd


def run_snort(cmd: list[str]) -> str:
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0 and not proc.stdout:
        raise RuntimeError(
            f"snort failed ({proc.returncode}):\n{proc.stderr.strip()[:800]}"
        )
    return proc.stdout


def write_csv(rows: list[CaptureMetrics], path: Path) -> None:
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(
            ["capture", "sid", "msg", "alerts", "first_alert",
             "last_alert", "latency_s", "benign", "verdict"]
        )
        for row in rows:
            writer.writerow([
                row.capture,
                row.sid,
                row.msg,
                row.alerts,
                row.first_alert.isoformat() if row.first_alert else "",
                row.last_alert.isoformat() if row.last_alert else "",
                f"{row.latency_s:.3f}" if row.latency_s is not None else "",
                row.benign,
                row.verdict,
            ])


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pcap-dir", type=Path, default=Path("/captures"))
    parser.add_argument("--rules", type=Path,
                        default=Path("/etc/snort/rules/local.rules"))
    parser.add_argument("--config", type=Path,
                        default=Path("/etc/snort/snort.lua"))
    parser.add_argument("--out", type=Path, default=Path("results"))
    parser.add_argument("--snaplen", type=int, default=65535)
    parser.add_argument("--endpoint-capture", dest="endpoint_capture",
                        action="store_true", default=True)
    parser.add_argument("--no-endpoint-capture", dest="endpoint_capture",
                        action="store_false")
    args = parser.parse_args()

    pcaps = sorted(args.pcap_dir.glob("*.pcap"))
    if not pcaps:
        print(f"no .pcap files in {args.pcap_dir}", file=sys.stderr)
        return 1

    known = rules_from_file(args.rules)
    print(f"{len(known)} rules loaded from {args.rules}")

    all_rows: list[CaptureMetrics] = []
    processed: list[str] = []

    for pcap in pcaps:
        name = pcap.stem
        try:
            start = pcap_start_time(pcap)
        except PcapError as exc:
            print(f"  skip {name}: {exc}", file=sys.stderr)
            continue

        benign = any(marker in name.lower() for marker in BENIGN_MARKERS)
        cmd = build_command(
            args.config, args.rules, pcap, args.endpoint_capture, args.snaplen
        )
        try:
            output = run_snort(cmd)
        except RuntimeError as exc:
            print(f"  skip {name}: {exc}", file=sys.stderr)
            continue

        alerts = parse_alerts(output, year=start.year)
        rows = summarise(name, alerts, start, benign, known)
        all_rows.extend(rows)
        processed.append(name)

        fired = sum(1 for r in rows if r.alerts)
        tag = " [benign control]" if benign else ""
        print(f"  {name}: {len(alerts)} alerts across {fired} rules{tag}")

    if not all_rows:
        print("nothing scored", file=sys.stderr)
        return 1

    args.out.mkdir(parents=True, exist_ok=True)
    write_csv(all_rows, args.out / "detection_metrics.csv")
    (args.out / "detection_metrics.json").write_text(
        json.dumps(
            [
                {
                    "capture": r.capture, "sid": r.sid, "msg": r.msg,
                    "alerts": r.alerts,
                    "first_alert": r.first_alert.isoformat() if r.first_alert else None,
                    "latency_s": r.latency_s, "benign": r.benign,
                    "verdict": r.verdict,
                }
                for r in all_rows
            ],
            indent=2,
        ),
        encoding="utf-8",
    )
    (args.out / "detection_matrix.md").write_text(
        markdown_table(all_rows, processed) + "\n", encoding="utf-8"
    )

    false_positives = sum(r.alerts for r in all_rows if r.benign and r.alerts)
    silent = {r.sid for r in all_rows} - {r.sid for r in all_rows if r.alerts}

    print(f"\nwrote {args.out}/detection_metrics.csv, .json, detection_matrix.md")
    print(f"false positives against benign control: {false_positives}")
    if silent:
        print(f"rules that never fired: {sorted(silent)}")
        print("  a silent rule is a finding — check instrumentation before "
              "assuming the rule is wrong")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
