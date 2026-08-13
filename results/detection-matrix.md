# Detection Results

Alert counts per rule, per capture. Snort 3.12.2.0, ruleset at
[`rules/local.rules`](../rules/local.rules).

## Invocation

Both flags below are **required**, and neither is optional tuning — see
[Instrumentation failures](#instrumentation-failures).

```
snort -c /etc/snort/snort.lua \
      -R /etc/snort/rules/local.rules \
      -r <capture.pcap> \
      -A alert_fast -q -s 65535 \
      --lua "network = { checksum_eval = 'none' }"
```

## Results

| # | Rule | baseline | recon | chainA-exploit | chainB-clean |
|---|------|---------:|------:|---------------:|-------------:|
| 1 | ICMP echo burst | **1485** | 0 | 0 | 0 |
| 2 | TCP SYN scan | 0 | **65,828** | 0 | 0 |
| 3 | Executable over HTTP | 0 | 0 | **1** | 0 |
| 4 | SMBv1 Trans2 (MS17-010) | 0 | 0 | 0 | **2** |
| 5 | C2 callback, port 4444 | 0 | 1 | **139** | **0** |
| 6 | PE transfer, content-based | 0 | 0 | **2** | **1** |

Captures: `baseline-clean-full` 9,092 pkt (benign control) · `chainA-recon`
132,727 pkt · `chainA-exploitation` 493 pkt · `chainB-clean` (Chain B with the
residual Chain A session on 4444 filtered out).

## Principal result — signature brittleness

Rules 5 and 6 were written as a paired experiment against the same event: a
199,238-byte Meterpreter stage, byte-identical across both chains.

| | Chain A (port 4444) | Chain B (port 5555) |
|---|---:|---:|
| Rule 5 — matches by **port** | 139 | **0** |
| Rule 6 — matches by **content** | 2 | **1** |

Changing a single configuration value — the C2 port — rendered the port-based
signature completely blind to an identical payload delivered by the same
operator against the same host. The content-based rule was unaffected.

Neither rule produced a false positive against the benign control.

## Rule quality, as measured

The six rules span the full range of signature quality, which was not designed
but is what the data shows:

- **Rules 3 and 4** — one and two alerts respectively, on exactly the correct
  captures, zero false positives. Precise and actionable.
- **Rule 6** — three alerts total, each corresponding to a real PE transfer,
  zero false positives. Fires twice on Chain A (HTTP delivery plus C2 stage)
  and once on Chain B (C2 stage only, as Chain B had no HTTP delivery stage).
  That asymmetry is a consistency check: the rule is tracking the attack
  structure, not coincidence.
- **Rule 2** — perfect specificity, 65,828 alerts. Correct and operationally
  useless; a single port scan would bury an analyst.
- **Rule 5** — catches one chain, misses an identical payload on another port.
  One further alert on the recon capture, triggered by the port scan probing
  4444 with no C2 present: a port-based rule cannot distinguish a scan touching
  a port from actual use of it.
- **Rule 1** — 1,485 false positives, zero true positives. The worst outcome
  available: all noise, no signal. The threshold (15 echoes in 5 seconds) is
  exceeded by the control capture's own ping generation.

## Instrumentation failures

Rules 4 and 6 initially returned **zero alerts against traffic that
demonstrably contained what they matched**, verified independently with
`tshark`. Two separate causes, both silent:

**1. Transmit checksum offload.** The NIC computes TCP checksums in hardware;
`tcpdump` taps before that, so every packet Kali *sent* was captured with an
unfinished checksum. Snort discards bad-checksum packets before detection —
111 of them here. All payload-bearing traffic in this lab is outbound from the
attacker, so the entire C2 and delivery surface was invisible. Fixed with
`checksum_eval = 'none'`; recovered rule 4.

**2. Segmentation offload and snaplen truncation.** TSO produced 7,354-byte
super-frames. Snort's pcap DAQ defaults to a 1518-byte snaplen, truncating
them; the decoder then discarded them as malformed on the header/length
mismatch. Snort ingested 167,618 bytes of a 1,237 kB capture — 13.5% — and
discarded 13.79% of packets outright. Fixed with `-s 65535`; recovered rule 6.

**Neither failure was visible in the output.** Both rules returned zero,
indistinguishable from a correctly-functioning rule finding nothing. Taken at
face value, the conclusion would have been that the signatures were wrong, and
working detection logic would have been rewritten to chase a problem that was
never in the rules.

Both trace to a single architectural cause: **the sensor is co-located with an
endpoint.** Capturing on a host means capturing before the NIC has finished
with the packet. An out-of-band sensor on a SPAN port or TAP observes
fully-formed frames and neither failure occurs.

That co-location was not chosen. Host virtualisation-based security held the
CPU's VT-x extensions, VirtualBox fell back to the NEM backend, and the
dedicated sensor VM could not be built (see the build guide's design
decisions). A constraint recorded in Phase 0 as "loss of an independent sensor"
became, in Phase 2, a measured and total detection failure on the traffic that
mattered most.

Sensor placement is not a deployment detail. It determines what can be detected
at all.

## Caveats

- Chain B's original capture was contaminated by a residual Chain A session on
  port 4444 (the victim was not restored to `ready-to-infect` between runs).
  Identified through TCP conversation analysis and filtered to produce
  `chainB-clean`. A clean re-run from a restored snapshot is outstanding.
- The control capture is 33% ICMP by construction, which directly causes rule
  1's false positive rate. Representative of the lab, not of a real network.
- Alerts and packets are not 1:1. Snort runs detection over reassembled
  streams, so counts above are alerts, not packets.
- All results required both flags above. Captures taken after disabling NIC
  offload (`ethtool -K eth0 tx off rx off tso off gso off gro off`) should not.
