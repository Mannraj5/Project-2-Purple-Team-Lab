# Detection Engineering

Why each rule matches what it matches, what it assumes, and how it would be
defeated. The [results](../results/detection-matrix.md) report what happened; this
is the reasoning that produced them.

Ruleset: [`rules/local.rules`](../rules/local.rules) · Snort 3.12.2.0 · SIDs
1000001–1000006.

---

## Design position

Every rule here matches one of two things, and the distinction turned out to
predict rule quality almost perfectly:

**Artefacts of the attack** — an executable inside an HTTP response body, a
deprecated SMB dialect, a PE header traversing a channel that should not carry
one. These are things an attacker must produce to achieve their objective.

**Volumes of ordinary protocol behaviour** — ICMP echoes, TCP SYN flags. These
occur constantly in benign traffic and are distinguished from an attack only by
rate, which means the rule encodes an assumption about what "normal" looks like.

Rules 3, 4 and 6 match artefacts. Rules 1 and 2 match volume. The measured
outcome follows that split exactly: nine precise alerts from the first group,
67,313 alerts and 1,485 false positives from the second.

## A lab-specific constraint

Both hosts sit inside `HOME_NET`, so the `$EXTERNAL_NET -> $HOME_NET` direction
that most public rulesets assume does not apply. Rules here key on behaviour and
content rather than on crossing a perimeter.

This is not purely an artefact of the lab. Flat internal segments are common,
lateral movement occurs entirely inside them, and a ruleset written around a
perimeter has nothing to say about traffic that never crosses one.

---

## Rule 0 — pipeline validation

```
alert tcp any any -> any any ( msg:"LAB-TEST TCP connection detected"; sid:1000000; rev:1; )
```

Deliberately terrible. It matches every TCP packet and produced **137 alerts
against a single 493-packet intrusion.**

It is retained, commented out, for two reasons. It demonstrates why alert volume
is the enemy — a technically correct rule that fires on everything hides
everything. And it proved the detection pipeline functioned end to end before any
real rule was trusted.

**In hindsight this should have been kept as a permanent canary rather than
retired once it matched.** Two rules later returned zero alerts because the
sensor was discarding the traffic, and a live catch-all rule would have shown
alert volume collapsing at the same moment. It was the one instrument that could
have caught the failure early, and it was switched off.

Note also that 137 alerts ≠ 493 packets. Snort runs detection over reassembled
streams, so alerts and packets are not in one-to-one correspondence. Any metric
that conflates them is wrong.

---

## Rule 1 — ICMP echo burst

```
alert icmp any any -> $HOME_NET any (
    msg:"LAB-RECON ICMP echo request burst (possible host sweep)";
    itype:8; detection_filter:track by_src, count 15, seconds 5;
    sid:1000001; rev:1; )
```

**Assumption:** more than fifteen echo requests from one source in five seconds
indicates sweeping rather than diagnostics.

**Result: 1,485 false positives, zero true positives.** The worst possible
outcome — all noise, no signal.

The threshold was exceeded by the benign control capture's own traffic. Volume in
that control was generated with `ping -i 0.2`, which is five echoes per second,
twenty-five per five-second window. The rule was guaranteed to fire before it was
ever deployed.

**This is a defect of the control as much as of the rule**, and both are stated
plainly. But the underlying lesson survives correction: a rate threshold encodes
a claim about normal traffic, and that claim must be validated against real
baseline data before the rule ships. The threshold was chosen by intuition and
the intuition was wrong by a factor of nearly two.

**Revision:** raise the count substantially, track distinct destinations rather
than raw echo volume — a sweep is characterised by *breadth*, not rate, and one
host pinging one host a hundred times is not reconnaissance — and re-validate
against a control that is not itself ICMP-saturated.

---

## Rule 2 — TCP SYN scan

```
alert tcp any any -> $HOME_NET any (
    msg:"LAB-RECON TCP SYN scan";
    flags:S; detection_filter:track by_src, count 30, seconds 5;
    sid:1000002; rev:1; )
```

**Result: 65,828 alerts on reconnaissance, zero everywhere else.** Perfect
specificity. Operationally useless.

The rule is correct and its output is unusable. One port scan buries an analyst
in more alerts than a busy SOC handles in a day, and the intrusion that followed
— which actually took the host — produced 493 packets and would sit entirely
unexamined beneath them.

**Revision:** the alert should be the *event*, not the packet. Snort's
`event_filter` with `type limit` collapses this to one alert per source per
interval, turning 65,828 lines into one actionable statement: *this host scanned
you*. The detection logic needs no change at all; only the reporting does.

That distinction — correct detection, unusable reporting — is worth separating
from rule quality generally. Rule 2 is not a bad rule. It is a good rule with no
output discipline.

---

## Rule 3 — executable requested over HTTP

```
alert tcp any any -> any 80 (
    msg:"LAB-DELIVERY executable requested over HTTP";
    flow:to_server,established; content:"GET"; content:".exe", nocase;
    sid:1000003; rev:1; )
```

**Result: exactly one alert, on exactly the right capture, no false positives.**

Matches the request rather than the response, which is deliberate — the request
is small, appears in a single reassembled PDU, and arrives before the payload
transfers. It is also the earliest point at which the delivery is visible.

**Evasion is trivial.** Rename the file, serve it from a path without an
extension, use HTTPS, or deliver over any protocol other than HTTP. This rule
catches unsophisticated delivery, which is worth catching because unsophisticated
delivery is common, but it should not be mistaken for coverage.

**Limitation:** port 80 only. It would miss an identical download on 8080 — the
same brittleness rule 5 was built to demonstrate, present here and not measured
because no such traffic was generated.

---

## Rule 4 — SMBv1 Trans2

```
alert tcp any any -> $HOME_NET 445 (
    msg:"LAB-EXPLOIT SMBv1 Trans2 request (possible MS17-010)";
    flow:to_server,established; content:"|FF|SMB|32|", offset 4, depth 5;
    sid:1000004; rev:1; )
```

Offset 4 skips the four-byte NetBIOS session header. `FF 53 4D 42` is the SMB1
header; `32` is `SMB_COM_TRANSACTION2`.

**Result: 2 alerts on Chain B, zero elsewhere, no false positives.**

**Why this rule works better than it deserves to.** The benign control contains
real SMB traffic, and it negotiated SMB2 — modern clients do. The two SMB1 frames
present are the initial negotiate before the upgrade. So the rule's precision
comes substantially from the *rarity of the protocol* rather than the precision
of the pattern. SMB1 on a current network is anomalous by itself.

That is a real and defensible source of detection value, but it should be named
rather than mistaken for signature craft. On a network with legacy SMB1 clients
this rule would behave very differently.

**Better target available.** The capture shows `CreateServiceW`, `StartServiceW`
and `DeleteService` over SMB — the actual execution mechanism. Remote service
creation is how a whole family of lateral movement techniques runs code,
MS17-010 or not, and detecting the technique generalises where detecting the
exploit does not. This is the highest-value addition to the ruleset.

---

## Rules 5 and 6 — the paired experiment

These two were written together to test one question: **does matching a C2
channel by port hold up when the port changes?**

Both target the same event — the 199,238-byte Meterpreter stage, byte-identical
across both chains.

### Rule 5 — matched by port

```
alert tcp $HOME_NET any -> $HOME_NET 4444 (
    msg:"LAB-C2 Meterpreter callback to TCP 4444 (port-specific)";
    flow:to_server; sid:1000005; rev:1; )
```

**Deliberately brittle. It is not to be corrected.** Its failure is the
measurement.

**Result: 139 alerts on Chain A, zero on Chain B.**

Chain B delivered the same payload on port 5555 and the rule was blind to it.
One configuration value, changed by an operator who was not even attempting
evasion.

It also produced one alert on the reconnaissance capture, where the port scan
probed 4444 and no C2 existed. A port-based rule cannot distinguish a scan
touching a port from actual use of it.

### Rule 6 — matched by content

```
alert tcp any any -> any any (
    msg:"LAB-C2 PE executable transferred over TCP (possible payload stage)";
    flow:established; content:"MZ"; content:"This program cannot be run in DOS mode";
    sid:1000006; rev:1; )
```

**Result: 2 alerts on Chain A, 1 on Chain B, no false positives.**

Port-agnostic, so the port change defeated nothing. The distribution is an
internal consistency check: Chain A transferred the executable over HTTP *and*
staged over C2 — two PE transfers. Chain B had no HTTP delivery stage — one. The
rule tracks attack structure, not coincidence.

**Its weaknesses, stated honestly.** Matching a DOS stub catches unencoded PE
transfers and nothing else. Encoding, packing, encrypting the channel, or a
stager that does not carry a full PE structure all defeat it. The `"MZ"` match
contributes nothing — two bytes, present everywhere — and adds fragility for no
gain; the DOS stub string alone is the useful pattern.

**What the pair actually shows** is narrower than "content beats port". It is
that a signature keyed to a *configurable* property of an attack fails when the
attacker changes it, while one keyed to a property the attack *must* exhibit
survives. The stage must be a PE. The port is a preference.

---

## Diagnosing silent failure

Rules 4 and 6 initially returned zero alerts. The process that recovered them is
the most transferable thing in this project.

**1. Confirm the data exists, using a different tool.** `tshark` found both
patterns present. This is the step that reframes the problem — the rules were no
longer suspect, the sensor was.

```
tshark -r capture.pcap -Y 'tcp contains "This program cannot"'
tshark -r capture.pcap -Y "smb.cmd == 0x32"
```

**2. Bisect the rule.** Split multi-condition rules into single-condition tests,
plus a control matching something known present. The control mattered most: a
rule matching `"GET"` fired, proving the ruleset loaded and content matching
worked, which eliminated an entire class of explanation.

**3. Read the sensor's own statistics, not just its alerts.** This was decisive
and should have come first:

```
daq       received: 493   analyzed: 493   rx_bytes: 167618
codec     discards: 68 (13.79%)
tcp       bad_tcp4_checksum: 111
```

`rx_bytes` of 167,618 against a 1,237,000-byte capture is the entire finding in
one line. Snort reported no errors and inspected 13.5% of the data.

**4. Fix at source, not with a flag.** `checksum_eval = 'none'` and `-s 65535`
compensate for offload artefacts, but disabling offload on the capture interface
removes the cause:

```
ethtool -K eth0 tx off rx off tso off gso off gro off
```

**The generalisable lesson:** an IDS reporting zero alerts is reporting one of
two entirely different things — no attack, or no visibility — and its alert
output cannot distinguish them. Only its telemetry can. Read `rx_bytes` and
`discards` before believing a quiet sensor.

---

## Required invocation

Both flags are mandatory for captures taken on an endpoint. They are not tuning
preferences; without them two of these six rules return zero against traffic that
matches them.

```
snort -c /etc/snort/snort.lua -R rules/local.rules -r <capture.pcap> \
      -A alert_fast -q -s 65535 --lua "network = { checksum_eval = 'none' }"
```

Captures from an out-of-band sensor, or taken after disabling interface offload,
need neither.

---

## Revisions, in priority order

1. **Add remote service creation detection** (`CreateServiceW` over SMB). Catches
   the technique rather than one exploit, and generalises beyond MS17-010.
2. **Apply `event_filter` to rule 2.** Turns 65,828 alerts into one actionable
   event without touching the detection logic.
3. **Rebuild rule 1** around distinct destinations rather than echo rate, and
   re-validate against a control that is not ICMP-saturated.
4. **Simplify rule 6** — drop the `"MZ"` match, keep the DOS stub.
5. **Broaden rule 3** beyond port 80, or bind it to the HTTP service rather than
   a port number.
6. **Keep a catch-all canary running permanently**, so a collapse in alert volume
   is visible as an event rather than as silence.
7. **Do not fix rule 5.** It is an instrument.
