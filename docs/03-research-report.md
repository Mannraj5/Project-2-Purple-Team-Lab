# Research Report — Structure and Argument

**Status: outline.** Section skeleton, word budgets, and the specific evidence
each section draws on. Prose to be written against this.

Target: 2,500–3,000 words, IEEE referencing.

---

## Working title

> **Silent Failure in Signature-Based Network Intrusion Detection: An
> Experimental Study of Sensor Placement, Capture Fidelity and Rule
> Brittleness**

The title deliberately leads with *silent failure* rather than with Meterpreter
or MS17-010. The attacks are the apparatus, not the subject. A report titled
"detecting Meterpreter with Snort" describes a lab exercise; this one reports a
finding.

## Thesis

> Signature-based network intrusion detection fails in ways that are invisible
> in its own output. A rule that never fires and a rule that fires correctly on
> nothing are indistinguishable, and the causes of the former can lie entirely
> outside the ruleset — in sensor placement, capture fidelity, and measurement
> methodology. Correct detection logic is therefore necessary but not
> sufficient; a detection capability cannot be assumed to work because it
> produces no errors.

Everything below serves that claim. The port-brittleness result supports it;
it is not the point.

## What to leave out

The lab is over-provisioned relative to a 3,000-word report. Cut ruthlessly:

- Blow-by-blow post-exploitation. `getsystem`, `hashdump` and `migrate` are one
  sentence establishing that compromise was total, not three paragraphs.
- The VirtualBox and VBS troubleshooting, except as the single causal sentence
  that explains why the sensor was co-located.
- Rule syntax walkthroughs. The ruleset goes in an appendix.
- The credential findings (blank `sshd` password, Administrator/IEUser hash
  reuse). Genuinely interesting, entirely off-thesis.

---

## 1. Introduction — ~350 words

**Job:** establish the problem, state the research question, say why it matters.

- Signature-based NIDS remains widely deployed; Snort and its derivatives are
  the reference implementation.
- The known weaknesses — evasion, encryption, zero-days — are all *adversarial*.
  Comparatively little attention goes to the sensor failing on its own.
- **Research question:** *To what extent can signature-based network intrusion
  detection identify the stages of a Meterpreter-based intrusion, and what
  causes it to fail?* The second clause is where the contribution is.
- State the headline up front: two of six rules initially returned zero alerts
  against traffic independently confirmed to contain their exact patterns.
- One paragraph on contribution and structure.

## 2. Background — ~300 words

**Job:** situate the work; earn the research-quality marks.

- Snort's detection model: header match, content match, stream reassembly.
- Meterpreter's staged architecture — small stager, large reflective DLL stage —
  and why the stage is the better detection target than the dropper.
- MS17-010 and the distinction that matters here: *eternalblue* against x64 is
  unauthenticated and wormable; the *psexec* variant this 32-bit target required
  is not. "Vulnerable to MS17-010" is not one thing.
- **Key citation to engage with: Ptacek and Newsham (1998).** Their argument is
  that an IDS and the endpoint can hold different views of the same traffic, and
  that attackers exploit the gap. This report documents a *non-adversarial*
  instance of the same structural problem: hardware offload, not an attacker,
  produced the divergence. Framing the finding as a modern accidental case of a
  known adversarial one is the strongest available positioning.
- Sommer and Paxson (2010) on why intrusion detection resists evaluation.

## 3. Methodology — ~600 words

**Job:** enough for reproduction; state limitations before Results, not after.

**Lab.** Two VMs, host-only `192.168.56.0/24`, no route out. Kali (`.10`)
attacker and sensor; Windows 7 Enterprise 7601 SP1 x86 (`.20`) victim, firewall
and Defender disabled, SMBv1 enabled, unpatched. Snort 3.12.2.0.

**State the design constraint here, plainly and once.** Host
virtualisation-based security held the CPU's VT-x extensions; VirtualBox fell
back to the NEM backend; a third VM for a dedicated sensor could not be built.
The IDS therefore runs on the attacking host. Note it as a limitation — its
consequences are a *result*, and belong in §4, not here.

**Attack chains.** Two paths to the same payload:

| | Chain A | Chain B |
|---|---|---|
| Initial access | User executes downloaded exe | Remote SMB exploitation |
| User interaction | Required | None |
| Credentials | None | Required |
| Landed as | `IEUser` | `NT AUTHORITY\SYSTEM` |
| Escalation | `getsystem` | None needed |
| C2 port | 4444 | 5555 |
| Stage | 199,238 bytes | 199,238 bytes |

The identical stage across differing access vectors is what makes rules 5 and 6
a controlled comparison rather than two unrelated observations.

**Datasets.** Four non-overlapping captures: benign control (9,092 packets,
16 min), reconnaissance (132,727), Chain A exploitation (493), Chain B
(filtered). All SHA-256 recorded; all in the repository.

**Ruleset.** Six signatures across recon, delivery, exploitation and C2. Rules 5
and 6 target the same event by port and by content respectively — a deliberate
paired comparison.

**Measurement.** Every capture replayed through the same ruleset; alerts parsed
programmatically. Note that alerts and packets are not 1:1 — Snort inspects
reassembled streams — and that the reported latency is offset from capture
start, not from attack start.

## 4. Results — ~600 words

**Job:** report. Interpretation goes in §5.

**Table 1 — alert matrix.**

| Rule | baseline | recon | chainA | chainB |
|---|---:|---:|---:|---:|
| 1 ICMP burst | 1485 | 0 | 0 | 0 |
| 2 SYN scan | 0 | 65,828 | 0 | 0 |
| 3 exe over HTTP | 0 | 0 | 1 | 0 |
| 4 SMBv1 Trans2 | 0 | 0 | 0 | 2 |
| 5 C2 by port | 0 | 1 | 139 | 0 |
| 6 C2 by content | 0 | 0 | 2 | 1 |

**4.1 Rule brittleness.** Rule 5: 139 on Chain A, 0 on Chain B. Rule 6: 2 and 1.
Identical payload; one configuration value defeated the port-based rule.

**4.2 Instrumentation failure.** Rules 4 and 6 initially returned zero against
traffic `tshark` confirmed contained their patterns. Two independent causes:

- Transmit checksum offload → 111 packets discarded pre-detection. All
  payload-bearing traffic is outbound from the attacker, so the entire delivery
  and C2 surface was invisible.
- Segmentation offload plus the DAQ's 1518-byte default snaplen → oversized
  frames truncated, then discarded as malformed. **Snort ingested 167,618 of
  1,237 kB — 13.5% — and discarded 13.79% of packets.**

Neither produced an error. Both rules returned zero.

**4.3 Alert volume and precision.** Rule 2: perfect specificity, 65,828 alerts.
Rule 1: 1,485 false positives, zero true positives. Rules 3, 4, 6: nine alerts
combined, all correct, no false positives.

**4.4 Timing.** Within Chain A: delivery at 620.593 s, PE transfer at 620.597 s
(+4 ms), C2 established at 630.092 s. **9.5 seconds from download to remote
control**, including human interaction with a browser dialogue.

**4.5 Attack volume asymmetry.** Reconnaissance 132,727 packets; full
compromise 493. A ratio of **269:1** between the noisiest phase and the one
that took the host.

## 5. Discussion — ~800 words

**Job:** the analytical marks live here. Four arguments, roughly 200 words each.

**5.1 Silent failure is the dominant risk.** Three separate instances in one
project — two offload faults and one double-counted metric that reported 2,970
false positives instead of 1,485. None raised an error; all produced plausible
output. Taken at face value, the conclusion would have been that working
signatures were broken. Generalise: a detection pipeline that emits no errors
is not evidence of a working detection capability, and the only defence is
validation traffic with known-correct answers — the purpose the deliberately
trivial rule 0 served.

**5.2 Sensor placement is a detection control.** Both offload faults follow
from capturing on an endpoint, before the NIC finishes with the packet. An
out-of-band sensor observes fully-formed frames and neither occurs. This is
Ptacek and Newsham's divergence-of-views problem arriving without an adversary.
The architectural decision recorded in §3 as a limitation produced a total
detection failure on exactly the traffic that mattered — placement is not a
deployment detail but a determinant of what is detectable at all.

**5.3 Specificity and volume trade against each other.** Rule 2 was perfectly
specific and useless; rule 1 was pure noise; rules 3, 4 and 6 were both precise
and quiet. The distinguishing feature is that the effective rules matched
*artefacts of the attack* — an executable in an HTTP body, an SMB dialect, a PE
header on a C2 channel — while the ineffective ones matched *volumes of ordinary
protocol behaviour*. Note honestly that rule 1's false positive rate is inflated
by a control capture that is 33% ICMP by construction.

**5.4 Response windows are shorter than response processes.** Every rule fired
within milliseconds. Detection speed was never the constraint; the 9.5-second
download-to-C2 window is shorter than any human triage process. This is the
argument for automated containment over alerting, and it also reframes the
269:1 asymmetry — the loud phase is the harmless one, so tuning a SOC by alert
volume optimises for the wrong signal.

**Optionally:** the process-ancestry observation. `iexplore.exe` spawning
`update[1].exe` from the browser cache is trivially visible to host telemetry
and structurally invisible to a network sensor — a concrete case for layered
detection. Include only if the word budget allows.

## 6. Conclusion — ~350 words

- Restate the finding, not the activity.
- Limitations, honestly: single victim OS and architecture; sensor not
  independent; no encrypted or obfuscated C2 tested; small number of runs;
  control capture unrepresentative; no evasion attempted; Chain B's original
  capture required filtering after contamination by a residual session.
- Future work: repeat with an out-of-band sensor and compare — this project
  makes that a testable hypothesis rather than speculation. Encrypted C2.
  Suricata comparison on identical captures.
- Close on the practical implication: validate that the sensor sees what you
  think it sees, before trusting anything it reports.

## References — 12–15, IEEE

Priorities:

- T. H. Ptacek and T. N. Newsham, *Insertion, Evasion, and Denial of Service*,
  1998 — the theoretical frame for §5.2.
- R. Sommer and V. Paxson, "Outside the closed world," IEEE S&P, 2010.
- M. Roesch, "Snort — lightweight intrusion detection for networks," LISA, 1999.
- Snort 3 official documentation (DAQ, snaplen, checksum handling).
- NIST SP 800-94, *Guide to Intrusion Detection and Prevention Systems*.
- MITRE ATT&CK: T1204 User Execution, T1210 Exploitation of Remote Services,
  T1071 Application Layer Protocol, T1055 Process Injection.
- Microsoft MS17-010 bulletin; a technical EternalBlue analysis.
- At least two peer-reviewed sources on IDS false-positive rates or evaluation
  methodology.

Cite the ATT&CK techniques where the chains are described — it maps the work to
a framework a practitioner recognises, at no cost in words.

## Appendices

- A — Full ruleset with commentary
- B — Capture inventory: packet counts, durations, SHA-256
- C — Repository link (raw pcaps, alert logs, analysis tooling, metrics)
- D — Reproduction instructions

## Figures

1. Lab topology
2. Attack chain comparison (parallel timelines, converging at the identical stage)
3. Alert matrix heatmap
4. Chain A timeline — the 9.5-second window
5. Bytes offered vs. bytes inspected — 1,237 kB against 167 kB

Figure 5 is the one to get right. It makes the central finding visible in a
single image: the sensor was reporting normally while inspecting an eighth of
the traffic.
