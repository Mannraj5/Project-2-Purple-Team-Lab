# Silent Failure in Signature-Based Network Intrusion Detection

### An Experimental Study of Sensor Placement, Capture Fidelity and Rule Brittleness

**Mannraj**

---

## Abstract

Signature-based network intrusion detection is usually evaluated on whether its
rules match the right traffic. This study reports an experiment in which two of
six correctly written rules produced no alerts against traffic independently
confirmed to contain their exact match patterns. The cause lay outside the
ruleset entirely: network interface offload artefacts, introduced by capturing
on an endpoint rather than out of band, left the sensor inspecting 13.5% of the
data it was offered while reporting no errors. A third measurement fault
inflated a false-positive count by exactly double. None of the three produced an
error condition; all produced plausible output. The finding is that the dominant
risk in signature-based detection is not the rule that matches badly but the
pipeline that fails silently, and that sensor placement is therefore a detection
control rather than a deployment detail.

---

## 1. Introduction

Signature-based network intrusion detection remains widely deployed, and Snort
[1] is its reference implementation. Its limitations are well catalogued:
signatures cannot match what they have not seen, encryption defeats content
inspection, and an adversary who knows the ruleset can evade it. What these
share is that they are *adversarial* — they describe an attacker defeating a
functioning sensor.

Comparatively little attention is paid to the sensor failing without any
adversary at all. This report describes an experiment in which precisely that
occurred, repeatedly, and in which the failures were invisible in the tool's own
output.

**Research question:** *To what extent can signature-based network intrusion
detection identify the stages of a Meterpreter-based intrusion, and what causes
it to fail?* The second clause carries the contribution. The first is answered
straightforwardly and largely confirms what is already known.

I built an isolated two-host laboratory, compromised a Windows 7 target through
two distinct attack chains delivering a byte-identical payload, wrote six Snort 3
signatures to detect them, and replayed four packet captures through those
signatures to measure the result. Two rules initially reported nothing. Packet
analysis with an independent tool confirmed the traffic they targeted was
present. The rules were correct; the sensor was not seeing the data.

Section 2 situates the work. Section 3 describes the apparatus. Section 4
reports results. Section 5 argues that silent instrumentation failure, rather
than rule quality, is the binding constraint on this class of detection, and
that the sensor's position in the network determines what can be detected at
all.

---

## 2. Background

Snort's detection model matches packet headers, then searches reassembled
application data for content patterns [1]. Modern releases interpose protocol
inspectors and stream reassembly between the wire and the rule, so a signature
does not see raw frames — it sees whatever the inspection chain presents. That
indirection is the source of the failures reported here.

The payload under study is Meterpreter, which uses a staged architecture: a small
first-stage executable establishes a connection and retrieves a much larger
reflectively-loaded library into memory. This makes the *stage transfer* a far
better detection target than the dropper, since the stage is orders of magnitude
larger and carries recognisable structure.

The exploitation chain uses MS17-010 (CVE-2017-0144) [7], the SMBv1 vulnerability
behind WannaCry. An important distinction emerged experimentally: MS17-010 is
routinely described as unauthenticated and wormable, which holds for the
`eternalblue` module against 64-bit targets, but the `psexec` variant required
for the 32-bit host used here refused anonymous exploitation and succeeded only
with valid SMB credentials. "Vulnerable to MS17-010" is not a single property.

The theoretical frame for the central finding is Ptacek and Newsham [2], who
argued in 1998 that an intrusion detection system and the endpoint it protects
can hold materially different views of the same traffic, and that this gap is
exploitable. Their concern was adversarial — insertion and evasion attacks
deliberately engineered to desynchronise the two views. This study documents the
same structural divergence arising with no attacker involved: network interface
hardware, performing routine optimisation, caused the sensor's view of the
traffic to differ from what actually crossed the wire.

Sommer and Paxson [3] observe that intrusion detection resists evaluation
because ground truth is scarce and operational data is not shareable. This
project addresses that narrowly by publishing every capture, rule and alert log
alongside the analysis. Axelsson [4] supplies the frame for interpreting
false-positive rates: because intrusions are rare relative to benign traffic,
even a low false-positive rate produces an alert stream dominated by noise.

---

## 3. Methodology

### 3.1 Laboratory

Two virtual machines on an isolated VirtualBox host-only segment,
`192.168.56.0/24`, with DHCP disabled and no default gateway configured on the
victim:

| Host | Role | Address |
|---|---|---|
| Kali Linux | Attacker; Snort 3.12.2.0 sensor | 192.168.56.10 |
| Windows 7 Enterprise 7601 SP1 x86 | Victim | 192.168.56.20 |

The victim was deliberately weakened and every change recorded: firewall
disabled on all profiles, Windows Defender disabled, SMBv1 and file sharing
enabled, UAC set to never notify, no patches applied. Exposure was verified by
port scan before exploitation was attempted, and vulnerability confirmed with
Metasploit's MS17-010 scanner rather than assumed.

The source material for this lab specifies a bridged network adapter. That would
place an unpatched host with its firewall disabled directly onto the residential
LAN, so host-only networking was used instead and the deviation documented. The
victim was given a single adapter and no gateway; the attacker's second adapter,
used for package installation, was disabled during every capture.

**A constraint must be declared here, because its consequences are a result.**
The intended design used a third virtual machine as a dedicated out-of-band
sensor observing the segment in promiscuous mode. The host system runs
virtualisation-based security, which holds the processor's VT-x extensions;
VirtualBox consequently falls back to a slower emulation backend and the third
machine could not be built. The IDS therefore runs on the attacking host. This is
recorded as a limitation of the design; Section 4.2 reports what it cost.

### 3.2 Attack chains

Two intrusion paths were executed, chosen to differ at initial access while
converging on an identical payload.

| | Chain A | Chain B |
|---|---|---|
| Initial access | User executes downloaded executable | Remote SMB exploitation |
| User interaction | Required | None |
| Credentials | None | Required |
| Landed as | `IE8WIN7\IEUser` | `NT AUTHORITY\SYSTEM` |
| Escalation | `getsystem`, named pipe impersonation | None needed |
| C2 port | 4444 | 5555 |
| Meterpreter stage | 199,238 bytes | 199,238 bytes |

The identical stage across differing access vectors is what makes the
rule comparison in Section 4.1 controlled rather than anecdotal: the same event
is presented to the same sensor twice, differing only in transport port.

### 3.3 Datasets

Four non-overlapping captures, all published with SHA-256 digests:

| Capture | Packets | Content |
|---|---:|---|
| `baseline-clean-full` | 9,092 | Benign control: HTTP, ICMP, authenticated SMB, background broadcast |
| `chainA-recon` | 132,727 | Host discovery and full TCP port scan |
| `chainA-exploitation` | 493 | Delivery, staging, command-and-control |
| `chainB-clean` | — | MS17-010 exploitation and C2 |

The benign control is the basis for every false-positive figure reported. It is
33% ICMP by construction, an artefact of the traffic generation used to reach
adequate volume, and unrepresentative of a production network in that respect.

Chain B's original capture was contaminated: the Chain A session had not been
terminated and continued beaconing on port 4444 throughout. This was detected
through TCP conversation analysis and the affected conversation filtered out.
The uncontaminated capture is reported as `chainB-clean`.

### 3.4 Ruleset and measurement

Six signatures were written covering reconnaissance, delivery, exploitation and
command-and-control, mapping to MITRE ATT&CK techniques T1204, T1210, T1071 and
T1055 [8]. Rules 5 and 6 form a deliberate paired comparison, targeting the same
event by transport port and by payload content respectively.

Each capture was replayed through the identical ruleset and alerts parsed
programmatically. Two properties of the measurement require statement. Alerts
and packets are not in one-to-one correspondence, because detection operates over
reassembled streams rather than frames. And the latency figures reported measure
offset from the first packet of a capture, not from the onset of the attack;
they are comparable within a capture and not between captures.

---

## 4. Results

### 4.1 Alert matrix

| Rule | baseline | recon | chainA | chainB |
|---|---:|---:|---:|---:|
| 1 — ICMP echo burst | **1485** | 0 | 0 | 0 |
| 2 — TCP SYN scan | 0 | **65,828** | 0 | 0 |
| 3 — Executable over HTTP | 0 | 0 | **1** | 0 |
| 4 — SMBv1 Trans2 (MS17-010) | 0 | 0 | 0 | **2** |
| 5 — C2 matched by port | 0 | 1 | **139** | **0** |
| 6 — C2 matched by content | 0 | 0 | **2** | **1** |

Rule 5 produced 139 alerts against Chain A and **none** against Chain B. Rule 6
detected both. The two chains delivered a byte-identical 199,238-byte payload
from the same operator against the same host; the port-based signature was
defeated by a single configuration value.

Rule 6's alert distribution provides an internal consistency check: two alerts on
Chain A, one on Chain B. Chain A transferred the executable over HTTP and then
staged over the C2 channel; Chain B had no delivery stage. The rule tracks
attack structure rather than coincidence.

### 4.2 Instrumentation failure

Rules 4 and 6 initially returned zero alerts. Independent inspection of the same
captures with `tshark` confirmed both patterns were present — the SMB Trans2
requests in frames 27 and 70, and the PE header and DOS stub on both the HTTP
response and the C2 channel. Two distinct causes were identified:

**Transmit checksum offload.** Modern interfaces compute TCP checksums in
hardware. Packet capture on the transmitting host taps before that occurs, so
outbound packets are recorded with incomplete checksums. Snort discards
bad-checksum packets before detection; 111 were dropped. Because every
payload-bearing packet in this lab is outbound from the attacker, the entire
delivery and C2 surface was excluded from inspection.

**Segmentation offload and snaplen truncation.** Segmentation offload produced
frames of 7,354 bytes, far above the 1,500-byte interface MTU. Snort's packet
capture layer defaults to a 1,518-byte snapshot length and truncated them; the
decoder then rejected the truncated frames as malformed on the length mismatch.
**Snort ingested 167,618 bytes of a 1,237,000-byte capture — 13.5% — and
discarded 13.79% of packets outright.**

Neither fault raised an error. Both rules simply reported zero, a result
indistinguishable from a correctly functioning rule finding nothing.

A third fault occurred in measurement rather than capture. The initial scoring
run included both merged captures and the captures derived from them, counting
the same packets twice and reporting 2,970 false positives where the correct
figure is 1,485.

### 4.3 Precision and volume

Rules 3, 4 and 6 produced nine alerts in total, every one corresponding to a real
attack event, with no false positives. Rule 2 achieved perfect specificity —
firing only on the reconnaissance capture — at a volume of 65,828 alerts. Rule 1
produced 1,485 false positives and no true positives.

### 4.4 Timing

Within the Chain A capture: the executable was requested at 620.593 s, the PE
transfer observed at 620.597 s, and the C2 channel established at 630.092 s.
**The interval from payload request to established remote control was 9.5
seconds**, and includes the time a human took to interact with a browser download
dialogue.

### 4.5 Volume asymmetry

Reconnaissance produced 132,727 packets. The complete compromise — delivery,
staging, C2 establishment, privilege escalation and credential access —
produced 493. A ratio of **269:1** between the noisiest phase of the intrusion
and the phase that took the host.

---

## 5. Discussion

### 5.1 Silent failure is the dominant risk

Three independent measurement faults occurred in a single short project. Two
arose from interface offload; one from double-counting overlapping datasets.
Their common property is more significant than their causes: **none produced an
error condition, and all produced plausible output.**

Two rules returning zero looks exactly like two rules that found nothing. A
false-positive count of 2,970 is no less believable than 1,485. Had any been
accepted at face value, the conclusion would have been that working signatures
were defective — and the rational response would have been to rewrite correct
detection logic to compensate for a fault that was never in it.

This inverts the usual framing of detection quality. Rule correctness is
necessary but not sufficient, and a pipeline emitting no errors is not evidence
of a functioning detection capability. All three faults were found by comparison
against an external reference: `tshark` for the capture faults, arithmetic for
the measurement fault. None was discoverable from the IDS output alone.

The practical implication is that detection pipelines require validation traffic
with known-correct answers, exercised regularly, purely to establish that the
sensor is seeing anything. The deliberately trivial rule used here to confirm the
pipeline functioned before real rules were deployed served exactly that purpose,
and in retrospect should have been retained as a permanent canary rather than
discarded once it had matched.

### 5.2 Sensor placement is a detection control

Both capture faults follow from a single architectural property: the sensor was
co-located with an endpoint, so packets were observed before the interface had
finished processing them. An out-of-band sensor on a mirror port or network tap
observes frames after transmission is complete, and neither fault arises.

This is Ptacek and Newsham's divergence-of-views problem [2] arriving without an
adversary. Their analysis concerned attackers deliberately engineering a
mismatch between what the IDS sees and what the endpoint processes. Here the
mismatch was produced by ordinary hardware optimisation, and the effect —
detection silently operating on a different data stream than the one on the wire
— was the same.

The constraint that produced it was recorded during lab construction as a
limitation, in the mild sense of a compromise made for practical reasons. It
became a total detection failure on outbound traffic, which is the direction
command-and-control travels. The distance between "we could not build a separate
sensor" and "the sensor could not see the attack" was not visible at the point
the decision was made, and was not visible in any output afterwards.

Sensor placement therefore belongs in the same category as rule quality: a
determinant of what is detectable, not an implementation detail to be settled by
available hardware.

### 5.3 Specificity and volume trade against each other

The six rules span the range of signature quality without that having been the
design intent. Rules 3, 4 and 6 were precise and quiet. Rule 2 was perfectly
specific and operationally useless — a single port scan generating 65,828 alerts
would exhaust an analyst before the intrusion it preceded was examined. Rule 1
was pure noise.

The distinguishing property is what each matched. The effective rules matched
*artefacts of the attack*: an executable within an HTTP response body, a
deprecated SMB dialect, a PE header traversing a non-HTTP channel. The
ineffective rules matched *volumes of ordinary protocol behaviour* — ICMP echoes
and TCP SYN flags — distinguished from benign traffic only by rate. Rate-based
thresholds encode an assumption about normal traffic that a control capture will
falsify as soon as it is examined honestly.

This is Axelsson's base-rate problem [4] in concrete form. Rule 1's threshold
was exceeded by the control capture's own traffic generation, which is a defect
of the control as much as of the rule, and is stated as such. But the direction
of the result holds independently: content-based signatures matching attack
artefacts substantially outperformed rate-based signatures matching protocol
volume, on both precision and alert burden.

### 5.4 Response windows are shorter than response processes

Every rule fired within milliseconds of the traffic that triggered it. Detection
latency was never the limiting factor, and optimising it further would achieve
nothing.

What limits response is the 9.5 seconds between payload request and established
remote control. No human triage process operates at that speed. By the time an
alert is queued, enriched and read, the host is already under external control
and the relevant question has changed from prevention to containment. This is a
direct argument for automated response rather than alerting, at least for
high-confidence signatures of the kind rules 3, 4 and 6 proved to be.

The volume asymmetry sharpens the point. Reconnaissance generated 269 times the
traffic of the compromise, so a monitoring posture tuned by alert volume
allocates its attention almost entirely to the phase that causes no harm. The
noisy phase is the survivable one; the quiet phase is the one that ends with
SYSTEM.

---

## 6. Conclusion

Signature-based network intrusion detection failed in this experiment in a manner
its own output could not express. Two correctly written rules reported nothing
while the sensor inspected 13.5% of the data offered to it, and no error was
raised at any point. A third fault doubled a reported false-positive rate. Each
was found only by checking the detection pipeline against an independent
reference.

The port-based signature's failure against an identical payload on a different
port is a clean demonstration of signature brittleness, but it is the less
important result. Brittleness is anticipated and can be designed around;
silent instrumentation failure cannot be designed around by anyone who does not
know it is occurring.

**Limitations.** A single victim operating system and architecture. A sensor
co-located with the attacking host rather than positioned out of band. No
encrypted or obfuscated command-and-control tested, and no evasion attempted. A
small number of runs, with no repetition to establish variance. A benign control
that is unrepresentative in protocol mix and that directly caused one rule's
false-positive rate. Chain B's capture required filtering after contamination by
a residual session.

**Future work.** The central claim is now directly testable: repeating this
experiment with an out-of-band sensor should eliminate both capture faults, and
the comparison would quantify what sensor placement is worth. Extending to
encrypted C2 would test whether the content-based signature that outperformed
its port-based counterpart here retains any advantage when the payload is opaque.
Replaying identical captures through a second detection engine would separate
findings specific to Snort from properties of signature-based detection
generally.

The practical conclusion is narrower than the theoretical one and more useful:
before trusting what an intrusion detection system reports, establish that it can
see. Silence is not evidence of absence, and in this experiment it was never
once evidence of absence.

---

## References

All references verified against the publisher of record. Web sources last
accessed 13 August 2026.

[1] M. Roesch, "Snort — lightweight intrusion detection for networks," in *Proc.
13th USENIX Conf. on System Administration (LISA '99)*, Seattle, WA, USA,
Nov. 1999, pp. 229–238.

[2] T. H. Ptacek and T. N. Newsham, "Insertion, evasion, and denial of service:
Eluding network intrusion detection," Secure Networks Inc., Calgary, AB, Canada,
Tech. Rep., Jan. 1998. (Also archived: U.S. Defense Technical Information Center,
ADA391565.)

[3] R. Sommer and V. Paxson, "Outside the closed world: On using machine learning
for network intrusion detection," in *Proc. IEEE Symp. Security and Privacy*,
Oakland, CA, USA, May 2010, pp. 305–316, doi: 10.1109/SP.2010.25.

[4] S. Axelsson, "The base-rate fallacy and the difficulty of intrusion
detection," *ACM Trans. Information and System Security*, vol. 3, no. 3,
pp. 186–205, Aug. 2000, doi: 10.1145/357830.357849.

[5] K. Scarfone and P. Mell, "Guide to intrusion detection and prevention systems
(IDPS)," National Institute of Standards and Technology, Gaithersburg, MD, USA,
NIST Special Publication 800-94, Feb. 2007. [Online]. Available:
https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-94.pdf

[6] Cisco Systems, *Snort 3 Documentation*. [Online]. Available:
https://www.snort.org/documents

[7] Microsoft Corporation, "Microsoft Security Bulletin MS17-010 — Critical:
Security update for Microsoft Windows SMB Server (4013389)," Mar. 2017. [Online].
Available:
https://learn.microsoft.com/en-us/security-updates/securitybulletins/2017/ms17-010

[8] MITRE Corporation, *MITRE ATT&CK Enterprise Matrix*. Techniques T1204.002
(User Execution: Malicious File), T1210 (Exploitation of Remote Services),
T1071.001 (Application Layer Protocol: Web Protocols), T1055 (Process Injection),
T1134 (Access Token Manipulation), T1003.002 (OS Credential Dumping: Security
Account Manager), T1569.002 (System Services: Service Execution). [Online].
Available: https://attack.mitre.org

[9] D. E. Denning, "An intrusion-detection model," *IEEE Trans. Software
Engineering*, vol. SE-13, no. 2, pp. 222–232, Feb. 1987,
doi: 10.1109/TSE.1987.232894.

[10] B. Anderson and D. McGrew, "Identifying encrypted malware traffic with
contextual flow data," in *Proc. 2016 ACM Workshop on Artificial Intelligence and
Security (AISec '16)*, Vienna, Austria, Oct. 2016, pp. 35–46,
doi: 10.1145/2996758.2996768.

[11] Rapid7, *Metasploit Framework Documentation*. [Online]. Available:
https://docs.metasploit.com

[12] The Tcpdump Group, *tcpdump and libpcap documentation*. [Online]. Available:
https://www.tcpdump.org

[13] Linux Kernel Organization, "Segmentation Offloads," *Linux Networking
Documentation*. [Online]. Available:
https://www.kernel.org/doc/html/latest/networking/segmentation-offloads.html

---

## Appendices

**Appendix A — Ruleset.** Six signatures with commentary and the required
invocation: [`rules/local.rules`](../rules/local.rules)

**Appendix B — Capture inventory.** Packet counts, durations and SHA-256 digests
for every capture: [`results/detection-matrix.md`](../results/detection-matrix.md)

**Appendix C — Raw data.** All captures, alert logs, evidence and analysis
tooling: https://github.com/Mannraj5/Project-2-Purple-Team-Lab

**Appendix D — Reproduction.** Detection results can be reproduced from the
published captures without rebuilding the laboratory. Instructions in the
repository README; analysis tooling in
[`scripts/`](../scripts/) with tests in [`tests/`](../tests/).
