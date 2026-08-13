# Screenshots

Console evidence from the lab, in the order it was produced.

| File | What it shows |
|---|---|
| `01-victim-adapter-media-disconnected.png` | Victim `ipconfig /all` during troubleshooting. `Media disconnected` — VirtualBox's "Cable Connected" box was unticked, so the adapter was present and correctly configured but dead. Also shows the adapter enumerated as *Local Area Connection 2*, because regenerating the MAC on import made Windows treat it as new hardware and orphan the original profile. |
| `02-chainA-meterpreter-session-opened.png` | Chain A compromise. The 7,168-byte dropper pulls a **199,238-byte stage** back down the same connection — the stage, not the dropper, is the useful detection target. |
| `03-chainA-sysinfo-getuid-ieuser.png` | Target confirmed as Windows 7 Build 7601 SP1 x86. Session running as `IE8WIN7\IEUser` — the "before" half of the privilege escalation evidence. |
| `04-chainA-process-list-dropper-in-ie-cache.png` | Process list. `update[1].exe` (PID 2728) running from the Internet Explorer cache with `iexplore.exe` (PID 2544) as its parent — a browser spawning an executable out of its own cache, which is obvious to host telemetry and structurally invisible to a network sensor. Also shows `sshd.exe` and `cygrunsrv.exe`, identifying the unexpected OpenSSH service found on port 22 during recon. |
| `05-chainA-getsystem-privilege-escalation.png` | `getsystem` succeeding via named pipe impersonation, `IEUser` becoming `NT AUTHORITY\SYSTEM`. **Cropped above the `hashdump` output** — credential material is deliberately excluded from this repository. |
| `06-chainA-capture-capinfos.png` | Capture provenance: packet count, duration and SHA-256. The 13.4-hour span is why this capture was later trimmed into separate reconnaissance and exploitation windows. |
| `07-chainB-ms17010-system-obtained.png` | Chain B. `Built a write-what-where primitive` then `SYSTEM session obtained` — kernel memory corruption granting SYSTEM directly, with no escalation step and no user interaction. Note `Authenticating as user 'IEUser'`: this variant refused anonymous exploitation. |
| `08-snort-config-validated-225-rules.png` | Snort 3 configuration validated. 225 rules loaded — 219 are `file_id` file-type signatures that never alert, plus the six custom rules, so every alert is attributable to a rule written for this project. |
| `09-detection-results-matrix.png` | The complete experiment: all six rules replayed across all four captures. **Rule 5 scores 139 on Chain A and is absent from Chain B; rule 6 catches both.** Note the two required flags — `-s 65535` and `checksum_eval = 'none'` — without which two of these rules return zero. |

## Redaction

`05` is cropped to exclude dumped NTLM hashes. The victim is a publicly
distributed Microsoft test image, so the credentials are not sensitive, but a
public repository is not the place for dumped credential material regardless of
provenance. `.gitignore` blocks `*hashdump*` and `*creds*` to stop it arriving
by accident.
