# Capture Inventory

Every packet capture used in this project, with provenance. All are classic pcap
(little-endian, Ethernet), readable by Snort's DAQ without conversion.

## Canonical set

These four are non-overlapping and are the captures the published results were
measured against.

| Capture | Packets | Duration | Size | Role |
|---|---:|---:|---:|---|
| `baseline-clean-full.pcap` | 9,092 | 976.5 s | 4.3 MB | Benign control |
| `chainA-recon.pcap` | 132,727 | 287.5 s | 9.5 MB | Host discovery, full TCP port scan |
| `chainA-exploitation.pcap` | 493 | 1060.4 s | 1.2 MB | HTTP delivery, staging, C2 on 4444 |
| `chainB-clean.pcap` | 563 | 329.0 s | 572 KB | MS17-010 exploitation, C2 on 5555 |

## Retained originals

Kept as primary evidence. **Do not score these alongside the canonical set** —
each contains packets that also appear in a capture derived from it, so including
both counts the same traffic twice. The first scoring run of this project reported
2,970 false positives instead of 1,485 for exactly that reason.

| Capture | Packets | Duration | Size | Superseded by |
|---|---:|---:|---:|---|
| `chainA-run1.pcap` | 134,478 | 48,225.8 s | 10.9 MB | `chainA-recon` + `chainA-exploitation` |
| `chainB-run1.pcap` | 581 | 329.0 s | 575 KB | `chainB-clean` |

## Derivations

**`chainA-recon.pcap`, `chainA-exploitation.pcap`** — time-window trims of
`chainA-run1.pcap`. The original ran 13.4 hours because `tcpdump` was left running
between the reconnaissance and exploitation sessions; the two windows isolate the
activity.

```
editcap -F pcap -A "2026-08-13 00:04:00" -B "2026-08-13 00:10:00" chainA-run1.pcap chainA-recon.pcap
editcap -F pcap -A "2026-08-13 13:10:00" -B "2026-08-13 13:29:00" chainA-run1.pcap chainA-exploitation.pcap
```

**`chainB-clean.pcap`** — `chainB-run1.pcap` with the residual Chain A session
removed. The Chain A Meterpreter session was not terminated before Chain B was
run and continued beaconing on port 4444 throughout, so the original capture
contains two intrusions. Identified through TCP conversation analysis and
filtered:

```
tshark -r chainB-run1.pcap -Y "not tcp.port==4444" -w chainB-clean.pcap -F pcap
```

581 packets in, 563 out — the 18 packets removed are the entire 4444 conversation.

**`baseline-clean-full.pcap`** — merge of two capture sessions. The first pass
contained no TCP 445 traffic at all, because the attacker runs no SMB server and
the victim-side share browse never established a session. Without benign SMB in
the control, the MS17-010 rule would have had nothing to be tested against and its
false-positive figure would have been meaningless. A second capture of
authenticated SMB file access was taken and merged:

```
mergecap -F pcap -w baseline-clean-full.pcap baseline-clean.pcap baseline-smb.pcap
```

The two input captures are not published — they are wholly contained in the merge.

## Integrity

SHA-256, computed on the committed files. Each was verified against `capinfos`
output on the sensor after transfer.

```
96ed0c0f0a32f104dcdeddb60415189d4213bbe703a058b0ee5aef1b31b2880e  baseline-clean-full.pcap
0b3268116a6001ec02c85b2ab569e446662bb08ee599bbf48e29fe5514d1ea38  chainA-recon.pcap
197eefed68630c7440bc0bc3308d3f2fbd0e2e2a0e0b04f65c67a529938c32c5  chainA-exploitation.pcap
7f0083762bf4012d37e3288a3e9dc3d6c3f3324b70aa3442aacbb3e67f50022b  chainA-run1.pcap
7a19ff4f4d1c3dd503e1858a48f183ae40358448550fe9526520de2b00803b07  chainB-clean.pcap
ba30820f31069e543c84fdc587b7b2bfeb4c1a66473afe01e05fbbea4b15cf44  chainB-run1.pcap
```

Verify with `sha256sum -c` against this list, or `capinfos <file>`, which prints
the digest alongside packet counts and duration.

## Known characteristics

Two properties affect how these captures behave under analysis, and both are
consequences of capturing on an endpoint rather than out of band.

**Incomplete checksums on outbound packets.** Transmit checksum offload means the
NIC finishes the checksum after `tcpdump` has already recorded the packet. Snort
discards bad-checksum packets before detection, which silently excludes all
attacker-originated traffic — the entire C2 and delivery surface.

**Oversized frames.** Segmentation offload produced frames up to 7,354 bytes,
above the 1,500-byte MTU. Snort's default 1518-byte snaplen truncates them and the
decoder then rejects them as malformed.

Both are compensated at replay time:

```
snort -c snort.lua -R local.rules -r <capture>.pcap -A alert_fast -q -s 65535 \
      --lua "network = { checksum_eval = 'none' }"
```

Without both flags, two of the six rules return zero alerts against traffic that
matches them. See [`results/detection-matrix.md`](../results/detection-matrix.md).

Captures taken after `ethtool -K eth0 tx off rx off tso off gso off gro off`, or
from an out-of-band sensor, require neither.
