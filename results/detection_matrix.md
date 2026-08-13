| Rule | baseline-clean-full | chainA-exploitation | chainA-recon | chainB-clean |
|---|---:|---:|---:|---:|
| 1000001 LAB-RECON ICMP echo request burst (possible host sweep) | 1485 | 0 | 0 | 0 |
| 1000002 LAB-RECON TCP SYN scan | 0 | 0 | 65828 | 0 |
| 1000003 LAB-DELIVERY executable requested over HTTP | 0 | 1 | 0 | 0 |
| 1000004 LAB-EXPLOIT SMBv1 Trans2 request (possible MS17-010) | 0 | 0 | 0 | 2 |
| 1000005 LAB-C2 Meterpreter callback to TCP 4444 (port-specific) | 0 | 139 | 1 | 0 |
| 1000006 LAB-C2 PE executable transferred over TCP (possible payload stage) | 0 | 2 | 0 | 1 |
