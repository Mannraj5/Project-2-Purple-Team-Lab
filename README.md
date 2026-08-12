# Purple Team Lab

**Exploitation, Detection Engineering & IDS Evaluation**

An end-to-end purple team project: build an isolated lab, compromise a Windows host
through two distinct attack chains, engineer Snort IDS signatures to detect them, then
measure how well those signatures actually perform — including where they fail.

> **Status:** in progress. Lab execution underway; results and analysis to follow.

---

## Scope and Authorisation

Every action documented here was performed against virtual machines built, owned and
operated by the author, on an isolated host-only network with no route to any external
system. No third-party system was touched at any point.

This repository is published for educational and portfolio purposes. It contains
detection signatures, network captures and methodology — **it does not contain working
payloads or exploit binaries.** Payload generation commands and their SHA-256 hashes
are documented so results can be reproduced, without distributing live malware.

---

## Project at a Glance

- Three-VM isolated lab with a dedicated IDS sensor in promiscuous mode
- Two attack chains: social-engineered Meterpreter payload, and remote exploitation via MS17-010
- Six custom Snort signatures covering reconnaissance, delivery, exploitation and C2
- Quantitative evaluation: detection rate, latency, alert volume and false positives against a clean control capture
- Reproducible offline analysis — replay the included captures and reproduce every number

## Architecture

<!-- TODO: network diagram -->

| Host | Role | Address |
|---|---|---|
| Kali Linux | Attacker | 192.168.56.10 |
| Windows 7 SP1 | Victim | 192.168.56.20 |
| Ubuntu 20.04 | Snort 2.9 sensor | 192.168.56.30 |

Host-only network, `192.168.56.0/24`. The sensor observes the segment in promiscuous
mode, capturing traffic between attacker and victim rather than merely its own.

## Key Findings

<!-- TODO: populated from results -->

## What's Included

- `docs/` — build guide, attack chain walkthrough, detection engineering notes, research report
- `rules/` — the Snort ruleset, plus the `snort.conf` diff against stock
- `pcaps/` — network captures for both attack chains and the clean baseline control
- `logs/` — raw Snort alert output from every run
- `scripts/` — replay harness and alert-log analysis tooling
- `results/` — detection metrics and generated charts
- `tests/` — validation suite

## Reproducing the Results

<!-- TODO: quickstart, once tooling is in place -->

## Documentation

| Document | Contents |
|---|---|
| [Build Guide](docs/00-BUILD-GUIDE.md) | Full lab construction and execution procedure |
| Lab Setup | Topology, configuration, containment decisions |
| Attack Chains | Both intrusion paths, step by step |
| Detection Engineering | Signature design, tuning and rationale |
| Research Report | Experimental evaluation and analysis |

## Author

**Manraj Singh Makin** — [github.com/Mannraj5](https://github.com/Mannraj5)

## License

[MIT](LICENSE)
