# Attack Time Machine

Attack Time Machine is a defensive cybersecurity MVP for recording endpoint activity into a causally linked, tamper-evident timeline. It is designed for incident response teams that need to reconstruct what happened after a compromise without trusting mutable logs left behind on the host.

The project focuses on safe blue-team capabilities:

- append-only JSONL event records with hash chaining
- optional HMAC sealing for deployment-specific integrity keys
- causal graph reconstruction across process, file, network, and alert events
- replay and query CLI for forensic timelines
- a simulator that generates benign attack-like incident traces for testing
- Linux-first collector architecture with an eBPF-ready adapter boundary

This repository does not include exploit code, malware, offensive payloads, or instructions for attacking systems.

## Quick Start

```bash
python -m venv .venv
. .venv/bin/activate
pip install -e ".[dev]"

atm simulate --scenario incident-dry-run --out demo.atm.jsonl --key demo-secret
atm verify demo.atm.jsonl --key demo-secret
atm timeline demo.atm.jsonl
atm replay demo.atm.jsonl --speed 20
atm graph demo.atm.jsonl --format dot > incident.dot
pytest
```

On Windows PowerShell:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
atm simulate --scenario incident-dry-run --out demo.atm.jsonl --key demo-secret
atm verify demo.atm.jsonl --key demo-secret
pytest
```

## Architecture

```text
Collectors          Recorder               Evidence Store          Reconstruction
----------          --------               --------------          --------------
eBPF adapter  --->  normalize event  --->  chained JSONL    --->  causal graph
auditd adapter      validate schema        previous_hash          timeline query
simulator           assign event_id        record_hash            replay
                    link parents           optional HMAC          DOT export
```

The MVP ships with a simulator collector so it can be run safely anywhere. The `collectors` module defines a small event-source interface intended for Linux collectors such as eBPF, auditd, or fanotify. See [docs/EBPF_COLLECTOR.md](docs/EBPF_COLLECTOR.md).

## Threat Model

Attack Time Machine assumes an attacker may gain user-level or partial administrative access after collection has started. It aims to make deletion, insertion, and rewriting of historical endpoint events detectable during later verification.

It does not claim to survive full kernel compromise, firmware compromise, stolen HMAC keys, or compromise of every remote evidence sink. For production use, forward records to remote immutable storage as they are produced.

## Event Model

Each event contains:

- stable `event_id`
- RFC 3339 UTC timestamp
- `event_type`: `process_start`, `file_write`, `network_connect`, `alert`, or similar
- `subject`: actor such as a process
- `object`: affected file, socket, account, or resource
- `parents`: causal predecessor event IDs
- `data`: normalized metadata

The recorder writes an envelope around the event:

- `sequence`
- `previous_hash`
- `event_hash`
- `record_hash`
- optional `hmac`

`record_hash` commits to the previous hash and normalized event, creating a tamper-evident chain.

## CLI

```bash
atm simulate --scenario incident-dry-run --out demo.atm.jsonl --key demo-secret
atm verify demo.atm.jsonl --key demo-secret
atm timeline demo.atm.jsonl --type file_write
atm query demo.atm.jsonl --subject proc:find:1519
atm replay demo.atm.jsonl --speed 10
atm graph demo.atm.jsonl --format json
atm graph demo.atm.jsonl --format dot
```

## Repository Layout

```text
src/attack_time_machine/
  chain.py          hash chain writer and verifier
  events.py         normalized event schema
  graph.py          causal graph reconstruction
  query.py          timeline filtering
  replay.py         deterministic replay
  simulator.py      safe incident simulator
  cli.py            command line interface
docs/
  ARCHITECTURE.md
  EBPF_COLLECTOR.md
  SECURITY.md
tests/
```

## Status

This is a serious MVP, not production EDR. The next step is a privileged Linux collector implemented with libbpf or BCC that maps kernel events into the same normalized event schema.
