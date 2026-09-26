# Architecture

Attack Time Machine separates collection, recording, storage, and reconstruction so the security boundary is easy to reason about.

## Components

## Collectors

Collectors observe endpoint activity and emit normalized events. The MVP includes a safe simulator. Linux production collectors should be implemented as adapters that translate eBPF, auditd, fanotify, or process accounting signals into the same event schema.

Collectors should avoid policy decisions. Their job is to preserve facts with enough context for later reconstruction.

## Recorder

The recorder validates event shape, assigns sequence numbers, and writes JSONL records. Each record commits to:

- the normalized event
- the event hash
- the previous record hash
- the sequence number

This creates a linear tamper-evident ledger. Reordering, deletion, insertion, and mutation are detectable by `atm verify`.

## Evidence Store

The MVP writes local JSONL for easy inspection and portability. A production deployment should forward each record to remote immutable storage such as object lock buckets, WORM storage, transparency logs, or a SIEM with append-only controls.

## Reconstruction

The graph builder uses explicit parent event IDs to reconstruct causality. Missing parent IDs are preserved as orphan edges so responders can see where context was lost.

## Security Defaults

- no offensive functionality
- no shell execution in the simulator
- reserved documentation/test network ranges only
- optional HMAC sealing
- deterministic verification failures
- simple JSONL format for independent auditing
