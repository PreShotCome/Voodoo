# Voodoo architecture

Voodoo uses a narrow trusted core surrounded by adapters.

```text
Operator -> CLI -> Voodoo runtime
                    |-- defensive sensors (read-only)
                    |-- Sentinel -> correlate -> alert/block/divert -> HTTP shield
                    |-- policy -> scope + lease + optional Proton guard -> recon
                    |-- memory + audit -> hash-chained SQLite ledger
                    |-- knowledge -> local SQLite FTS5
                    `-- qualitative state -> Ollama adapter
```

## Design invariants

1. Defensive observation does not require a network capability lease.
2. Active network work cannot run without centralized policy authorization.
3. Scope and lease are separate records; authorization needs both.
4. A scope may additionally require a detectable Proton VPN connection.
5. VPN integration never receives credentials and never changes VPN state.
6. The model does not choose whether policy passes and cannot edit the ledger.
7. The model receives qualitative behavioral guidance, never raw affect values.
8. Tool results are ledger events; the assistant must not invent missing results.
9. Host-changing remediation is absent from v0.2.
10. Sentinel containment happens in the foreground inline shield; it does not
    leave persistent firewall rules behind after Voodoo exits.

## Data root

Runtime data defaults to `~/VoodooData` and stays outside the source tree:

- `state/events.sqlite3`: conversation, audit, scopes, leases, and decisions
- `state/integrity.json`: authenticated integrity manifest
- `state/integrity.key`: local HMAC key
- `knowledge/knowledge.sqlite3`: FTS5 reference corpus
- `workspace/`: reserved operator-controlled working directory
- `reports/`: reserved generated reports

Set `VOODOO_DATA` or pass `--data-root` to use another location.

## Why leases instead of a kill switch

A Boolean switch answers only “on or off.” Voodoo's leases answer who/what/where/
why/until: a specific capability, a specific engagement, a reason, and an
expiry. Restarting Voodoo does not extend a lease. Revocation is an append-only
event, preserving the audit trail.

## Extension seam

New defensive sensors should be read-only and return structured findings. New
network capabilities must call `PolicyEngine.authorize` before resolving or
connecting to a target. Remediation features should use a separate approval
contract with previews, rollback data, and post-change verification.

## Sentinel data path

Sentinel has four deliberately separate stages: detectors turn untrusted text or
HTTP metadata into structured signals; the correlator counts matching signals
inside a time window; the guard suppresses containment for protected address
ranges; and the responder either forwards, blocks, or serves a decoy response.
The detector never receives permission to execute commands.

The HTTP shield is an application-layer reverse proxy, not a network-wide IDS.
It protects only traffic actually routed through it. Logs from other services
can be observed with `sentinel watch`, but watch mode records decisions rather
than altering the host firewall.
