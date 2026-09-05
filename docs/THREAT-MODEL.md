# Threat model

## Protected assets

- Operator files and credentials
- Integrity of Voodoo's audit history and baselines
- Authorization boundaries for network activity
- Privacy of local conversation and knowledge

## Principal risks and controls

| Risk | Current control | Residual limitation |
| --- | --- | --- |
| Model initiates unauthorized network work | Tools enforce scope and lease outside the model | A future tool can be unsafe if it bypasses the central policy API |
| Scope escape through DNS | Resolved addresses must fit declared networks when both domain and network are set | DNS can change after authorization; capabilities should connect to verified addresses in a future hardening pass |
| Stale broad authorization | Leases expire within 120 minutes and can be revoked | The operator can still intentionally grant a broad scope |
| VPN silently disconnected | Proton-required scopes fail closed on adapter detection | Adapter presence is not cryptographic proof of egress; v0.2 reports this honestly |
| Baseline tampering | Manifest is HMAC authenticated | A local administrator who steals the key can forge a manifest |
| Secrets leaked in findings | Scanner output is redacted | Source files still contain the secret until the operator rotates/removes it |
| Destructive false positive | v0.2 never quarantines or changes host settings | Operator remediation is manual |
| Ledger database edited | SHA-256 chain detects record mutation or deletion within the chain | Truncation of only the newest suffix needs an external checkpoint to prove |
| Sentinel false positive | Alert-only log watching; containment requires inline proxy mode; private ranges protected by default | A signature can still misclassify unusual legitimate HTTP paths |
| Forged client address | Direct socket peer is authoritative; untrusted forwarded headers are ignored | Deployment behind another proxy sees that proxy as the peer until trusted-proxy support is configured in a future version |
| Shield bypass | Documentation requires the upstream to bind privately | Incorrect deployment can leave the upstream publicly reachable |
| Resource exhaustion | Request bodies and rates are bounded per source | v0.2 needs global connection ceilings and streaming response limits |

## Non-goals for v0.2

- Antivirus replacement
- Kernel/driver telemetry
- Automatic malware removal
- Firewall or registry mutation
- Persistent IP firewall bans
- Exploit execution
- VPN connection management
