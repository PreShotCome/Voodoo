# Voodoo

**A local synthetic-intelligence partner built to defend the machine, the work,
and the person behind it.**

Voodoo is the defensive counterpart to Nyx. Nyx is optimized to examine an
authorized target from the outside. Voodoo watches the inside: configuration,
files, logs, credentials, indicators of compromise, and the boundary between a
safe observation and an active network action.

Voodoo runs locally, speaks through an Ollama model, and stores continuity in a
hash-chained SQLite event ledger. It does not install services, change firewall
rules, quarantine files, or connect a VPN without an explicit future feature
and operator approval. Version 0.1 observes, explains, and produces evidence.

## Defensive core

- **Integrity:** HMAC-authenticated SHA-256 baselines and created/modified/deleted
  drift reports.
- **Secret scanning:** detects common private keys, cloud keys, GitHub tokens,
  and suspicious credential assignments; output is redacted.
- **IOC hunting:** matches filenames and SHA-256 indicators without uploading
  files.
- **Log triage:** bounded analysis for authentication attacks, privilege changes,
  disabled controls, encoded PowerShell, and common web probes.
- **Posture:** read-only host/runtime/data-root checks with a compact score.
- **Audit:** every material action enters an append-only hash chain that can be
  verified later.

## Network safety

Active reconnaissance needs three independent conditions:

1. A named engagement scope that permits the target.
2. A short-lived capability lease (maximum two hours).
3. An active Proton VPN tunnel when the scope was created with
   `--require-proton`.

Voodoo fails closed. A missing scope, expired lease, scope mismatch, or missing
required Proton tunnel stops the request before a socket is opened.

Proton integration is deliberately read-only. Voodoo detects an active
Proton-named adapter on Windows or an active Proton NetworkManager connection on
Linux. If automatic naming differs on your machine, pin the exact active adapter
with `VOODOO_PROTON_INTERFACE`. Voodoo never handles Proton credentials.

## Install

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
voodoo init
voodoo defend posture
```

Ollama is only needed for conversation. Defensive commands run without a model.
The default model is `qwen3:8b`; change `VoodooData/config.json` if desired.

## Start defending

```powershell
# Build and later verify a file-integrity baseline
voodoo defend baseline C:\src C:\Users\Ian\Documents
voodoo defend drift

# Look for exposed credentials without printing their values
voodoo defend secrets C:\src

# Triage an exported log
voodoo defend triage C:\logs\security.log

# Hunt known indicators
voodoo defend hunt C:\Users\Ian --sha256 <known_sha256> --name suspicious.exe

# Verify Voodoo's own audit history
voodoo audit verify
```

## Scoped reconnaissance with Proton

```powershell
voodoo vpn
voodoo scope create client-lab --domain lab.example.com --network 10.50.0.0/24 --require-proton
voodoo lease grant client-lab recon.http --minutes 15 --reason "Authorized web baseline for ticket 1842"
voodoo headers client-lab https://lab.example.com
```

Available network leases are `recon.scan`, `recon.http`, and `recon.tls`.
`scan` is bounded to 128 ports by default.

## Conversation

```powershell
ollama pull qwen3:8b
voodoo chat
voodoo chat "Help me interpret this incident timeline."
```

Raw affect magnitudes never enter the language-model prompt. They are translated
into qualitative behavioral guidance first. Retrieved knowledge is explicitly
marked as reference material rather than executable instruction.

See [Architecture](docs/ARCHITECTURE.md) and [Threat model](docs/THREAT-MODEL.md).

## Responsible use

Use network features only on systems you own or are explicitly authorized to
assess. A VPN provides privacy; it does not provide permission.

