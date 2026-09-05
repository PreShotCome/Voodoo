from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path

from voodoo.security import EngagementScope, PolicyDenied
from voodoo.sentinel import Correlator, Detector, LogWatcher, SentinelGuard, ShieldProxy
from voodoo.system import Voodoo


def _ports(value: str) -> list[int]:
    result: set[int] = set()
    for part in value.split(","):
        part = part.strip()
        if "-" in part:
            start, end = (int(x) for x in part.split("-", 1))
            result.update(range(start, end + 1))
        else:
            result.add(int(part))
    return sorted(result)


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(
        prog="voodoo", description="Local authorized-security companion"
    )
    root.add_argument("--data-root", type=Path)
    commands = root.add_subparsers(dest="command", required=True)
    commands.add_parser("init")
    commands.add_parser("status")
    commands.add_parser("vpn")

    chat = commands.add_parser("chat")
    chat.add_argument("prompt", nargs="?")

    scope = commands.add_parser("scope")
    scope_commands = scope.add_subparsers(dest="scope_command", required=True)
    scope_commands.add_parser("list")
    create = scope_commands.add_parser("create")
    create.add_argument("name")
    create.add_argument("--domain", action="append", default=[])
    create.add_argument("--network", action="append", default=[])
    create.add_argument("--require-proton", action="store_true")

    lease = commands.add_parser("lease")
    lease_commands = lease.add_subparsers(dest="lease_command", required=True)
    lease_commands.add_parser("list")
    grant = lease_commands.add_parser("grant")
    grant.add_argument("scope")
    grant.add_argument("capability", choices=("recon.scan", "recon.http", "recon.tls"))
    grant.add_argument("--minutes", type=int, default=15)
    grant.add_argument("--reason", required=True)
    revoke = lease_commands.add_parser("revoke")
    revoke.add_argument("lease_id")
    revoke.add_argument("--reason", required=True)

    scan = commands.add_parser("scan")
    scan.add_argument("scope")
    scan.add_argument("host")
    scan.add_argument("--ports", type=_ports, default=_ports("22,80,443"))
    headers = commands.add_parser("headers")
    headers.add_argument("scope")
    headers.add_argument("url")
    cert = commands.add_parser("cert")
    cert.add_argument("scope")
    cert.add_argument("host")
    cert.add_argument("--port", type=int, default=443)

    knowledge = commands.add_parser("knowledge")
    knowledge_commands = knowledge.add_subparsers(
        dest="knowledge_command", required=True
    )
    add = knowledge_commands.add_parser("add")
    add.add_argument("title")
    add.add_argument("file", type=Path)
    add.add_argument("--source", default="operator")
    search = knowledge_commands.add_parser("search")
    search.add_argument("query")

    audit = commands.add_parser("audit")
    audit.add_argument("action", choices=("verify",))

    defend = commands.add_parser("defend")
    defend_commands = defend.add_subparsers(dest="defend_command", required=True)
    defend_commands.add_parser("posture")
    baseline = defend_commands.add_parser("baseline")
    baseline.add_argument("paths", nargs="+", type=Path)
    defend_commands.add_parser("drift")
    secret_scan = defend_commands.add_parser("secrets")
    secret_scan.add_argument("path", type=Path)
    triage = defend_commands.add_parser("triage")
    triage.add_argument("log", type=Path)
    hunt = defend_commands.add_parser("hunt")
    hunt.add_argument("path", type=Path)
    hunt.add_argument("--sha256", action="append", default=[])
    hunt.add_argument("--name", action="append", default=[])

    sentinel = commands.add_parser("sentinel")
    sentinel_commands = sentinel.add_subparsers(dest="sentinel_command", required=True)
    watch = sentinel_commands.add_parser("watch")
    watch.add_argument("log", type=Path)
    watch.add_argument("--mode", choices=("alert", "block", "divert"), default="alert")
    watch.add_argument("--threshold", type=int, default=6)
    watch.add_argument("--window", type=int, default=60)
    watch.add_argument("--from-start", action="store_true")
    watch.add_argument("--allow-private-containment", action="store_true")
    proxy = sentinel_commands.add_parser("proxy")
    proxy.add_argument("--upstream", required=True)
    proxy.add_argument("--listen", default="127.0.0.1")
    proxy.add_argument("--port", type=int, default=8080)
    proxy.add_argument("--mode", choices=("block", "divert"), default="block")
    proxy.add_argument("--threshold", type=int, default=6)
    proxy.add_argument("--window", type=int, default=60)
    proxy.add_argument("--rate-limit", type=int, default=120)
    proxy.add_argument("--allow-private-containment", action="store_true")
    return root


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    app = Voodoo.open(args.data_root)
    try:
        if args.command == "init":
            print(f"Voodoo initialized at {app.settings.data_root}")
        elif args.command == "status":
            status = json.loads(app.policy.describe())
            status["proton_vpn"] = app.vpn.inspect().as_dict()
            print(json.dumps(status, indent=2))
        elif args.command == "vpn":
            print(json.dumps(app.vpn.inspect().as_dict(), indent=2))
        elif args.command == "chat":
            if args.prompt:
                print(app.chat(args.prompt))
            else:
                _repl(app)
        elif args.command == "scope" and args.scope_command == "create":
            item = EngagementScope(
                args.name, tuple(args.domain), tuple(args.network), args.require_proton
            )
            app.policy.save_scope(item)
            print(f"Created scope {item.name}")
        elif args.command == "scope":
            print(
                json.dumps(
                    {name: vars(item) for name, item in app.policy.scopes().items()},
                    indent=2,
                )
            )
        elif args.command == "lease" and args.lease_command == "grant":
            print(
                json.dumps(
                    vars(
                        app.policy.grant(
                            args.scope, args.capability, args.minutes, args.reason
                        )
                    ),
                    indent=2,
                )
            )
        elif args.command == "lease" and args.lease_command == "revoke":
            app.policy.revoke(args.lease_id, args.reason)
            print("Lease revoked")
        elif args.command == "lease":
            print(
                json.dumps(
                    [vars(item) for item in app.policy.active_leases()], indent=2
                )
            )
        elif args.command == "scan":
            results = asyncio.run(app.recon.scan(args.scope, args.host, args.ports))
            print(json.dumps([vars(item) for item in results if item.open], indent=2))
        elif args.command == "headers":
            print(
                json.dumps(
                    asyncio.run(app.recon.headers(args.scope, args.url)), indent=2
                )
            )
        elif args.command == "cert":
            print(
                json.dumps(
                    app.recon.certificate(args.scope, args.host, args.port), indent=2
                )
            )
        elif args.command == "knowledge" and args.knowledge_command == "add":
            app.knowledge.add(
                args.title, args.file.read_text(encoding="utf-8"), args.source
            )
            print("Knowledge added")
        elif args.command == "knowledge":
            print(
                json.dumps(
                    [vars(hit) for hit in app.knowledge.search(args.query)], indent=2
                )
            )
        elif args.command == "audit":
            valid, sequence = app.ledger.verify()
            print("Ledger valid" if valid else f"Ledger invalid at event {sequence}")
            return 0 if valid else 1
        elif args.command == "defend" and args.defend_command == "posture":
            print(json.dumps(app.posture.run(app.settings.data_root), indent=2))
        elif args.command == "defend" and args.defend_command == "baseline":
            count = app.integrity.create(args.paths)
            app.ledger.append(
                "defense.baseline.created",
                {"paths": [str(x.resolve()) for x in args.paths], "files": count},
            )
            print(f"Baselined {count} files")
        elif args.command == "defend" and args.defend_command == "drift":
            drift = app.integrity.check()
            app.ledger.append("defense.drift.checked", {"findings": len(drift)})
            print(json.dumps([vars(item) for item in drift], indent=2))
            return 1 if drift else 0
        elif args.command == "defend" and args.defend_command == "secrets":
            findings = app.secrets.scan(args.path)
            app.ledger.append(
                "defense.secrets.scanned",
                {"path": str(args.path.resolve()), "findings": len(findings)},
            )
            print(json.dumps([vars(item) for item in findings], indent=2))
            return 1 if findings else 0
        elif args.command == "defend" and args.defend_command == "triage":
            report = app.triage.analyze(args.log)
            app.ledger.append(
                "defense.log.triaged",
                {"path": str(args.log.resolve()), "signals": report["signal_count"]},
            )
            print(json.dumps(report, indent=2))
        elif args.command == "defend" and args.defend_command == "hunt":
            matches = app.iocs.hunt(args.path, set(args.sha256), set(args.name))
            app.ledger.append(
                "defense.ioc.hunted",
                {"path": str(args.path.resolve()), "matches": len(matches)},
            )
            print(json.dumps([vars(item) for item in matches], indent=2))
            return 1 if matches else 0
        elif args.command == "sentinel":
            detector = Detector()
            correlator = Correlator(args.threshold, args.window)
            guard = SentinelGuard(app.ledger, args.allow_private_containment)
            if args.sentinel_command == "watch":
                print(f"Sentinel watching {args.log}. Press Ctrl+C to stop.")
                LogWatcher(detector, correlator, guard).follow(
                    args.log, args.mode, args.from_start
                )
            else:
                print(
                    f"Sentinel shield listening on {args.listen}:{args.port} "
                    f"for {args.upstream}. Press Ctrl+C to stop."
                )
                ShieldProxy(
                    args.upstream,
                    detector,
                    correlator,
                    guard,
                    args.mode,
                    rate_limit=args.rate_limit,
                ).serve(args.listen, args.port)
    except (PolicyDenied, ValueError, RuntimeError) as exc:
        print(f"Refused: {exc}")
        return 2
    return 0


def _repl(app: Voodoo) -> None:
    print("Voodoo is listening. Type /quit to leave.")
    while True:
        try:
            prompt = input("you> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return
        if prompt in {"/quit", "/exit"}:
            return
        if prompt:
            print("voodoo> " + app.chat(prompt))
