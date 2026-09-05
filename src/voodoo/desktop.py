from __future__ import annotations

import os
import queue
import subprocess
import sys
import threading
from datetime import datetime
from pathlib import Path
from tkinter import (
    BOTH,
    END,
    LEFT,
    RIGHT,
    BooleanVar,
    StringVar,
    Tk,
    X,
    filedialog,
    messagebox,
    scrolledtext,
    ttk,
)
from typing import Callable

from voodoo.config import Settings


class CommandRunner:
    """Runs the existing CLI without a shell and streams output to the UI."""

    def __init__(self, data_root: Path, emit: Callable[[str], None]):
        self.data_root = data_root
        self.emit = emit
        self.processes: dict[str, subprocess.Popen[str]] = {}
        self._lock = threading.Lock()

    def command(self, *arguments: str) -> list[str]:
        return [
            sys.executable,
            "-u",
            "-m",
            "voodoo",
            "--data-root",
            str(self.data_root),
            *arguments,
        ]

    def run(self, name: str, arguments: list[str], persistent: bool = False) -> bool:
        with self._lock:
            current = self.processes.get(name)
            if current and current.poll() is None:
                self.emit(f"[{name}] already running")
                return False
        self.emit(f"[{name}] starting: voodoo {' '.join(arguments)}")
        thread = threading.Thread(
            target=self._worker,
            args=(name, arguments, persistent),
            daemon=True,
        )
        thread.start()
        return True

    def _worker(self, name: str, arguments: list[str], persistent: bool) -> None:
        flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
        try:
            process = subprocess.Popen(
                self.command(*arguments),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1,
                creationflags=flags,
            )
        except OSError as exc:
            self.emit(f"[{name}] could not start: {exc}")
            return
        with self._lock:
            self.processes[name] = process
        if process.stdout:
            for line in process.stdout:
                self.emit(f"[{name}] {line.rstrip()}")
        code = process.wait()
        with self._lock:
            self.processes.pop(name, None)
        state = (
            "stopped"
            if persistent and code in {0, -15, 1}
            else f"finished with code {code}"
        )
        self.emit(f"[{name}] {state}")

    def stop(self, name: str) -> bool:
        with self._lock:
            process = self.processes.get(name)
        if process is None or process.poll() is not None:
            self.emit(f"[{name}] is not running")
            return False
        self.emit(f"[{name}] stopping")
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.emit(f"[{name}] did not stop cleanly; forcing shutdown")
            process.kill()
        return True

    def stop_all(self) -> None:
        with self._lock:
            names = list(self.processes)
        for name in names:
            self.stop(name)


class VoodooDesktop:
    def __init__(self, root: Tk, data_root: Path | None = None):
        self.root = root
        self.settings = Settings.load(data_root)
        self.settings.initialize()
        self.messages: queue.Queue[str] = queue.Queue()
        self.runner = CommandRunner(self.settings.data_root, self.messages.put)
        self.status_text = StringVar(value="Ready")
        self.vpn_text = StringVar(value="Proton: checking")
        self._configure_window()
        self._build()
        self.root.after(100, self._drain_messages)
        self.root.after(250, lambda: self.run("vpn-status", ["vpn"]))
        self.root.protocol("WM_DELETE_WINDOW", self.close)

    def _configure_window(self) -> None:
        self.root.title("Voodoo Defense Console")
        self.root.geometry("1180x780")
        self.root.minsize(980, 680)
        style = ttk.Style(self.root)
        if "vista" in style.theme_names():
            style.theme_use("vista")
        style.configure("Title.TLabel", font=("Segoe UI", 18, "bold"))
        style.configure("Section.TLabel", font=("Segoe UI", 11, "bold"))
        style.configure("Danger.TButton", foreground="#8b0000")

    def _build(self) -> None:
        header = ttk.Frame(self.root, padding=(16, 12))
        header.pack(fill=X)
        ttk.Label(header, text="VOODOO", style="Title.TLabel").pack(side=LEFT)
        ttk.Label(header, text="Defensive security control center").pack(
            side=LEFT, padx=14
        )
        ttk.Label(header, textvariable=self.vpn_text).pack(side=RIGHT)

        pane = ttk.Panedwindow(self.root, orient="vertical")
        pane.pack(fill=BOTH, expand=True, padx=12, pady=(0, 12))
        notebook = ttk.Notebook(pane)
        pane.add(notebook, weight=4)

        self._dashboard(notebook)
        self._defense(notebook)
        self._sentinel(notebook)
        self._recon(notebook)
        self._access(notebook)
        self._knowledge(notebook)
        self._chat(notebook)

        activity = ttk.Frame(pane, padding=(4, 8))
        pane.add(activity, weight=2)
        bar = ttk.Frame(activity)
        bar.pack(fill=X)
        ttk.Label(bar, text="Live activity", style="Section.TLabel").pack(side=LEFT)
        ttk.Button(bar, text="Export", command=self._export_activity).pack(side=RIGHT)
        ttk.Button(bar, text="Clear", command=self._clear_activity).pack(
            side=RIGHT, padx=6
        )
        self.console = scrolledtext.ScrolledText(
            activity,
            height=12,
            state="disabled",
            font=("Consolas", 9),
            bg="#111318",
            fg="#d7e0ea",
            insertbackground="#ffffff",
        )
        self.console.pack(fill=BOTH, expand=True, pady=(6, 0))
        ttk.Label(self.root, textvariable=self.status_text, anchor="w").pack(
            fill=X, padx=16, pady=(0, 6)
        )

    def _tab(self, notebook: ttk.Notebook, title: str) -> ttk.Frame:
        frame = ttk.Frame(notebook, padding=14)
        notebook.add(frame, text=title)
        return frame

    def _section(self, parent: ttk.Frame, title: str) -> ttk.LabelFrame:
        frame = ttk.LabelFrame(parent, text=title, padding=10)
        frame.pack(fill=X, pady=(0, 10))
        return frame

    def _entry(
        self, parent: ttk.Frame, label: str, value: str = "", width: int = 48
    ) -> StringVar:
        row = ttk.Frame(parent)
        row.pack(fill=X, pady=3)
        ttk.Label(row, text=label, width=22).pack(side=LEFT)
        variable = StringVar(value=value)
        ttk.Entry(row, textvariable=variable, width=width).pack(
            side=LEFT, fill=X, expand=True
        )
        return variable

    def _dashboard(self, notebook: ttk.Notebook) -> None:
        tab = self._tab(notebook, "Dashboard")
        checks = self._section(tab, "System checks")
        for label, name, args in (
            ("Refresh status", "status", ["status"]),
            ("Check Proton VPN", "vpn-status", ["vpn"]),
            ("Run posture audit", "posture", ["defend", "posture"]),
            ("Verify audit ledger", "ledger", ["audit", "verify"]),
        ):
            ttk.Button(
                checks, text=label, command=lambda n=name, a=args: self.run(n, a)
            ).pack(side=LEFT, padx=4, pady=4)
        info = self._section(tab, "Runtime")
        ttk.Label(info, text=f"Data root: {self.settings.data_root}").pack(anchor="w")
        ttk.Label(info, text=f"Model: {self.settings.model}").pack(anchor="w")
        ttk.Label(
            info,
            text="Nothing starts automatically; active services remain visible below.",
        ).pack(anchor="w", pady=(8, 0))

    def _defense(self, notebook: ttk.Notebook) -> None:
        tab = self._tab(notebook, "Defense")
        integrity = self._section(tab, "File integrity")
        self.baseline_path = self._entry(integrity, "Files or folder")
        self._browse_button(integrity, self.baseline_path, directory=True)
        ttk.Button(integrity, text="Create baseline", command=self._baseline).pack(
            side=LEFT, padx=4, pady=5
        )
        ttk.Button(
            integrity,
            text="Check drift",
            command=lambda: self.run("drift", ["defend", "drift"]),
        ).pack(side=LEFT, padx=4)

        secrets = self._section(tab, "Secret exposure")
        self.secrets_path = self._entry(secrets, "Folder")
        self._browse_button(secrets, self.secrets_path, directory=True)
        ttk.Button(secrets, text="Scan for secrets", command=self._secret_scan).pack(
            side=LEFT, padx=4, pady=5
        )

        triage = self._section(tab, "Logs and indicators")
        self.triage_path = self._entry(triage, "Log file")
        self._browse_button(triage, self.triage_path, directory=False)
        ttk.Button(triage, text="Triage log", command=self._triage).pack(
            side=LEFT, padx=4, pady=5
        )
        self.hunt_path = self._entry(triage, "IOC search folder")
        self.hunt_hash = self._entry(triage, "SHA-256 (optional)")
        self.hunt_name = self._entry(triage, "Filename (optional)")
        ttk.Button(triage, text="Hunt indicators", command=self._hunt).pack(
            side=LEFT, padx=4, pady=5
        )

    def _sentinel(self, notebook: ttk.Notebook) -> None:
        tab = self._tab(notebook, "Sentinel")
        watcher = self._section(tab, "Incoming log monitor")
        self.watch_log = self._entry(watcher, "Log file")
        self._browse_button(watcher, self.watch_log, directory=False)
        self.watch_mode = self._choice(
            watcher, "Mode", ("alert", "block", "divert"), "alert"
        )
        self.watch_threshold = self._entry(watcher, "Threshold", "6")
        self.watch_window = self._entry(watcher, "Window seconds", "60")
        self.watch_private = BooleanVar(value=False)
        ttk.Checkbutton(
            watcher,
            text="Allow private-address containment",
            variable=self.watch_private,
        ).pack(anchor="w", pady=4)
        ttk.Button(watcher, text="Start watcher", command=self._start_watcher).pack(
            side=LEFT, padx=4
        )
        ttk.Button(
            watcher,
            text="Stop watcher",
            command=lambda: self.runner.stop("sentinel-watch"),
        ).pack(side=LEFT, padx=4)

        proxy = self._section(tab, "Inline HTTP shield")
        self.proxy_upstream = self._entry(
            proxy, "Protected service", "http://127.0.0.1:3000"
        )
        self.proxy_listen = self._entry(proxy, "Listen address", "127.0.0.1")
        self.proxy_port = self._entry(proxy, "Listen port", "8080")
        self.proxy_mode = self._choice(
            proxy, "Attack response", ("block", "divert"), "block"
        )
        self.proxy_threshold = self._entry(proxy, "Correlation threshold", "6")
        self.proxy_rate = self._entry(proxy, "Requests/minute", "120")
        self.proxy_private = BooleanVar(value=False)
        ttk.Checkbutton(
            proxy, text="Allow private-address containment", variable=self.proxy_private
        ).pack(anchor="w", pady=4)
        ttk.Button(proxy, text="Start shield", command=self._start_proxy).pack(
            side=LEFT, padx=4
        )
        ttk.Button(
            proxy,
            text="Stop shield",
            command=lambda: self.runner.stop("sentinel-proxy"),
        ).pack(side=LEFT, padx=4)

    def _recon(self, notebook: ttk.Notebook) -> None:
        tab = self._tab(notebook, "Recon")
        scan = self._section(tab, "Authorized port scan")
        self.scan_scope = self._entry(scan, "Scope")
        self.scan_host = self._entry(scan, "Host")
        self.scan_ports = self._entry(scan, "Ports", "22,80,443")
        ttk.Button(scan, text="Scan", command=self._scan).pack(
            side=LEFT, padx=4, pady=5
        )
        web = self._section(tab, "Web and TLS")
        self.web_scope = self._entry(web, "Scope")
        self.web_url = self._entry(web, "URL", "https://")
        ttk.Button(web, text="Inspect headers", command=self._headers).pack(
            side=LEFT, padx=4, pady=5
        )
        self.cert_host = self._entry(web, "TLS host")
        self.cert_port = self._entry(web, "TLS port", "443")
        ttk.Button(web, text="Inspect certificate", command=self._certificate).pack(
            side=LEFT, padx=4, pady=5
        )

    def _access(self, notebook: ttk.Notebook) -> None:
        tab = self._tab(notebook, "Scopes & Leases")
        scope = self._section(tab, "Engagement scope")
        self.scope_name = self._entry(scope, "Name")
        self.scope_domain = self._entry(scope, "Domain (optional)")
        self.scope_network = self._entry(scope, "Network (optional)")
        self.scope_proton = BooleanVar(value=False)
        ttk.Checkbutton(
            scope, text="Require Proton VPN", variable=self.scope_proton
        ).pack(anchor="w", pady=4)
        ttk.Button(scope, text="Create scope", command=self._create_scope).pack(
            side=LEFT, padx=4
        )
        ttk.Button(
            scope,
            text="List scopes",
            command=lambda: self.run("scope-list", ["scope", "list"]),
        ).pack(side=LEFT, padx=4)

        lease = self._section(tab, "Capability lease")
        self.lease_scope = self._entry(lease, "Scope")
        self.lease_capability = self._choice(
            lease, "Capability", ("recon.scan", "recon.http", "recon.tls"), "recon.http"
        )
        self.lease_minutes = self._entry(lease, "Minutes", "15")
        self.lease_reason = self._entry(lease, "Authorization reason")
        ttk.Button(lease, text="Grant lease", command=self._grant_lease).pack(
            side=LEFT, padx=4
        )
        ttk.Button(
            lease,
            text="List leases",
            command=lambda: self.run("lease-list", ["lease", "list"]),
        ).pack(side=LEFT, padx=4)
        self.revoke_id = self._entry(lease, "Lease ID to revoke")
        self.revoke_reason = self._entry(
            lease, "Revocation reason", "Operator requested revocation"
        )
        ttk.Button(lease, text="Revoke lease", command=self._revoke_lease).pack(
            side=LEFT, padx=4
        )

    def _knowledge(self, notebook: ttk.Notebook) -> None:
        tab = self._tab(notebook, "Knowledge")
        add = self._section(tab, "Add local reference")
        self.knowledge_title = self._entry(add, "Title")
        self.knowledge_file = self._entry(add, "Text file")
        self._browse_button(add, self.knowledge_file, directory=False)
        self.knowledge_source = self._entry(add, "Source", "operator")
        ttk.Button(add, text="Add knowledge", command=self._add_knowledge).pack(
            side=LEFT, padx=4
        )
        search = self._section(tab, "Search")
        self.knowledge_query = self._entry(search, "Query")
        ttk.Button(
            search, text="Search knowledge", command=self._search_knowledge
        ).pack(side=LEFT, padx=4)

    def _chat(self, notebook: ttk.Notebook) -> None:
        tab = self._tab(notebook, "Chat")
        frame = self._section(tab, "Talk to Voodoo")
        self.chat_prompt = self._entry(frame, "Message", width=70)
        ttk.Button(frame, text="Send", command=self._send_chat).pack(
            side=LEFT, padx=4, pady=5
        )
        ttk.Label(frame, text="Requires Ollama. Replies appear in Live activity.").pack(
            side=LEFT, padx=8
        )

    def _choice(
        self, parent: ttk.Frame, label: str, values: tuple[str, ...], selected: str
    ) -> StringVar:
        row = ttk.Frame(parent)
        row.pack(fill=X, pady=3)
        ttk.Label(row, text=label, width=22).pack(side=LEFT)
        variable = StringVar(value=selected)
        ttk.Combobox(
            row, textvariable=variable, values=values, state="readonly", width=24
        ).pack(side=LEFT)
        return variable

    def _browse_button(
        self, parent: ttk.Frame, variable: StringVar, directory: bool
    ) -> None:
        def browse() -> None:
            value = (
                filedialog.askdirectory() if directory else filedialog.askopenfilename()
            )
            if value:
                variable.set(value)

        ttk.Button(parent, text="Browse", command=browse).pack(side=RIGHT, padx=4)

    def run(self, name: str, args: list[str], persistent: bool = False) -> None:
        self.status_text.set(f"Starting {name}")
        self.runner.run(name, args, persistent)

    def _required(self, *pairs: tuple[str, StringVar]) -> list[str] | None:
        values: list[str] = []
        for label, variable in pairs:
            value = variable.get().strip()
            if not value:
                messagebox.showwarning("Missing value", f"{label} is required.")
                return None
            values.append(value)
        return values

    def _baseline(self) -> None:
        values = self._required(("Path", self.baseline_path))
        if values and messagebox.askyesno(
            "Create baseline", "Replace the current integrity baseline?"
        ):
            self.run("baseline", ["defend", "baseline", values[0]])

    def _secret_scan(self) -> None:
        values = self._required(("Folder", self.secrets_path))
        if values:
            self.run("secrets", ["defend", "secrets", values[0]])

    def _triage(self) -> None:
        values = self._required(("Log file", self.triage_path))
        if values:
            self.run("triage", ["defend", "triage", values[0]])

    def _hunt(self) -> None:
        values = self._required(("Search path", self.hunt_path))
        if not values:
            return
        args = ["defend", "hunt", values[0]]
        if self.hunt_hash.get().strip():
            args += ["--sha256", self.hunt_hash.get().strip()]
        if self.hunt_name.get().strip():
            args += ["--name", self.hunt_name.get().strip()]
        self.run("ioc-hunt", args)

    def _start_watcher(self) -> None:
        values = self._required(("Log file", self.watch_log))
        if not values:
            return
        args = [
            "sentinel",
            "watch",
            values[0],
            "--mode",
            self.watch_mode.get(),
            "--threshold",
            self.watch_threshold.get(),
            "--window",
            self.watch_window.get(),
        ]
        if self.watch_private.get():
            args.append("--allow-private-containment")
        self.run("sentinel-watch", args, True)

    def _start_proxy(self) -> None:
        values = self._required(
            ("Protected service", self.proxy_upstream),
            ("Listen address", self.proxy_listen),
            ("Port", self.proxy_port),
        )
        if not values:
            return
        if self.proxy_listen.get() == "0.0.0.0" and not messagebox.askyesno(
            "Expose shield", "Listen on every network interface?"
        ):
            return
        args = [
            "sentinel",
            "proxy",
            "--upstream",
            values[0],
            "--listen",
            values[1],
            "--port",
            values[2],
            "--mode",
            self.proxy_mode.get(),
            "--threshold",
            self.proxy_threshold.get(),
            "--rate-limit",
            self.proxy_rate.get(),
        ]
        if self.proxy_private.get():
            args.append("--allow-private-containment")
        self.run("sentinel-proxy", args, True)

    def _scan(self) -> None:
        values = self._required(
            ("Scope", self.scan_scope),
            ("Host", self.scan_host),
            ("Ports", self.scan_ports),
        )
        if values:
            self.run("scan", ["scan", values[0], values[1], "--ports", values[2]])

    def _headers(self) -> None:
        values = self._required(("Scope", self.web_scope), ("URL", self.web_url))
        if values:
            self.run("headers", ["headers", values[0], values[1]])

    def _certificate(self) -> None:
        values = self._required(
            ("Scope", self.web_scope),
            ("Host", self.cert_host),
            ("Port", self.cert_port),
        )
        if values:
            self.run("certificate", ["cert", values[0], values[1], "--port", values[2]])

    def _create_scope(self) -> None:
        values = self._required(("Scope name", self.scope_name))
        if not values:
            return
        args = ["scope", "create", values[0]]
        if self.scope_domain.get().strip():
            args += ["--domain", self.scope_domain.get().strip()]
        if self.scope_network.get().strip():
            args += ["--network", self.scope_network.get().strip()]
        if self.scope_proton.get():
            args.append("--require-proton")
        self.run("scope-create", args)

    def _grant_lease(self) -> None:
        values = self._required(
            ("Scope", self.lease_scope), ("Reason", self.lease_reason)
        )
        if values:
            self.run(
                "lease-grant",
                [
                    "lease",
                    "grant",
                    values[0],
                    self.lease_capability.get(),
                    "--minutes",
                    self.lease_minutes.get(),
                    "--reason",
                    values[1],
                ],
            )

    def _revoke_lease(self) -> None:
        values = self._required(
            ("Lease ID", self.revoke_id), ("Reason", self.revoke_reason)
        )
        if values:
            self.run(
                "lease-revoke", ["lease", "revoke", values[0], "--reason", values[1]]
            )

    def _add_knowledge(self) -> None:
        values = self._required(
            ("Title", self.knowledge_title), ("File", self.knowledge_file)
        )
        if values:
            self.run(
                "knowledge-add",
                [
                    "knowledge",
                    "add",
                    values[0],
                    values[1],
                    "--source",
                    self.knowledge_source.get().strip() or "operator",
                ],
            )

    def _search_knowledge(self) -> None:
        values = self._required(("Query", self.knowledge_query))
        if values:
            self.run("knowledge-search", ["knowledge", "search", values[0]])

    def _send_chat(self) -> None:
        values = self._required(("Message", self.chat_prompt))
        if values:
            self.run("chat", ["chat", values[0]])
            self.chat_prompt.set("")

    def _drain_messages(self) -> None:
        while True:
            try:
                message = self.messages.get_nowait()
            except queue.Empty:
                break
            stamp = datetime.now().strftime("%H:%M:%S")
            self.console.configure(state="normal")
            self.console.insert(END, f"{stamp} {message}\n")
            self.console.see(END)
            self.console.configure(state="disabled")
            self.status_text.set(message)
            if message.startswith("[vpn-status]") and "connected" in message.lower():
                self.vpn_text.set("Proton: see activity")
        self.root.after(100, self._drain_messages)

    def _clear_activity(self) -> None:
        self.console.configure(state="normal")
        self.console.delete("1.0", END)
        self.console.configure(state="disabled")

    def _export_activity(self) -> None:
        path = filedialog.asksaveasfilename(
            defaultextension=".log",
            filetypes=(("Log file", "*.log"), ("Text file", "*.txt")),
        )
        if path:
            Path(path).write_text(self.console.get("1.0", END), encoding="utf-8")

    def close(self) -> None:
        if self.runner.processes and not messagebox.askyesno(
            "Stop Voodoo", "Stop active Voodoo services and close?"
        ):
            return
        self.runner.stop_all()
        self.root.destroy()


def main() -> int:
    root = Tk()
    VoodooDesktop(root)
    root.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
