from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    data_root: Path
    model: str = "qwen3:8b"
    ollama_url: str = "http://127.0.0.1:11434"
    max_scan_ports: int = 128
    max_scan_concurrency: int = 32

    @classmethod
    def load(cls, data_root: Path | None = None) -> "Settings":
        root = data_root or Path(os.getenv("VOODOO_DATA", Path.home() / "VoodooData"))
        config_path = root / "config.json"
        if not config_path.exists():
            return cls(data_root=root)
        raw = json.loads(config_path.read_text(encoding="utf-8"))
        return cls(
            data_root=root,
            model=str(raw.get("model", "qwen3:8b")),
            ollama_url=str(raw.get("ollama_url", "http://127.0.0.1:11434")),
            max_scan_ports=int(raw.get("max_scan_ports", 128)),
            max_scan_concurrency=int(raw.get("max_scan_concurrency", 32)),
        )

    def initialize(self) -> None:
        self.data_root.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.data_root, 0o700)
        except OSError:
            pass
        for name in ("state", "knowledge", "workspace", "reports"):
            (self.data_root / name).mkdir(parents=True, exist_ok=True)
        config_path = self.data_root / "config.json"
        if not config_path.exists():
            payload = asdict(self)
            payload.pop("data_root")
            config_path.write_text(
                json.dumps(payload, indent=2) + "\n", encoding="utf-8"
            )
