from __future__ import annotations

import json
import time
from pathlib import Path

from voodoo.sentinel.correlator import Correlator
from voodoo.sentinel.detector import Detector
from voodoo.sentinel.guard import SentinelGuard


class LogWatcher:
    def __init__(
        self, detector: Detector, correlator: Correlator, guard: SentinelGuard
    ):
        self.detector = detector
        self.correlator = correlator
        self.guard = guard

    def follow(
        self,
        path: Path,
        mode: str = "alert",
        from_start: bool = False,
        poll_seconds: float = 0.5,
    ) -> None:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            if not from_start:
                handle.seek(0, 2)
            while True:
                line = handle.readline()
                if not line:
                    time.sleep(poll_seconds)
                    continue
                for signal in self.detector.inspect_line(line):
                    decision = self.guard.enforce(
                        signal, self.correlator.evaluate(signal, mode)
                    )
                    print(
                        json.dumps(
                            {
                                "signal": signal.rule,
                                "decision": decision.action,
                                "source": decision.source_ip,
                                "reason": decision.reason,
                            }
                        )
                    )
