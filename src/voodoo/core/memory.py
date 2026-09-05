from __future__ import annotations

from dataclasses import dataclass

from voodoo.core.ledger import EventLedger


@dataclass(frozen=True)
class Memory:
    role: str
    content: str


class ConversationMemory:
    def __init__(self, ledger: EventLedger):
        self.ledger = ledger

    def add(self, role: str, content: str) -> None:
        if role not in {"user", "assistant"}:
            raise ValueError("role must be user or assistant")
        self.ledger.append("conversation.message", {"role": role, "content": content})

    def recent(self, limit: int = 12) -> list[Memory]:
        values = [
            Memory(e.payload["role"], e.payload["content"])
            for e in self.ledger.events("conversation.message")
        ]
        return values[-limit:]
