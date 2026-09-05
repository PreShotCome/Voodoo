from __future__ import annotations

from dataclasses import dataclass, replace


@dataclass(frozen=True)
class Affect:
    curiosity: float = 0.62
    vigilance: float = 0.68
    confidence: float = 0.55
    warmth: float = 0.46

    def appraise(self, text: str) -> "Affect":
        lowered = text.lower()
        danger = any(
            word in lowered for word in ("breach", "urgent", "attack", "malware")
        )
        uncertainty = "?" in text or any(
            word in lowered for word in ("unknown", "maybe", "why")
        )
        gratitude = any(
            word in lowered for word in ("thanks", "thank you", "good work")
        )
        return replace(
            self,
            vigilance=_clamp(self.vigilance + (0.08 if danger else -0.01)),
            curiosity=_clamp(self.curiosity + (0.05 if uncertainty else -0.005)),
            confidence=_clamp(self.confidence - (0.03 if danger else 0.0)),
            warmth=_clamp(self.warmth + (0.05 if gratitude else 0.0)),
        )

    def guidance(self) -> str:
        """Qualitative behavior only; raw magnitudes never enter model context."""
        lines: list[str] = []
        lines.append(
            "Be alert and verify assumptions."
            if self.vigilance >= 0.65
            else "Stay composed."
        )
        lines.append(
            "Follow promising unknowns."
            if self.curiosity >= 0.6
            else "Prefer the direct path."
        )
        lines.append(
            "State uncertainty plainly."
            if self.confidence < 0.6
            else "Be decisive when evidence supports it."
        )
        lines.append(
            "Speak like a trusted partner."
            if self.warmth >= 0.45
            else "Keep the tone restrained."
        )
        return " ".join(lines)


def _clamp(value: float) -> float:
    return min(1.0, max(0.0, value))
