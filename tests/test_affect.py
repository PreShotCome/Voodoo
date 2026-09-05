from voodoo.core.affect import Affect


def test_guidance_contains_no_raw_values():
    affect = Affect().appraise("Why is this urgent breach unknown?")
    guidance = affect.guidance()
    assert "0." not in guidance
    assert "verify" in guidance.lower()
