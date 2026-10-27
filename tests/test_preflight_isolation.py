"""Customer events and SIEM results must have no path to the model or to Tavily, not even an indirect import."""
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODEL_SIDE = ("shakedown.llm", "shakedown.pipeline", "shakedown.research", "shakedown.loop", "shakedown.spec", "shakedown.live", "shakedown.server")


def loaded_after(import_line: str) -> list[str]:
    code = f"import sys; sys.path.insert(0, {str(ROOT)!r}); {import_line}; print(','.join(m for m in sys.modules if m.startswith('shakedown.')))"
    out = subprocess.run([sys.executable, "-I", "-c", code], cwd=ROOT, capture_output=True, text=True)
    assert out.returncode == 0, out.stderr
    return out.stdout.strip().split(",")


def test_the_assessment_stack_never_loads_the_model_client_or_research_code():
    modules = loaded_after("import shakedown.assess, shakedown.byo, shakedown.splunk")
    assert "shakedown.assess" in modules and "shakedown.splunk" in modules  # the stack really loaded
    assert not [m for m in MODEL_SIDE if m in modules], [m for m in MODEL_SIDE if m in modules]


def test_running_the_assessment_main_with_a_mock_does_not_load_them_either():
    modules = loaded_after("import shakedown.assess as a; import shakedown.runners")
    assert not [m for m in MODEL_SIDE if m in modules]
