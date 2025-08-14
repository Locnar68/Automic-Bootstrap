import importlib.util
from pathlib import Path


def test_preflight_script_exists():
    assert (Path.cwd() / "preflight.py").exists()


def test_preflight_entry_importable():
    p = Path.cwd() / "automic_bootstrap" / "tools" / "preflight_entry.py"
    assert p.exists()
    spec = importlib.util.spec_from_file_location("preflight_entry", str(p))
    assert spec is not None
