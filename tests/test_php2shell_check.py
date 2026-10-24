"""Version logic and the no-execution rule of tools/php2shell-check.sh."""
import re
import shutil
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "tools" / "php2shell-check.sh"
pytestmark = pytest.mark.skipif(shutil.which("bash") is None, reason="bash needed")


def state(version):
    text = SCRIPT.read_text()
    funcs = text[text.index("upstream_of()"):text.index("have() {")]
    out = subprocess.run(["bash", "-c", funcs + '\nfixed_state "$1"', "x", version],
                         capture_output=True, text=True, check=True)
    return out.stdout.strip()


@pytest.mark.parametrize("version,expected", [
    ("8.3.36", "fixed"), ("8.3.35", "vulnerable"), ("8.2.35", "fixed"), ("8.2.34", "vulnerable"),
    ("8.4.27", "fixed"), ("8.5.12", "fixed"), ("8.5.11", "vulnerable"), ("7.4.33", "vulnerable"),
    ("8.6.0", "fixed"), ("8.6.1", "fixed"), ("9.0.0", "fixed"),
    ("1:8.3.36-1~deb12u1", "fixed"), ("8.3.35-1~deb12u1", "vulnerable"),
])
def test_final_releases(version, expected):
    assert state(version) == expected


@pytest.mark.parametrize("version", ["8.6.0-dev", "8.6.0RC1", "8.6.0alpha1", "8.6.0beta2", "9.0.0-dev",
                                     "8.3.36RC1", "8.5.12-dev", "8.4.0~rc1-1"])
def test_pre_release_is_never_fixed(version):
    st = state(version)
    assert st in ("unknown", "vulnerable") and st != "fixed"


def test_pre_release_of_a_known_line_below_the_fixed_patch_is_vulnerable():
    assert state("8.3.35RC1") == "vulnerable"


def test_pre_release_gives_warn_not_pass():
    text = SCRIPT.read_text()
    assert re.search(r'elif \[ "\$st" = unknown \]; then\s+emit WARN package', text)
    assert re.search(r'elif \[ "\$st" = unknown \]; then emit WARN runtime', text)


def test_script_never_executes_discovered_binaries():
    code = "\n".join(l for l in SCRIPT.read_text().splitlines() if not l.lstrip().startswith("#"))
    assert not re.search(r'timeout \d+ "\$(b|1|CLI)"', code)
    assert '"$p/exe" -v' not in code and "bin_version()" in code
    assert "$b -i" not in code
