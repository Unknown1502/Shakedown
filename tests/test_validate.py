"""Rule validator: YAML parse first (sigma-cli crashes on malformed YAML), then the real `sigma check`."""
from pathlib import Path

import pytest

from shakedown.validate import validate_rule

ROOT = Path(__file__).resolve().parents[1]
REF = ROOT / "data/raw/sigma/rules/windows/process_creation/proc_creation_win_amsi_registry_tampering.yml"

GOOD = """\
title: Shakedown Test Rule
id: 6f0c1c3e-8f4a-4a57-9d5e-2a3b4c5d6e7f
status: experimental
description: Detects a test image name.
author: shakedown
date: 2026-10-27
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\\\x.exe'
    condition: selection
level: medium
"""


def test_valid_rule_passes():
    result = validate_rule(GOOD)
    assert result.ok, result.errors


@pytest.mark.skipif(not REF.exists(), reason="SigmaHQ data not downloaded")
def test_real_sigmahq_rule_passes():
    assert validate_rule(REF.read_text(encoding="utf-8")).ok


def test_malformed_yaml_is_an_error_not_a_crash():
    result = validate_rule('title: x\ndetection:\n  selection:\n    Image: "\\x.exe"\n')
    assert not result.ok
    assert any("yaml" in e.lower() for e in result.errors)


def test_undefined_condition_reference_fails():
    result = validate_rule(GOOD.replace("condition: selection", "condition: selection and missing_sel"))
    assert not result.ok


def test_unknown_modifier_fails():
    result = validate_rule(GOOD.replace("Image|endswith", "Image|containz"))
    assert not result.ok


@pytest.mark.parametrize("missing", ["title", "id"])
def test_missing_required_field_fails_before_sigma_check(missing):
    text = "\n".join(l for l in GOOD.splitlines() if not l.startswith(missing + ":"))
    result = validate_rule(text)
    assert not result.ok
    assert any(missing in e for e in result.errors)


def test_missing_block_fields_fail():
    no_detection = GOOD.split("detection:")[0] + "level: medium\n"
    result = validate_rule(no_detection)
    assert not result.ok
    assert any("detection" in e for e in result.errors)


def test_non_mapping_document_fails():
    assert not validate_rule("- just\n- a list\n").ok
