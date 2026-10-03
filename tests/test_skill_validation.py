"""Tests for Agent Skills Open Standard compliance."""
import pathlib
from scripts.validate_skill import validate_skill_file

ROOT_DIR = pathlib.Path(__file__).resolve().parent.parent


def test_skills_privacy_audit_conforms_to_standard():
    path = ROOT_DIR / "skills" / "privacy-audit" / "SKILL.md"
    assert path.exists()
    assert validate_skill_file(path) is True


def test_agents_skills_privacy_audit_conforms_to_standard():
    path = ROOT_DIR / ".agents" / "skills" / "privacy-audit" / "SKILL.md"
    assert path.exists()
    assert validate_skill_file(path) is True
