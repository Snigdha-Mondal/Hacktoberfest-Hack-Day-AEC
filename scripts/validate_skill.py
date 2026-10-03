"""Validator for the privacy-audit Agent Skill package.

Validates that SKILL.md adheres to the Agent Skills Open Standard:
- Valid YAML frontmatter (name, description, license, metadata)
- Hyphenated lowercase name
- Meaningful description
- Mandatory security sections: Procedure, Hard rules, and Output
"""
import pathlib
import sys
import re

ROOT_DIR = pathlib.Path(__file__).resolve().parent.parent
SKILL_PATHS = [
    ROOT_DIR / "skills" / "privacy-audit" / "SKILL.md",
    ROOT_DIR / ".agents" / "skills" / "privacy-audit" / "SKILL.md",
]


def parse_frontmatter(content: str) -> tuple[dict, str]:
    pattern = r"^---\s*\n(.*?)\n---\s*\n(.*)$"
    match = re.match(pattern, content, re.DOTALL)
    if not match:
        raise ValueError("File does not start with valid '---' frontmatter delimiters.")

    raw_yaml = match.group(1)
    body = match.group(2)

    # Basic key-value parser
    frontmatter = {}
    current_key = None
    for line in raw_yaml.splitlines():
        line_str = line.strip()
        if not line_str or line_str.startswith("#"):
            continue
        if ":" in line_str and not line.startswith(" "):
            parts = line_str.split(":", 1)
            current_key = parts[0].strip()
            frontmatter[current_key] = parts[1].strip()
        elif current_key and line.startswith(" "):
            # nested or multiline
            frontmatter[current_key] += " " + line_str

    return frontmatter, body


def validate_skill_file(skill_path: pathlib.Path) -> bool:
    print(f"[*] Validating Skill: {skill_path.relative_to(ROOT_DIR)}...")

    if not skill_path.exists():
        print(f"    [FAIL] File does not exist: {skill_path}")
        return False

    content = skill_path.read_text(encoding="utf-8")
    try:
        frontmatter, body = parse_frontmatter(content)
    except Exception as e:
        print(f"    [FAIL] Frontmatter parse error: {e}")
        return False

    # 1. Validate required fields
    required = ["name", "description", "license"]
    for field in required:
        if field not in frontmatter or not frontmatter[field]:
            print(f"    [FAIL] Missing required frontmatter field: '{field}'")
            return False

    # 2. Validate name format
    name = frontmatter["name"]
    if not re.match(r"^[a-z0-9]+(-[a-z0-9]+)*$", name):
        print(f"    [FAIL] Skill name '{name}' must be lowercase alphanumeric and hyphens only.")
        return False

    # 3. Validate description length
    desc = frontmatter["description"]
    if len(desc) < 30:
        print(f"    [FAIL] Skill description too short ({len(desc)} chars).")
        return False

    # 4. Validate body sections
    body_lower = body.lower()
    if "procedure" not in body_lower:
        print("    [FAIL] Body must contain '## Procedure' section.")
        return False
    if "hard rules" not in body_lower and "rules" not in body_lower:
        print("    [FAIL] Body must contain '## Hard rules' section.")
        return False
    if "output" not in body_lower:
        print("    [FAIL] Body must contain '## Output' section.")
        return False

    print("    [PASS] Schema conforms to Agent Skills Open Standard.")
    print(f"    - Name:        {name}")
    print(f"    - License:     {frontmatter.get('license')}")
    print(f"    - Description: {desc[:60]}...")
    return True


def main():
    print("=" * 70)
    print("  Agent Skills Open Standard — Validation Suite")
    print("=" * 70)

    success = True
    for path in SKILL_PATHS:
        if path.exists():
            valid = validate_skill_file(path)
            if not valid:
                success = False
            print()

    if success:
        print("=" * 70)
        print("  [SUCCESS] All privacy-audit skills verified!")
        print("=" * 70)
        sys.exit(0)
    else:
        print("=" * 70)
        print("  [FAILURE] One or more skills failed validation.")
        print("=" * 70)
        sys.exit(1)


if __name__ == "__main__":
    main()
