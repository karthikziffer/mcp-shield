from pathlib import Path

import pytest

from mcp_shield import Shield


@pytest.fixture
def example_policy_path() -> Path:
    return Path(__file__).resolve().parent.parent / "examples" / "policies.yaml"


@pytest.fixture
def shield(example_policy_path: Path) -> Shield:
    return Shield.from_yaml(example_policy_path)
