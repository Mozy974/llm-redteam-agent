import yaml
from pathlib import Path

PAYLOADS_DIR = Path(__file__).parent


def load_payloads(category: str) -> list[dict]:
    """Load payloads from a YAML file. Returns list of {name, prompt, severity} dicts."""
    path = PAYLOADS_DIR / f"{category}.yaml"
    if not path.exists():
        raise FileNotFoundError(f"No payload file: {path}")

    with open(path) as f:
        data = yaml.safe_load(f)

    payloads = []
    for technique, entries in data.items():
        for entry in entries:
            if isinstance(entry, dict):
                entry["technique"] = technique
                payloads.append(entry)
    return payloads


def list_categories() -> list[str]:
    """List available payload categories."""
    return sorted(
        p.stem for p in PAYLOADS_DIR.glob("*.yaml")
    )
