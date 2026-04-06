import os
from pathlib import Path

try:
    import tomllib
except ImportError:
    try:
        import tomli as tomllib  # type: ignore
    except ImportError:
        tomllib = None  # type: ignore

_CONFIG_FILE = Path.home() / ".config" / "meridian" / "keys.toml"

_ENV_MAP = {
    "SHODAN_API_KEY": "shodan_api_key",
    "VT_API_KEY": "vt_api_key",
    "GITHUB_TOKEN": "github_token",
}


def load_config() -> dict[str, str]:
    """Load API keys from ~/.config/meridian/keys.toml, then override with env vars."""
    config: dict[str, str] = {}

    if tomllib and _CONFIG_FILE.exists():
        with open(_CONFIG_FILE, "rb") as f:
            config.update(tomllib.load(f))

    for env_var, key in _ENV_MAP.items():
        value = os.environ.get(env_var, "")
        if value:
            config[key] = value

    return config
