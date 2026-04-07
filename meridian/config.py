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
    "SHODAN_API_KEY":   "shodan_api_key",
    "VT_API_KEY":       "vt_api_key",
    "GITHUB_TOKEN":     "github_token",
    "HUNTER_API_KEY":   "hunter_api_key",
    "INTELX_API_KEY":   "intelx_api_key",
    "RAPIDAPI_KEY":     "rapidapi_key",
    "DEHASHED_EMAIL":   "dehashed_email",
    "DEHASHED_API_KEY": "dehashed_api_key",
}


def load_config() -> dict[str, str]:
    """Load API keys from all known locations, lowest to highest priority."""
    from dotenv import load_dotenv

    config: dict[str, str] = {}

    # 1. ~/.config/meridian/keys.toml
    if tomllib and _CONFIG_FILE.exists():
        with open(_CONFIG_FILE, "rb") as f:
            config.update(tomllib.load(f))

    # 2. ~/.config/meridian/.env (permanent location, works from any directory)
    _home_env = Path.home() / ".config" / "meridian" / ".env"
    if _home_env.exists():
        load_dotenv(_home_env, override=False)

    # 3. Environment variables (includes anything already exported in shell)
    for env_var, key in _ENV_MAP.items():
        value = os.environ.get(env_var, "")
        if value:
            config[key] = value

    return config
