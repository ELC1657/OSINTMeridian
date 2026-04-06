from __future__ import annotations

import click
from dotenv import load_dotenv

from .app import MeridianApp
from .config import load_config


@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.argument("target")
@click.option("--shodan-key",    envvar="SHODAN_API_KEY", default="", help="Shodan API key")
@click.option("--vt-key",        envvar="VT_API_KEY",     default="", help="VirusTotal API key")
@click.option("--github-token",  envvar="GITHUB_TOKEN",   default="", help="GitHub personal access token")
@click.option("--env-file",      default=".env",          help="Path to .env file (default: .env)")
def main(target: str, shodan_key: str, vt_key: str, github_token: str, env_file: str) -> None:
    """
    MERIDIAN - Passive recon aggregator.

    TARGET can be a domain (example.com), IP address, or CIDR range.

    API keys are read from environment variables or a .env file:

    \b
      SHODAN_API_KEY  - https://account.shodan.io/
      VT_API_KEY      - https://www.virustotal.com/gui/my-apikey
      GITHUB_TOKEN    - https://github.com/settings/tokens
    """
    load_dotenv(env_file, override=False)
    config = load_config()

    if shodan_key:
        config["shodan_api_key"] = shodan_key
    if vt_key:
        config["vt_api_key"] = vt_key
    if github_token:
        config["github_token"] = github_token

    app = MeridianApp(target=target, config=config)
    app.run()


if __name__ == "__main__":
    main()
