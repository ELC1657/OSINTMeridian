from __future__ import annotations

import click
from dotenv import load_dotenv

from .app import MeridianApp
from .config import load_config


@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.argument("target")
@click.option("--shodan-key",      envvar="SHODAN_API_KEY",   default="", help="Shodan API key")
@click.option("--vt-key",          envvar="VT_API_KEY",       default="", help="VirusTotal API key")
@click.option("--github-token",    envvar="GITHUB_TOKEN",     default="", help="GitHub personal access token")
@click.option("--intelx-key",      envvar="INTELX_API_KEY",   default="", help="IntelligenceX API key")
@click.option("--rapidapi-key",    envvar="RAPIDAPI_KEY",     default="", help="RapidAPI key (BreachDirectory)")
@click.option("--dehashed-email",  envvar="DEHASHED_EMAIL",   default="", help="Dehashed account email")
@click.option("--dehashed-key",    envvar="DEHASHED_API_KEY", default="", help="Dehashed API key")
@click.option("--env-file",        default=".env",            help="Path to .env file (default: .env)")
@click.option("--watch", "-w",     is_flag=True, default=False, help="Monitor mode: re-scan automatically")
@click.option("--interval",        default=30, show_default=True, help="Watch interval in minutes")
def main(
    target: str,
    shodan_key: str,
    vt_key: str,
    github_token: str,
    intelx_key: str,
    rapidapi_key: str,
    dehashed_email: str,
    dehashed_key: str,
    env_file: str,
    watch: bool,
    interval: int,
) -> None:
    """
    MERIDIAN - Passive recon aggregator.

    TARGET can be a domain (example.com), IP address, or CIDR range.

    API keys are read from environment variables or a .env file:

    \b
      SHODAN_API_KEY    - https://account.shodan.io/
      VT_API_KEY        - https://www.virustotal.com/gui/my-apikey
      GITHUB_TOKEN      - https://github.com/settings/tokens
      INTELX_API_KEY    - https://intelx.io (free tier)
      RAPIDAPI_KEY      - https://rapidapi.com (BreachDirectory, free tier)
      DEHASHED_EMAIL    - https://dehashed.com (paid)
      DEHASHED_API_KEY  - https://dehashed.com (paid)

    Watch mode re-scans the target on a timer and highlights new findings:

    \b
      meridian example.com --watch
      meridian example.com --watch --interval 15
    """
    load_dotenv(env_file, override=False)
    config = load_config()

    if shodan_key:
        config["shodan_api_key"] = shodan_key
    if vt_key:
        config["vt_api_key"] = vt_key
    if github_token:
        config["github_token"] = github_token
    if intelx_key:
        config["intelx_api_key"] = intelx_key
    if rapidapi_key:
        config["rapidapi_key"] = rapidapi_key
    if dehashed_email:
        config["dehashed_email"] = dehashed_email
    if dehashed_key:
        config["dehashed_api_key"] = dehashed_key

    app = MeridianApp(
        target=target,
        config=config,
        watch_interval=interval if watch else None,
    )
    app.run()


if __name__ == "__main__":
    main()
