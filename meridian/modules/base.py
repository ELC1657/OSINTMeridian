from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import AsyncIterator


def _normalize(target: str) -> str:
    """Strip scheme, path, wildcards from a target string."""
    if "://" in target:
        target = target.split("://", 1)[1]
    target = target.split("/")[0].split("?")[0]
    target = target.lstrip("*.")
    return target.strip()


@dataclass
class Finding:
    module: str
    line: str  # Rich markup string

    def format_rich(self) -> str:
        return self.line

    def format_plain(self) -> str:
        """Strip Rich markup for plain-text export."""
        import re
        return re.sub(r"\[/?[^\]]*\]", "", self.line)


class ReconModule(ABC):
    name: str = ""
    panel_id: str = ""
    requires_key: bool = False
    key_env: str = ""

    def __init__(self, config: dict[str, str]) -> None:
        self.config = config

    def get_key(self, name: str) -> str:
        return self.config.get(name, "")

    @abstractmethod
    async def run(self, target: str) -> AsyncIterator[Finding]:
        return
        yield  # makes this an async generator so subclass signatures match
