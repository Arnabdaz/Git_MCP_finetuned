"""The MCP wiring: tools are listed and callable through a real (in-process) client.

Uses the pre-2026 handshake (mode="legacy"), as older MCP clients such as IDEs do.
"""

import asyncio
from pathlib import Path
from typing import Any

import git
import pytest
from mcp.client import Client

from mcp_server_git.server import GitTools, build_server


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    repository = git.Repo.init(tmp_path)
    (tmp_path / "a.txt").write_text("hello")
    repository.index.add(["a.txt"])
    repository.index.commit("initial")
    return tmp_path


def _run(coro: Any) -> Any:
    return asyncio.run(coro)


def test_lists_every_tool() -> None:
    async def names() -> set[str]:
        async with Client(build_server(), mode="legacy") as client:
            return {t.name for t in (await client.list_tools()).tools}

    assert _run(names()) == {t.value for t in GitTools}


def test_calls_a_tool(repo: Path) -> None:
    async def status() -> tuple[bool, str]:
        async with Client(build_server(), mode="legacy") as client:
            result = await client.call_tool(GitTools.STATUS.value, {"repo_path": str(repo)})
            return result.is_error, result.content[0].text

    is_error, text = _run(status())
    assert is_error is False
    assert "Repository status" in text


def test_errors_come_back_as_text(repo: Path) -> None:
    async def bad() -> str:
        async with Client(build_server(), mode="legacy") as client:
            result = await client.call_tool(
                GitTools.CHECKOUT.value, {"repo_path": str(repo), "branch_name": "nope"}
            )
            return result.content[0].text

    assert _run(bad()).startswith("Error")
