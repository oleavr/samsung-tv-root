"""S95D model surface for the SDK archive root route."""

from __future__ import annotations

import asyncio
from pathlib import Path

from .archive_root import (
    CAPTURE_PORT,
    STAGING_ROOT,
    ArchiveRootError,
    probe,
)
from .resources import payload_directory
from .sdb import SdbClient, find_sdb


DEFAULT_AGENT_PORT = 24001
UEP_PAYLOAD_DIRECTORY = "s95d"
UEP_STAGING = STAGING_ROOT / "uep"


def run_s95d_root_session(
    tv_host: str,
    commands: tuple[str, ...],
    *,
    callback_host: str | None = None,
    bind_host: str | None = None,
    sdb_timeout: float = 15.0,
    accept_timeout: float = 30.0,
    command_timeout: float = 45.0,
    agent_port: int = DEFAULT_AGENT_PORT,
) -> dict[str, object]:
    return asyncio.run(
        probe(
            tv_host,
            model="s95d",
            callback_host=callback_host,
            bind_host=bind_host,
            sdb_timeout=sdb_timeout,
            accept_timeout=accept_timeout,
            command_timeout=command_timeout,
            commands=commands,
            agent_port=agent_port,
        )
    )


def run_s95d_uep_control(
    tv_host: str,
    action: str,
    *,
    callback_host: str | None = None,
    bind_host: str | None = None,
    sdb_timeout: float = 15.0,
    accept_timeout: float = 30.0,
    command_timeout: float = 45.0,
    agent_port: int = DEFAULT_AGENT_PORT,
    payload_directory: Path | None = None,
) -> dict[str, object]:
    client = SdbClient(
        find_sdb(),
        tv_host,
        timeout=sdb_timeout,
        callback_port=CAPTURE_PORT,
    )
    client.connect()
    for name in ("UepPatch.dll", "UepPatch.runtimeconfig.json"):
        source = (payload_directory or _uep_payload_directory()) / name
        client.push(source, UEP_STAGING / name)
    command = (
        f"UEP_DEVICE=/dev/sdp_hwmem /usr/bin/dotnet {UEP_STAGING}/UepPatch.dll {action}"
    )
    return run_s95d_root_session(
        tv_host,
        (command,),
        callback_host=callback_host,
        bind_host=bind_host,
        sdb_timeout=sdb_timeout,
        accept_timeout=accept_timeout,
        command_timeout=command_timeout,
        agent_port=agent_port,
    )


def _uep_payload_directory() -> Path:
    return payload_directory(UEP_PAYLOAD_DIRECTORY)


__all__ = [
    "ArchiveRootError",
    "run_s95d_root_session",
    "run_s95d_uep_control",
]
