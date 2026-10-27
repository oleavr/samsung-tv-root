"""Surface tests for the S95D model route."""

from __future__ import annotations

import pytest

from samsung_tv_root.cli import build_parser


def test_s95d_root_takes_a_command() -> None:
    arguments = build_parser().parse_args(
        ["s95d", "root", "192.0.2.77", "--command", "id"]
    )
    assert arguments.host == "192.0.2.77"
    assert arguments.command == ["id"]


def test_s95d_uep_takes_an_action() -> None:
    arguments = build_parser().parse_args(
        ["s95d", "uep", "192.0.2.77", "status"]
    )
    assert arguments.host == "192.0.2.77"
    assert arguments.action == "status"


def test_s95d_uep_rejects_unknown_actions() -> None:
    with pytest.raises(SystemExit):
        build_parser().parse_args(["s95d", "uep", "192.0.2.77", "disable"])


def test_archive_root_group_still_parses() -> None:
    arguments = build_parser().parse_args(
        ["archive-root", "root", "192.0.2.77", "--command", "id"]
    )
    assert arguments.host == "192.0.2.77"
    assert arguments.model is None
