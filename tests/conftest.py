#!/usr/bin/env python

"""Configures execution of pytest."""

import pytest


def pytest_addoption(parser):
    """pytest add option."""
    parser.addoption(
        "--allow-online",
        action="store_true",
        default=False,
        help="Allow execution of online tests.",
    )


def pytest_collection_modifyitems(config, items):
    """pytest collection modifier."""

    skip_online = pytest.mark.skip(
        reason="Execution of online tests requires --allow-online option."
    )
    for item in items:
        if "online" in item.keywords and not config.getoption("--allow-online"):
            item.add_marker(skip_online)


def pytest_configure(config):
    """pytest configuration hook."""
    config.addinivalue_line("markers", "online: allow execution of online tests.")
