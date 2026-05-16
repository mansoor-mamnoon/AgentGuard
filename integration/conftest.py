"""Shared pytest fixtures for integration tests."""

from __future__ import annotations

import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest


@pytest.fixture()
def sandbox(tmp_path: Path) -> Path:
    """A temporary directory used as the filesystem server's sandbox."""
    return tmp_path


@pytest.fixture()
def git_repo(tmp_path: Path) -> Path:
    """A temporary git repo with one commit."""
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", str(repo)], capture_output=True, check=True)
    subprocess.run(
        ["git", "-C", str(repo), "config", "user.email", "test@test.com"],
        capture_output=True,
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(repo), "config", "user.name", "Test"],
        capture_output=True,
        check=True,
    )
    readme = repo / "README.md"
    readme.write_text("# Test repo\nThis is a test.\n")
    subprocess.run(["git", "-C", str(repo), "add", "."], capture_output=True, check=True)
    subprocess.run(
        ["git", "-C", str(repo), "commit", "-m", "initial commit"],
        capture_output=True,
        check=True,
    )
    return repo


@pytest.fixture()
def sqlite_db(tmp_path: Path) -> Path:
    """A temporary SQLite database with test data."""
    db_path = tmp_path / "test.db"
    conn = sqlite3.connect(str(db_path))
    conn.execute("CREATE TABLE employees (id INTEGER PRIMARY KEY, name TEXT, department TEXT)")
    conn.executemany(
        "INSERT INTO employees (name, department) VALUES (?, ?)",
        [
            ("Alice", "Engineering"),
            ("Bob", "Marketing"),
            ("Carol", "Engineering"),
        ],
    )
    conn.execute("CREATE TABLE config (key TEXT PRIMARY KEY, value TEXT)")
    conn.executemany(
        "INSERT INTO config (key, value) VALUES (?, ?)",
        [("app_name", "TestApp"), ("version", "1.0")],
    )
    conn.commit()
    conn.close()
    return db_path


@pytest.fixture()
def fs_upstream(sandbox: Path) -> str:
    return f"{sys.executable} -m integration.servers.filesystem_server {sandbox}"


@pytest.fixture()
def git_upstream(git_repo: Path) -> str:
    return f"{sys.executable} -m integration.servers.git_server {git_repo}"


@pytest.fixture()
def sqlite_upstream(sqlite_db: Path) -> str:
    return f"{sys.executable} -m integration.servers.sqlite_server {sqlite_db}"
