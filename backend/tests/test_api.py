import os
import sys
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).parents[1]))
os.environ["DATABASE_URL"] = "sqlite:///" + str(Path(__file__).with_name("test.db"))
os.environ.pop("GITHUB_TOKEN", None)

from github_service import GitHubError  # noqa: E402
from main import app, canonical_github_url, github_repository_parts  # noqa: E402


def test_github_not_configured(monkeypatch) -> None:
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    with TestClient(app) as client:
        response = client.get("/github/status")
    assert response.status_code == 200
    assert response.json()["status"] == "not_configured"


def test_github_auth_failure() -> None:
    os.environ["GITHUB_TOKEN"] = "test-token"
    with patch("main.GitHubClient.identity", side_effect=GitHubError("bad", 401)):
        with TestClient(app) as client:
            response = client.get("/github/status")
    assert response.status_code == 200
    assert response.json()["status"] == "authentication_failed"
    os.environ.pop("GITHUB_TOKEN", None)


def test_register_uses_remote_metadata() -> None:
    remote = {"id": 7, "name": "repo", "full_name": "owner/repo", "html_url": "https://github.com/owner/repo", "owner": {"login": "owner"}, "private": False, "default_branch": "main"}
    os.environ["GITHUB_TOKEN"] = "test-token"
    with patch("main.GitHubClient.repository", return_value=remote):
        with TestClient(app) as client:
            response = client.post("/repositories", json={"url": remote["html_url"], "branch": "main"})
    assert response.status_code in (201, 409)
    os.environ.pop("GITHUB_TOKEN", None)


def test_github_repository_url_normalizes_git_suffix_and_trailing_slash() -> None:
    value = " https://github.com/owner/repo.git/// "
    assert canonical_github_url(value) == "https://github.com/owner/repo"
    assert github_repository_parts(value) == ("owner", "repo")


def test_github_repository_url_rejects_unsafe_or_ambiguous_urls() -> None:
    invalid = (
        "http://github.com/owner/repo",
        "https://example.com/owner/repo",
        "https://github.com/owner/repo/issues",
        "https://github.com/owner/repo?tab=readme",
        "https://github.com/owner/",
    )
    for value in invalid:
        with pytest.raises(ValueError):
            canonical_github_url(value)
