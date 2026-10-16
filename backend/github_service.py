import base64
import os
from pathlib import Path
from typing import Any

import requests
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent / ".env", override=False)


class GitHubError(RuntimeError):
    def __init__(self, message: str, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


class GitHubClient:
    def __init__(self, token: str | None = None) -> None:
        self.token = (token if token is not None else os.getenv("GITHUB_TOKEN", "")).strip()
        self.base_url = os.getenv("GITHUB_API_BASE_URL", "https://api.github.com").rstrip("/")
        self.timeout = (5, 20)

    @property
    def configured(self) -> bool:
        return bool(self.token)

    def _request(self, method: str, path: str, params: dict[str, str] | None = None) -> Any:
        if not self.configured:
            raise GitHubError("GitHub token is not configured.")
        try:
            response = requests.request(
                method,
                f"{self.base_url}{path}",
                headers={"Authorization": "Bearer " + self.token, "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"},
                params=params,
                timeout=self.timeout,
            )
        except requests.Timeout as exc:
            raise GitHubError("GitHub request timed out.") from exc
        except requests.RequestException as exc:
            raise GitHubError("GitHub request failed.") from exc
        if response.status_code == 401:
            raise GitHubError("GitHub authentication failed.", 401)
        if response.status_code == 403 and response.headers.get("X-RateLimit-Remaining") == "0":
            raise GitHubError("GitHub API rate limit exceeded.", 429)
        if response.status_code >= 400:
            raise GitHubError(f"GitHub returned HTTP {response.status_code}.", response.status_code)
        return response.json()

    def identity(self) -> dict[str, Any]:
        return self._request("GET", "/user")

    @staticmethod
    def exchange_oauth_code(client_id: str, client_secret: str, code: str, redirect_uri: str) -> str:
        try:
            response = requests.post(
                "https://github.com/login/oauth/access_token",
                data={"client_id": client_id, "client_secret": client_secret, "code": code, "redirect_uri": redirect_uri},
                headers={"Accept": "application/json"},
                timeout=(5, 20),
            )
        except requests.RequestException as exc:
            raise GitHubError("GitHub OAuth token exchange failed.") from exc
        if response.status_code >= 400:
            raise GitHubError("GitHub OAuth token exchange failed.", response.status_code)
        payload = response.json()
        if payload.get("error") or not payload.get("access_token"):
            raise GitHubError(payload.get("error_description") or "GitHub did not return an access token.")
        return str(payload["access_token"])

    def repositories(self, page: int = 1, per_page: int = 30) -> list[dict[str, Any]]:
        return self._request("GET", "/user/repos", {"page": str(page), "per_page": str(per_page), "sort": "updated"})

    def repository(self, owner: str, name: str) -> dict[str, Any]:
        return self._request("GET", f"/repos/{owner}/{name}")

    def branches(self, owner: str, name: str) -> list[dict[str, Any]]:
        return self._request("GET", f"/repos/{owner}/{name}/branches", {"per_page": "100"})

    def commits(self, owner: str, name: str, branch: str) -> list[dict[str, Any]]:
        return self._request("GET", f"/repos/{owner}/{name}/commits", {"sha": branch, "per_page": "10"})

    def tree(self, owner: str, name: str, sha: str) -> dict[str, Any]:
        return self._request("GET", f"/repos/{owner}/{name}/git/trees/{sha}", {"recursive": "1"})

    def content(self, owner: str, name: str, path: str, sha: str) -> str:
        data = self._request("GET", f"/repos/{owner}/{name}/contents/{path}", {"ref": sha})
        if data.get("type") != "file" or not data.get("content"):
            raise GitHubError("GitHub did not return a text file.")
        return base64.b64decode(data["content"].replace("\n", "")).decode("utf-8", errors="strict")
