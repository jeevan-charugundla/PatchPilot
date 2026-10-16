import os
import re
import secrets
import sqlite3
import hashlib
import base64
import json
from urllib.parse import urlsplit
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from fastapi import Cookie, Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, field_validator
from dotenv import load_dotenv
from cryptography.fernet import Fernet, InvalidToken

if __package__:
    from .analysis_service import analyze_repository
    from .github_service import GitHubClient, GitHubError
else:
    from analysis_service import analyze_repository
    from github_service import GitHubClient, GitHubError

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env", override=False)
database_url = os.getenv("DATABASE_URL", f"sqlite:///{BASE_DIR / 'patchpilot.db'}")
database_path = Path(database_url.removeprefix("sqlite:///") if database_url.startswith("sqlite:///") else database_url)
DB_PATH = database_path if database_path.is_absolute() else BASE_DIR / database_path
app = FastAPI(title="PatchPilot API", version="0.2.0")
FRONTEND_ORIGIN = os.getenv("FRONTEND_ORIGIN", "http://localhost:5173").rstrip("/")
SESSION_COOKIE = "patchpilot_session"
CSRF_COOKIE = "patchpilot_csrf"
SESSION_TTL = 60 * 60 * 24 * 7
OAUTH_TTL = 600
app.add_middleware(CORSMiddleware, allow_origins=[FRONTEND_ORIGIN, "http://localhost:5173", "http://127.0.0.1:5173"], allow_credentials=True, allow_methods=["GET", "POST", "DELETE"], allow_headers=["Content-Type", "X-CSRF-Token"])


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def connection() -> sqlite3.Connection:
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    return db


def encryption() -> Fernet:
    key = os.getenv("SESSION_ENCRYPTION_KEY", "").strip()
    if not key:
        raise HTTPException(503, "OAuth is not configured: set SESSION_ENCRYPTION_KEY.")
    try:
        return Fernet(key.encode())
    except (ValueError, TypeError) as exc:
        raise HTTPException(503, "OAuth is not configured: SESSION_ENCRYPTION_KEY is invalid.") from exc


def cookie_secure() -> bool:
    return FRONTEND_ORIGIN.startswith("https://")


def iso_after(seconds: int) -> str:
    return (datetime.now(timezone.utc) + timedelta(seconds=seconds)).isoformat()


def token_for_user(user_id: str) -> str:
    with connection() as db:
        row = db.execute("SELECT token_ciphertext FROM github_tokens WHERE user_id = ?", (user_id,)).fetchone()
    if not row:
        raise HTTPException(401, "GitHub session is not connected.")
    try:
        return encryption().decrypt(row["token_ciphertext"].encode()).decode()
    except InvalidToken as exc:
        raise HTTPException(503, "Stored GitHub credentials could not be decrypted.") from exc


def current_session(session_id: str | None = Cookie(default=None, alias=SESSION_COOKIE)) -> dict[str, str]:
    if session_id:
        with connection() as db:
            row = db.execute(
                "SELECT s.*, u.login, u.name, u.avatar_url, u.github_id FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.id = ? AND s.expires_at > ?",
                (session_id, now()),
            ).fetchone()
        if row:
            return dict(row)
    legacy_token = os.getenv("GITHUB_TOKEN", "").strip()
    if legacy_token:
        return {"id": "legacy", "user_id": "legacy", "login": "legacy", "csrf_token": ""}
    raise HTTPException(401, "Sign in with GitHub to continue.")


def strict_session(session_id: str | None = Cookie(default=None, alias=SESSION_COOKIE)) -> dict[str, str]:
    if not session_id:
        raise HTTPException(401, "Sign in with GitHub to continue.")
    with connection() as db:
        row = db.execute(
            "SELECT s.*, u.login, u.name, u.avatar_url, u.github_id FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.id = ? AND s.expires_at > ?",
            (session_id, now()),
        ).fetchone()
    if not row:
        raise HTTPException(401, "Sign in with GitHub to continue.")
    return dict(row)


def require_csrf(session: dict[str, str], csrf_header: str | None) -> None:
    if session["id"] != "legacy" and (not csrf_header or not secrets.compare_digest(csrf_header, session["csrf_token"])):
        raise HTTPException(403, "CSRF validation failed.")


def github_client(session: dict[str, str] = Depends(current_session)) -> GitHubClient:
    return GitHubClient(os.getenv("GITHUB_TOKEN", "") if session["id"] == "legacy" else token_for_user(session["user_id"]))


def init_db() -> None:
    with connection() as db:
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS repositories (
                id TEXT PRIMARY KEY, github_id INTEGER UNIQUE, name TEXT NOT NULL, owner TEXT NOT NULL,
                full_name TEXT NOT NULL, url TEXT NOT NULL, branch TEXT NOT NULL, visibility TEXT,
                last_commit_sha TEXT, last_sync TEXT, status TEXT NOT NULL, last_analysis TEXT
            );
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY, github_id INTEGER UNIQUE NOT NULL, login TEXT NOT NULL,
                name TEXT, avatar_url TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS github_tokens (
                user_id TEXT PRIMARY KEY, token_ciphertext TEXT NOT NULL, updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sessions (
                id TEXT PRIMARY KEY, user_id TEXT NOT NULL, csrf_token TEXT NOT NULL,
                created_at TEXT NOT NULL, expires_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS oauth_states (
                state_hash TEXT PRIMARY KEY, csrf_token TEXT NOT NULL, created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS analysis_runs (
                id TEXT PRIMARY KEY, repository_id TEXT NOT NULL, commit_sha TEXT NOT NULL, branch TEXT,
                status TEXT NOT NULL, started_at TEXT NOT NULL, completed_at TEXT, error TEXT,
                stats_json TEXT NOT NULL, checks_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS findings (
                id TEXT PRIMARY KEY, repository_id TEXT NOT NULL, analysis_run_id TEXT NOT NULL,
                commit_sha TEXT NOT NULL, file TEXT NOT NULL, line INTEGER, column_number INTEGER,
                rule_id TEXT NOT NULL, category TEXT NOT NULL, severity TEXT NOT NULL, title TEXT NOT NULL,
                explanation TEXT NOT NULL, evidence TEXT NOT NULL, analyzer TEXT NOT NULL,
                analyzer_version TEXT NOT NULL, confidence TEXT NOT NULL, created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS activity (
                id TEXT PRIMARY KEY, action TEXT NOT NULL, entity_id TEXT NOT NULL,
                outcome TEXT NOT NULL, created_at TEXT NOT NULL
            );
            """
        )
        # Additive migration for databases created by the first milestone.
        columns = {row["name"] for row in db.execute("PRAGMA table_info(repositories)")}
        for name, sql in {"github_id": "INTEGER", "full_name": "TEXT", "visibility": "TEXT", "last_commit_sha": "TEXT", "last_sync": "TEXT"}.items():
            if name not in columns:
                db.execute(f"ALTER TABLE repositories ADD COLUMN {name} {sql}")
        columns = {row["name"] for row in db.execute("PRAGMA table_info(repositories)")}
        if "user_id" not in columns:
            db.execute("ALTER TABLE repositories ADD COLUMN user_id TEXT")


@app.on_event("startup")
def startup() -> None:
    init_db()


class RepositoryInput(BaseModel):
    url: str
    branch: str = Field(default="main", min_length=1, max_length=100)

    @field_validator("url")
    @classmethod
    def valid_url(cls, value: str) -> str:
        return canonical_github_url(value)


class AnalysisInput(BaseModel):
    branch: str | None = None
    commit_sha: str | None = None

    @field_validator("branch", "commit_sha")
    @classmethod
    def safe_ref(cls, value: str | None) -> str | None:
        if value and not re.fullmatch(r"[A-Za-z0-9._/-]{1,200}", value):
            raise ValueError("Invalid branch or commit identifier.")
        return value


def log(db: sqlite3.Connection, action: str, entity_id: str, outcome: str) -> None:
    db.execute("INSERT INTO activity VALUES (?, ?, ?, ?, ?)", (str(uuid4()), action, entity_id, outcome, now()))


def canonical_github_url(value: str) -> str:
    candidate = value.strip()
    parsed = urlsplit(candidate)
    if parsed.scheme != "https" or parsed.netloc.lower() != "github.com" or parsed.query or parsed.fragment:
        raise ValueError("Use an HTTPS GitHub repository URL.")
    parts = [part for part in parsed.path.split("/") if part]
    if len(parts) != 2 or parts[0] in {".", ".."} or parts[1] in {".", ".."}:
        raise ValueError("Use an HTTPS GitHub repository URL.")
    owner, name = parts
    if name.endswith(".git"):
        name = name[:-4]
    if not owner or not name or not re.fullmatch(r"[A-Za-z0-9_.-]+", owner) or not re.fullmatch(r"[A-Za-z0-9_.-]+", name):
        raise ValueError("Use an HTTPS GitHub repository URL.")
    return f"https://github.com/{owner}/{name}"


def github_repository_parts(value: str) -> tuple[str, str]:
    canonical = canonical_github_url(value)
    owner, name = canonical.removeprefix("https://github.com/").split("/", 1)
    return owner, name


def github_error(error: GitHubError) -> HTTPException:
    status = error.status_code or 502
    if status == 401:
        return HTTPException(502, "GitHub authentication failed.")
    if status == 429:
        return HTTPException(429, "GitHub API rate limit exceeded.")
    return HTTPException(502, str(error))


@app.get("/")
def root() -> dict[str, str]:
    return {"message": "PatchPilot API is running", "version": "0.2.0"}


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "healthy"}


@app.get("/auth/github")
def github_login() -> RedirectResponse:
    client_id = os.getenv("GITHUB_CLIENT_ID", "").strip()
    if not client_id or not os.getenv("GITHUB_CLIENT_SECRET", "").strip():
        raise HTTPException(503, "GitHub OAuth is not configured.")
    state = secrets.token_urlsafe(32)
    csrf_token = secrets.token_urlsafe(32)
    with connection() as db:
        db.execute("DELETE FROM oauth_states WHERE expires_at <= ?", (now(),))
        db.execute("INSERT INTO oauth_states VALUES (?, ?, ?, ?)", (hashlib.sha256(state.encode()).hexdigest(), csrf_token, now(), iso_after(OAUTH_TTL)))
    redirect_uri = os.getenv("GITHUB_OAUTH_REDIRECT_URI", f"{os.getenv('BACKEND_ORIGIN', 'http://127.0.0.1:8000')}/auth/github/callback")
    url = f"https://github.com/login/oauth/authorize?client_id={client_id}&redirect_uri={redirect_uri}&scope=repo&state={state}"
    response = RedirectResponse(url)
    response.set_cookie("patchpilot_oauth_state", state, httponly=True, secure=cookie_secure(), samesite="lax", max_age=OAUTH_TTL)
    return response


@app.get("/auth/github/callback")
def github_callback(code: str | None = None, state: str | None = None, error: str | None = None, error_description: str | None = None, oauth_state_cookie: str | None = Cookie(default=None, alias="patchpilot_oauth_state")) -> RedirectResponse:
    if error:
        return RedirectResponse(f"{FRONTEND_ORIGIN}/?auth_error={error_description or error}")
    if not code or not state or not oauth_state_cookie or not secrets.compare_digest(state, oauth_state_cookie):
        return RedirectResponse(f"{FRONTEND_ORIGIN}/?auth_error=Missing+OAuth+callback+parameters")
    with connection() as db:
        oauth_state = db.execute("SELECT * FROM oauth_states WHERE state_hash = ? AND expires_at > ?", (hashlib.sha256(state.encode()).hexdigest(), now())).fetchone()
        if not oauth_state:
            return RedirectResponse(f"{FRONTEND_ORIGIN}/?auth_error=Invalid+or+expired+OAuth+state")
        db.execute("DELETE FROM oauth_states WHERE state_hash = ?", (hashlib.sha256(state.encode()).hexdigest(),))
    redirect_uri = os.getenv("GITHUB_OAUTH_REDIRECT_URI", f"{os.getenv('BACKEND_ORIGIN', 'http://127.0.0.1:8000')}/auth/github/callback")
    try:
        token = GitHubClient.exchange_oauth_code(os.getenv("GITHUB_CLIENT_ID", ""), os.getenv("GITHUB_CLIENT_SECRET", ""), code, redirect_uri)
        account = GitHubClient(token).identity()
        encryption()
    except (GitHubError, HTTPException) as exc:
        detail = exc.detail if isinstance(exc, HTTPException) else str(exc)
        return RedirectResponse(f"{FRONTEND_ORIGIN}/?auth_error={detail}")
    user_id = f"user-{account['id']}"
    session_id = secrets.token_urlsafe(32)
    with connection() as db:
        timestamp = now()
        db.execute(
            "INSERT INTO users (id, github_id, login, name, avatar_url, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(github_id) DO UPDATE SET login=excluded.login, name=excluded.name, avatar_url=excluded.avatar_url, updated_at=excluded.updated_at",
            (user_id, account["id"], account["login"], account.get("name"), account.get("avatar_url"), timestamp, timestamp),
        )
        actual_user_id = db.execute("SELECT id FROM users WHERE github_id = ?", (account["id"],)).fetchone()["id"]
        db.execute("INSERT OR REPLACE INTO github_tokens VALUES (?, ?, ?)", (actual_user_id, encryption().encrypt(token.encode()).decode(), timestamp))
        db.execute("INSERT INTO sessions VALUES (?, ?, ?, ?, ?)", (session_id, actual_user_id, oauth_state["csrf_token"], timestamp, iso_after(SESSION_TTL)))
    response = RedirectResponse(FRONTEND_ORIGIN)
    response.delete_cookie("patchpilot_oauth_state")
    response.set_cookie(SESSION_COOKIE, session_id, httponly=True, secure=cookie_secure(), samesite="lax", max_age=SESSION_TTL)
    response.set_cookie(CSRF_COOKIE, oauth_state["csrf_token"], httponly=False, secure=cookie_secure(), samesite="lax", max_age=SESSION_TTL)
    return response


@app.get("/auth/me")
def auth_me(session: dict[str, str] = Depends(strict_session)) -> dict[str, Any]:
    return {"authenticated": True, "account": {"login": session["login"], "name": session.get("name"), "avatar_url": session.get("avatar_url"), "github_id": session["github_id"]}}


@app.post("/auth/logout")
def logout(session: dict[str, str] = Depends(current_session), csrf_header: str | None = Header(default=None, alias="X-CSRF-Token")) -> dict[str, str]:
    require_csrf(session, csrf_header)
    if session["id"] != "legacy":
        with connection() as db:
            db.execute("DELETE FROM sessions WHERE id = ?", (session["id"],))
    return {"status": "logged_out"}


@app.get("/github/status")
def github_status(session: dict[str, str] | None = Depends(lambda session_id=Cookie(default=None, alias=SESSION_COOKIE): current_session(session_id) if session_id else None)) -> dict[str, Any]:
    client = github_client(session) if session else GitHubClient()
    if not client.configured:
        return {"status": "not_configured", "account": None}
    try:
        account = client.identity()
        return {"status": "connected", "account": {"login": account.get("login"), "name": account.get("name"), "avatar_url": account.get("avatar_url")}}
    except GitHubError as error:
        if error.status_code == 401:
            return {"status": "authentication_failed", "account": None}
        raise github_error(error)


@app.delete("/github/connection")
def disconnect_github() -> dict[str, str]:
    return {"status": "disabled_locally", "message": "Set GITHUB_TOKEN empty to disable the integration."}


@app.get("/github/repositories")
def accessible_repositories(search: str = Query(default=""), page: int = Query(default=1, ge=1), per_page: int = Query(default=30, ge=1, le=100), client: GitHubClient = Depends(github_client)) -> list[dict[str, Any]]:
    try:
        items = client.repositories(page, per_page)
    except GitHubError as error:
        raise github_error(error)
    query = search.lower().strip()
    return [item for item in items if not query or query in item.get("full_name", "").lower()]


@app.get("/github/repositories/{owner}/{name}")
def github_repository(owner: str, name: str, client: GitHubClient = Depends(github_client)) -> dict[str, Any]:
    try:
        return client.repository(owner, name)
    except GitHubError as error:
        raise github_error(error)


@app.get("/github/repositories/{owner}/{name}/branches")
def github_branches(owner: str, name: str, client: GitHubClient = Depends(github_client)) -> list[dict[str, Any]]:
    try:
        return client.branches(owner, name)
    except GitHubError as error:
        raise github_error(error)


@app.get("/github/repositories/{owner}/{name}/commits")
def github_commits(owner: str, name: str, branch: str = "HEAD", client: GitHubClient = Depends(github_client)) -> list[dict[str, Any]]:
    try:
        return client.commits(owner, name, branch)
    except GitHubError as error:
        raise github_error(error)


@app.get("/github/repositories/{owner}/{name}/contents/{path:path}")
def github_source(owner: str, name: str, path: str, sha: str = Query(..., min_length=7, max_length=64), client: GitHubClient = Depends(github_client)) -> dict[str, str]:
    if not re.fullmatch(r"[0-9a-fA-F]{7,64}", sha) or not path or ".." in path.split("/"):
        raise HTTPException(400, "A commit SHA and safe source path are required.")
    try:
        return {"path": path, "commit_sha": sha, "content": client.content(owner, name, path, sha)}
    except GitHubError as error:
        raise github_error(error)


@app.get("/repositories")
def list_repositories(session: dict[str, str] = Depends(current_session)) -> list[dict[str, Any]]:
    with connection() as db:
        query = "SELECT * FROM repositories WHERE user_id = ? ORDER BY rowid DESC" if session["id"] != "legacy" else "SELECT * FROM repositories ORDER BY rowid DESC"
        return [dict(row) for row in db.execute(query, (session["user_id"],) if session["id"] != "legacy" else ())]


@app.post("/repositories", status_code=201)
def register_repository(payload: RepositoryInput, session: dict[str, str] = Depends(current_session), client: GitHubClient = Depends(github_client), csrf_header: str | None = Header(default=None, alias="X-CSRF-Token")) -> dict[str, Any]:
    require_csrf(session, csrf_header)
    owner, name = github_repository_parts(payload.url)
    try:
        remote = client.repository(owner, name)
    except GitHubError as error:
        raise github_error(error)
    repo = {"id": f"repo-{uuid4().hex[:8]}", "user_id": None if session["id"] == "legacy" else session["user_id"], "github_id": remote["id"], "name": remote["name"], "owner": remote["owner"]["login"], "full_name": remote["full_name"], "url": remote["html_url"], "branch": payload.branch or remote["default_branch"], "visibility": "private" if remote.get("private") else "public", "last_commit_sha": None, "last_sync": now(), "status": "synchronized", "last_analysis": None}
    with connection() as db:
        try:
            db.execute(
                """
                INSERT INTO repositories
                    (id, user_id, github_id, name, owner, full_name, url, branch, visibility,
                     last_commit_sha, last_sync, status, last_analysis)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    repo["id"], repo["user_id"],
                    repo["github_id"],
                    repo["name"],
                    repo["owner"],
                    repo["full_name"],
                    repo["url"],
                    repo["branch"],
                    repo["visibility"],
                    repo["last_commit_sha"],
                    repo["last_sync"],
                    repo["status"],
                    repo["last_analysis"],
                ),
            )
            log(db, "Repository registered", repo["id"], "Metadata synchronized from GitHub")
        except sqlite3.IntegrityError as exc:
            raise HTTPException(409, "That GitHub repository is already registered.") from exc
    return repo


@app.delete("/repositories/{repository_id}")
def unregister_repository(repository_id: str, session: dict[str, str] = Depends(current_session), csrf_header: str | None = Header(default=None, alias="X-CSRF-Token")) -> dict[str, str]:
    require_csrf(session, csrf_header)
    with connection() as db:
        query = "DELETE FROM repositories WHERE id = ?" if session["id"] == "legacy" else "DELETE FROM repositories WHERE id = ? AND user_id = ?"
        params = (repository_id,) if session["id"] == "legacy" else (repository_id, session["user_id"])
        deleted = db.execute(query, params).rowcount
        if not deleted:
            raise HTTPException(404, "Repository not found.")
        log(db, "Repository unregistered", repository_id, "Local record removed")
    return {"status": "removed"}


@app.post("/repositories/{repository_id}/analysis", status_code=201)
def start_analysis(repository_id: str, payload: AnalysisInput, session: dict[str, str] = Depends(current_session), client: GitHubClient = Depends(github_client), csrf_header: str | None = Header(default=None, alias="X-CSRF-Token")) -> dict[str, Any]:
    require_csrf(session, csrf_header)
    with connection() as db:
        query = "SELECT * FROM repositories WHERE id = ?" if session["id"] == "legacy" else "SELECT * FROM repositories WHERE id = ? AND user_id = ?"
        repo = db.execute(query, (repository_id,) if session["id"] == "legacy" else (repository_id, session["user_id"])).fetchone()
    if not repo:
        raise HTTPException(404, "Repository not found.")
    branch = payload.branch or repo["branch"]
    try:
        commit = {"sha": payload.commit_sha} if payload.commit_sha else client.commits(repo["owner"], repo["name"], branch)[0]
        sha = commit["sha"]
        run_id = f"run-{uuid4().hex[:10]}"
        findings, stats = analyze_repository(client, repo["owner"], repo["name"], sha, run_id, repository_id)
    except (GitHubError, IndexError) as error:
        message = str(error) or "No commit found for the selected branch."
        with connection() as db:
            db.execute("INSERT INTO analysis_runs VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (locals().get("run_id", f"run-{uuid4().hex[:10]}"), repository_id, locals().get("sha", ""), branch, "failed", now(), now(), message, "{}", "{}"))
        raise github_error(error) if isinstance(error, GitHubError) else HTTPException(502, message)
    completed = now()
    with connection() as db:
        db.execute("INSERT INTO analysis_runs VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (run_id, repository_id, sha, branch, "completed", completed, completed, None, str(stats), '{"python_rules":"executed","pattern_rules":"executed"}'))
        for finding in findings:
            db.execute("INSERT INTO findings VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (finding["id"], finding["repository_id"], finding["analysis_run_id"], finding["commit_sha"], finding["file"], finding["line"], finding["column"], finding["rule_id"], finding["category"], finding["severity"], finding["title"], finding["explanation"], finding["evidence"], finding["analyzer"], finding["analyzer_version"], finding["confidence"], finding["created_at"]))
        db.execute("UPDATE repositories SET last_commit_sha = ?, last_sync = ?, last_analysis = ? WHERE id = ?", (sha, completed, completed, repository_id))
        log(db, "Analysis completed", run_id, f"{len(findings)} findings at {sha[:12]}")
    return {"id": run_id, "repository_id": repository_id, "commit_sha": sha, "branch": branch, "status": "completed", "findings_count": len(findings), "stats": stats}


@app.get("/analysis")
def list_analysis(repository_id: str | None = None, session: dict[str, str] = Depends(current_session)) -> list[dict[str, Any]]:
    query = "SELECT a.* FROM analysis_runs a JOIN repositories r ON r.id = a.repository_id"
    params: tuple[str, ...] = ()
    if session["id"] != "legacy":
        query += " WHERE r.user_id = ?"
        params = (session["user_id"],)
    if repository_id:
        query += " AND a.repository_id = ?" if " WHERE " in query else " WHERE a.repository_id = ?"
        params += (repository_id,)
    query += " ORDER BY a.started_at DESC"
    with connection() as db:
        return [dict(row) for row in db.execute(query, params)]


@app.get("/analysis/{run_id}/findings")
def run_findings(run_id: str, session: dict[str, str] = Depends(current_session)) -> list[dict[str, Any]]:
    with connection() as db:
        query = "SELECT f.* FROM findings f JOIN repositories r ON r.id = f.repository_id WHERE f.analysis_run_id = ?"
        params: tuple[str, ...] = (run_id,)
        if session["id"] != "legacy":
            query += " AND r.user_id = ?"
            params += (session["user_id"],)
        query += " ORDER BY f.line"
        return [dict(row) for row in db.execute(query, params)]


@app.get("/activity")
def list_activity(session: dict[str, str] = Depends(current_session)) -> list[dict[str, Any]]:
    with connection() as db:
        if session["id"] == "legacy":
            return [dict(row) for row in db.execute("SELECT * FROM activity ORDER BY created_at DESC LIMIT 100")]
        return [dict(row) for row in db.execute("SELECT a.* FROM activity a JOIN repositories r ON r.id = a.entity_id WHERE r.user_id = ? OR a.entity_id IN (SELECT id FROM analysis_runs WHERE repository_id IN (SELECT id FROM repositories WHERE user_id = ?)) ORDER BY a.created_at DESC LIMIT 100", (session["user_id"], session["user_id"]))]


@app.get("/patches")
def list_patches() -> list[dict[str, Any]]:
    return []
