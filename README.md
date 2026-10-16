# PatchPilot

PatchPilot is a security-focused repository analysis workspace for engineering teams. It connects to GitHub through OAuth, lets an authenticated user choose a repository, pins analysis to an exact commit, and presents deterministic findings for human review.



## Highlights

- Real GitHub OAuth web application flow with CSRF-resistant, expiring, single-use state.
- Server-side authenticated sessions with secure cookie settings.
- GitHub access tokens encrypted at rest and never exposed to browser storage.
- Authenticated repository discovery with pagination and private repository support.
- Repository metadata, branches, latest commits, and source retrieval pinned to a commit SHA.
- User-scoped repositories, analysis runs, findings, and activity records.
- Static analysis safeguards for excluded paths, binary files, unsupported extensions, file sizes, file counts, and total source size.
- Deterministic Python AST and pattern-based checks with redacted evidence.
- React dashboard for repository selection, analysis, findings, approvals, and activity.

## Architecture

```text
GitHub OAuth
     |
     v
React + TypeScript + Vite  <---- JSON/HTTP + secure cookies ---->  FastAPI
                                                                  |
                                                                  +-- GitHub API
                                                                  +-- SQLite
                                                                  +-- Static analysis
```

### Backend

The backend lives in [`backend/`](./backend) and provides:

- OAuth initiation, callback, session identity, and logout endpoints.
- Authenticated GitHub repository and source endpoints.
- Repository registration and commit-pinned analysis.
- SQLite persistence for users, encrypted credentials, sessions, repositories, runs, findings, and activity.

### Frontend

The frontend lives in [`frontend/`](./frontend) and provides:

- GitHub login screen.
- Authenticated account display and logout.
- Repository picker backed by the user's GitHub authorization.
- Analysis dashboard and finding review experience.

## Requirements

- Python 3.11+
- Node.js 18+
- npm
- A GitHub OAuth App for real login

## Local setup

### 1. Configure the backend

Create `backend/.env` from the example:

```powershell
Copy-Item backend\.env.example backend\.env
```

Create a GitHub OAuth App at <https://github.com/settings/developers>. Use this callback URL for local development:

```text
http://127.0.0.1:8000/auth/github/callback
```

Fill in `backend/.env`:

```env
GITHUB_CLIENT_ID=your_oauth_client_id
GITHUB_CLIENT_SECRET=your_oauth_client_secret
GITHUB_OAUTH_REDIRECT_URI=http://127.0.0.1:8000/auth/github/callback
SESSION_ENCRYPTION_KEY=your_fernet_key
GITHUB_API_BASE_URL=https://api.github.com
DATABASE_URL=sqlite:///./patchpilot.db
FRONTEND_ORIGIN=http://localhost:5173
BACKEND_ORIGIN=http://127.0.0.1:8000
```

Generate the encryption key after installing backend dependencies:

```powershell
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

The OAuth `repo` scope is used so a user can explicitly authorize access to private repositories. Do not commit `backend/.env`, client secrets, encryption keys, access tokens, or database files.

### 2. Install and run the backend

```powershell
Set-Location backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m uvicorn main:app --reload --host 127.0.0.1 --port 8000
```

Backend API documentation is available at <http://127.0.0.1:8000/docs>.

### 3. Install and run the frontend

In a second terminal:

```powershell
Set-Location frontend
npm install
npm run dev -- --host 127.0.0.1
```

Open <http://127.0.0.1:5173>.

The frontend uses `VITE_API_URL` when supplied; otherwise it defaults to `http://127.0.0.1:8000`.

## OAuth flow

1. The user selects **Login with GitHub**.
2. The backend creates a random state value, stores a hash and expiry server-side, and sets a short-lived HttpOnly state cookie.
3. GitHub redirects back to the backend callback.
4. The backend validates state, consumes it once, exchanges the code for an access token, and calls GitHub's authenticated-user API.
5. The token is encrypted and stored server-side; the browser receives only an application session cookie and CSRF cookie.
6. Repository and analysis requests use the server-side token and enforce the session's user ownership.

## Analysis workflow

1. Authenticate with GitHub.
2. Open **Repositories** and choose an authorized repository.
3. PatchPilot retrieves repository metadata and the default branch.
4. An analysis run resolves the selected branch to its current commit SHA.
5. The repository tree and supported source files are retrieved for that exact SHA.
6. Static analysis runs without executing downloaded source code.
7. Findings, statistics, commit SHA, and activity are persisted in SQLite.

## API overview

| Area | Endpoints |
| --- | --- |
| Health | `GET /`, `GET /health` |
| Authentication | `GET /auth/github`, `GET /auth/github/callback`, `GET /auth/me`, `POST /auth/logout` |
| GitHub | `GET /github/status`, `GET /github/repositories`, repository details, branches, commits, pinned source |
| Local repositories | `GET/POST /repositories`, `DELETE /repositories/{repository_id}` |
| Analysis | `POST /repositories/{repository_id}/analysis`, `GET /analysis`, `GET /analysis/{run_id}/findings` |
| Activity | `GET /activity` |

## Validation

Backend tests:

```powershell
Set-Location backend
.\.venv\Scripts\python.exe -m pytest tests\test_api.py -q
```

Frontend build:

```powershell
Set-Location frontend
npm run build
```

## Security notes

- OAuth client secrets and GitHub access tokens stay on the backend.
- Access tokens are encrypted with Fernet before SQLite persistence.
- Browser authentication uses HttpOnly session cookies.
- State-changing authenticated requests require the CSRF token issued with the session.
- Repository and analysis queries are scoped to the authenticated application user.
- Analysis never executes repository source code.
- Local environment files and SQLite databases are ignored by Git.

## Project layout

```text
PatchPilot/
├── backend/
│   ├── analysis_service.py
│   ├── github_service.py
│   ├── main.py
│   ├── requirements.txt
│   └── tests/
├── frontend/
│   ├── src/
│   ├── package.json
│   └── vite.config.ts
├── .env.example
├── .gitignore
└── README.md
```

## License

No license has been selected for this repository yet. Add an explicit license before distributing PatchPilot publicly.
