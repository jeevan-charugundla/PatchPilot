import ast
import re
from datetime import datetime, timezone
from typing import Any

if __package__:
    from .github_service import GitHubClient, GitHubError
else:
    from github_service import GitHubClient, GitHubError

EXCLUDED = (".git/", "node_modules/", "dist/", "build/", "vendor/", "__pycache__/", ".venv/")
MAX_FILE_BYTES = 500_000
MAX_FILES = 300
MAX_TOTAL_BYTES = 10_000_000


def analyze_repository(client: GitHubClient, owner: str, name: str, commit_sha: str, run_id: str, repository_id: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    tree = client.tree(owner, name, commit_sha).get("tree", [])
    findings: list[dict[str, Any]] = []
    stats: dict[str, Any] = {"files_discovered": 0, "files_analyzed": 0, "files_skipped": 0, "skip_reasons": []}
    total_bytes = 0
    for item in tree:
        path = item.get("path", "")
        if item.get("type") != "blob" or any(path.startswith(prefix) for prefix in EXCLUDED):
            continue
        stats["files_discovered"] += 1
        size = int(item.get("size") or 0)
        if len(stats["skip_reasons"]) >= MAX_FILES or size > MAX_FILE_BYTES or total_bytes + size > MAX_TOTAL_BYTES:
            stats["files_skipped"] += 1
            stats["skip_reasons"].append({"path": path, "reason": "analysis_limit" if len(stats["skip_reasons"]) >= MAX_FILES else "oversized_or_total_limit"})
            continue
        if not path.endswith((".py", ".js", ".jsx", ".ts", ".tsx", ".json", ".yml", ".yaml", ".env.example")):
            stats["files_skipped"] += 1
            stats["skip_reasons"].append({"path": path, "reason": "unsupported_text_extension"})
            continue
        try:
            source = client.content(owner, name, path, commit_sha)
        except (GitHubError, UnicodeDecodeError):
            stats["files_skipped"] += 1
            stats["skip_reasons"].append({"path": path, "reason": "unreadable_or_binary"})
            continue
        total_bytes += len(source.encode("utf-8"))
        stats["files_analyzed"] += 1
        findings.extend(_python_findings(source, path, repository_id, run_id, commit_sha))
        findings.extend(_pattern_findings(source, path, repository_id, run_id, commit_sha))
    return findings, stats


def _finding(repository_id: str, run_id: str, sha: str, path: str, line: int, rule: str, category: str, severity: str, title: str, explanation: str, evidence: str, confidence: str) -> dict[str, Any]:
    safe_evidence = re.sub(r"(?i)(token|password|secret|api[_-]?key)\s*=\s*[^\s,;]+", r"\1=<redacted>", evidence)[:500]
    return {"id": f"{run_id}:{rule}:{path}:{line}", "repository_id": repository_id, "analysis_run_id": run_id, "commit_sha": sha, "file": path, "line": line, "column": 1, "rule_id": rule, "category": category, "severity": severity, "title": title, "explanation": explanation, "evidence": safe_evidence, "analyzer": "patchpilot-rules", "analyzer_version": "0.2.0", "confidence": confidence, "created_at": datetime.now(timezone.utc).isoformat()}


def _python_findings(source: str, path: str, repository_id: str, run_id: str, sha: str) -> list[dict[str, Any]]:
    if not path.endswith(".py"):
        return []
    try:
        tree = ast.parse(source, filename=path)
    except SyntaxError as exc:
        return [_finding(repository_id, run_id, sha, path, exc.lineno or 1, "PY001", "Syntax", "High", "Python syntax error", str(exc), source.splitlines()[max((exc.lineno or 1) - 1, 0)], "Certain")]
    results = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in {"eval", "exec"}:
            results.append(_finding(repository_id, run_id, sha, path, node.lineno, "PY002", "Dynamic execution", "High", "Dynamic code execution", "Dynamic execution makes control flow depend on runtime input and requires careful validation.", ast.get_source_segment(source, node) or node.func.id, "High"))
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "run":
            if any(keyword.arg == "shell" and isinstance(keyword.value, ast.Constant) and keyword.value.value is True for keyword in node.keywords):
                results.append(_finding(repository_id, run_id, sha, path, node.lineno, "PY003", "Subprocess", "Medium", "Shell-enabled subprocess call", "This heuristic identifies shell=True; determine whether command inputs are trusted before treating it as a vulnerability.", ast.get_source_segment(source, node) or "subprocess.run(...)", "Medium"))
    return results


def _pattern_findings(source: str, path: str, repository_id: str, run_id: str, sha: str) -> list[dict[str, Any]]:
    results = []
    patterns = [(r"(?i)(password|secret|api[_-]?key|token)\s*[:=]\s*[\"'][^\"']{8,}[\"']", "GEN001", "Credentials", "High", "Potential hardcoded credential", "A credential-like value appears in source. The value is redacted in stored evidence; rotate it if it is real.", "High")]
    for line_number, line in enumerate(source.splitlines(), 1):
        for pattern, rule, category, severity, title, explanation, confidence in patterns:
            if re.search(pattern, line):
                results.append(_finding(repository_id, run_id, sha, path, line_number, rule, category, severity, title, explanation, line, confidence))
    return results
