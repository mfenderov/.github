#!/usr/bin/env python3
"""Nightly audit: every owned repo must have the Gitleaks caller workflow.

Reads repos via `gh api` (GH_TOKEN must have repo read scope).
Writes Markdown report to REPORT_PATH (default report.md).
Never fails on missing coverage — findings go to the issue, not the exit code.
Only hard-fails when the GitHub API itself is unreachable.
"""
import json
import os
import subprocess
import sys

CALLER_PATHS = [
    ".github/workflows/gitleaks.yml",
    ".github/workflows/gitleaks.yaml",
    ".github/workflows/secret-scan.yml",
]
REPORT_PATH = os.environ.get("REPORT_PATH", "report.md")


def api(args):
    p = subprocess.run(
        ["gh", "api", *args], capture_output=True, text=True, timeout=60
    )
    if p.returncode != 0:
        print(f"API ERROR: gh api {' '.join(args)}: {p.stderr.strip()}", file=sys.stderr)
        raise SystemExit(2)
    return json.loads(p.stdout or "null")


def api_or_none(args):
    """Like api(), but returns None instead of exiting (for expected 404s)."""
    p = subprocess.run(
        ["gh", "api", *args], capture_output=True, text=True, timeout=60
    )
    if p.returncode != 0:
        return None
    return json.loads(p.stdout or "null")


def main():
    repos = api(["user/repos", "--paginate", "--jq", "[.[]]"])
    mine = [r for r in repos if r["full_name"].startswith("mfenderov/")]
    mine = [r for r in mine if not r["archived"]]

    missing_caller, unprotected_push, unprotected_branch, unavailable = [], [], [], []
    for r in sorted(mine, key=lambda x: x["name"]):
        owner, name = r["full_name"].split("/")
        if name == ".github":
            continue  # host of the shared workflows, no caller needed
        try:
            tree = api_or_none([f"repos/{owner}/{name}/contents/.github/workflows", "--jq", "[.[].name]"])
        except SystemExit:
            tree = None  # no .github/workflows dir at all
        if tree is None or not any(
            c.rsplit("/", 1)[-1] in tree for c in CALLER_PATHS
        ):
            missing_caller.append(name)

        # NOTE: the list endpoint omits security_and_analysis, fetch per repo.
        full = api([f"repos/{owner}/{name}", "--jq", "{sec: .security_and_analysis, private: .private, branch: .default_branch}"])
        sec = full.get("sec") or {}
        scan = (sec.get("secret_scanning") or {}).get("status")
        push = (sec.get("secret_scanning_push_protection") or {}).get("status")
        if full["private"]:
            unavailable.append(f"{name} secret scanning (needs GHAS)")
        elif push != "enabled":
            unprotected_push.append(name)

        if not full["private"]:
            prot = api_or_none([f"repos/{owner}/{name}/branches/{full['branch']}/protection", "--jq", "{force: .allow_force_pushes.enabled}"])
            if prot is None:
                unprotected_branch.append(f"{name} (no protection)")
        else:
            unavailable.append(f"{name} branch protection (needs Pro)")

    def bullets(items):
        return [f"- [ ] `{n}`" for n in items] or ["- none 🎉"]

    lines = [
        "## Secret-scan coverage audit",
        "",
        f"Repos checked: {len(mine)} (archived and non-owned excluded).",
        "",
        f"### Missing Gitleaks caller ({len(missing_caller)})",
        *bullets(missing_caller),
        "",
        f"### Push protection disabled ({len(unprotected_push)})",
        *bullets(unprotected_push),
        "",
        f"### Branch protection missing, public repos ({len(unprotected_branch)})",
        *bullets(unprotected_branch),
        "",
        "### Unavailable without paid plan (GHAS/Pro private repos)",
        *([f"- `{n}`" for n in sorted(set(unavailable))] or ["- none"]),
    ]
    with open(REPORT_PATH, "w") as f:
        f.write("\n".join(lines) + "\n")

    # Machine-readable outcome for the workflow step.
    print(f"MISSING_CALLER={len(missing_caller)}")
    print(f"UNPROTECTED_PUSH={len(unprotected_push)}")
    print(f"UNPROTECTED_BRANCH={len(unprotected_branch)}")
    problems = len(missing_caller) + len(unprotected_push) + len(unprotected_branch)
    print(f"PROBLEMS={problems}")
    with open(os.environ.get("GITHUB_OUTPUT", "/dev/null"), "a") as f:
        f.write(f"problems={problems}\n")


if __name__ == "__main__":
    main()
