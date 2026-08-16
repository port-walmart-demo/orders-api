#!/usr/bin/env python3
"""Publish Snyk CLI JSON findings to Port as vulnerability entities.

Usage:
    PORT_CLIENT_ID=... PORT_CLIENT_SECRET=... PORT_SERVICE_ID=orders_api \\
      python3 scripts/snyk_to_port.py snyk.json

Each unique Snyk issue id becomes one vulnerability related to PORT_SERVICE_ID.
Re-running upserts in place (stable identifiers: snyk_<service>_<issueId>).
"""

from __future__ import annotations

import json
import os
import re
import sys
import urllib.error
import urllib.request

PORT_API = os.environ.get("PORT_API_BASE_URL", "https://api.getport.io").rstrip("/")
SERVICE_ID = os.environ.get("PORT_SERVICE_ID", "orders_api")


def die(msg: str, code: int = 1) -> None:
    print(f"ERROR: {msg}", file=sys.stderr)
    sys.exit(code)


def get_token() -> str:
    client_id = os.environ.get("PORT_CLIENT_ID")
    client_secret = os.environ.get("PORT_CLIENT_SECRET")
    if not client_id or not client_secret:
        die("set PORT_CLIENT_ID and PORT_CLIENT_SECRET")
    body = json.dumps({"clientId": client_id, "clientSecret": client_secret}).encode()
    req = urllib.request.Request(
        f"{PORT_API}/v1/auth/access_token",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode())["accessToken"]
    except urllib.error.HTTPError as exc:
        die(f"Port auth failed ({exc.code}): {exc.read().decode()}")


def upsert(token: str, entity: dict) -> None:
    identifier = entity["identifier"]
    data = json.dumps(entity).encode()
    req = urllib.request.Request(
        f"{PORT_API}/v1/blueprints/vulnerability/entities?upsert=true&merge=true",
        data=data,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            resp.read()
        print(f"  OK   {identifier}")
    except urllib.error.HTTPError as exc:
        die(f"upsert {identifier} failed ({exc.code}): {exc.read().decode()}")


def sanitize(issue_id: str) -> str:
    return re.sub(r"[^A-Za-z0-9_:.-]", "_", issue_id)


def unique_findings(raw: dict) -> list[dict]:
    seen: set[str] = set()
    out: list[dict] = []
    for vuln in raw.get("vulnerabilities") or []:
        issue_id = vuln.get("id") or ""
        if not issue_id or issue_id in seen:
            continue
        seen.add(issue_id)
        cves = (vuln.get("identifiers") or {}).get("CVE") or []
        severity = (vuln.get("severity") or "medium").lower()
        if severity not in {"low", "medium", "high", "critical"}:
            severity = "medium"
        out.append(
            {
                "identifier": f"snyk_{SERVICE_ID}_{sanitize(issue_id)}",
                "title": vuln.get("title") or issue_id,
                "icon": "Snyk",
                "properties": {
                    "severity": severity,
                    "issueId": issue_id,
                    "package": vuln.get("packageName") or vuln.get("name") or "",
                    "isFixable": bool(vuln.get("isUpgradable") or vuln.get("isPatchable")),
                    "cve": cves[0] if cves else "",
                },
                "relations": {"service": SERVICE_ID},
            }
        )
    return out


def main() -> None:
    if len(sys.argv) != 2:
        die("usage: snyk_to_port.py <snyk.json>")
    path = sys.argv[1]
    with open(path) as fh:
        raw = json.load(fh)
    if raw.get("error"):
        die(f"Snyk JSON is an error payload: {raw.get('message') or raw}")

    findings = unique_findings(raw)
    print(f"Publishing {len(findings)} unique Snyk issues to service '{SERVICE_ID}'")
    if not findings:
        print("No issues in report (Snyk ok:true). Nothing to upsert.")
        return

    token = get_token()
    for entity in findings:
        upsert(token, entity)
    print("Done.")


if __name__ == "__main__":
    main()
