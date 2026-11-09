"""Bounded service adapters. Importing this module makes no external calls."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from tools import capstone_release as release


class ServiceError(RuntimeError):
    def __init__(self, code: str, classification: str = "FAIL") -> None:
        super().__init__(code)
        self.code = code
        self.classification = classification


def command(args: list[str], root: Path, *, stdin: str | None = None, timeout: int = 60) -> str:
    executable = shutil.which(args[0])
    if executable is None:
        raise ServiceError("EXECUTABLE_UNAVAILABLE_" + args[0])
    try:
        result = subprocess.run(  # noqa: S603 -- argv, no shell; no captured error leakage
            [executable, *args[1:]],
            cwd=root,
            input=stdin,
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ServiceError("COMMAND_OUTCOME_UNKNOWN", "INDETERMINATE") from exc
    if result.returncode:
        raise ServiceError("COMMAND_FAILED_" + args[0])
    return result.stdout.strip()


def load_hcp_token() -> str:
    for name in ("TFC_TOKEN", "TF_TOKEN_app_terraform_io"):
        if os.environ.get(name, "").strip():
            return os.environ[name].strip()
    candidates = [Path.home() / ".terraform.d/credentials.tfrc.json"]
    if os.environ.get("APPDATA"):
        candidates.append(Path(os.environ["APPDATA"]) / "terraform.d/credentials.tfrc.json")
    for path in candidates:
        if path.is_file():
            value = (
                json.loads(path.read_bytes())
                .get("credentials", {})
                .get("app.terraform.io", {})
                .get("token")
            )
            if isinstance(value, str) and value.strip():
                return value.strip()
    raise ServiceError("HCP_TOKEN_UNAVAILABLE_USE_EXISTING_SECRET_ENVIRONMENT")


def relationship(item: dict[str, Any], name: str) -> str | None:
    return (item.get("relationships", {}).get(name, {}).get("data") or {}).get("id")


class Services:
    def __init__(self, root: Path, profile: str) -> None:
        self.root, self.profile = root, profile
        self.audit_path = root / "report" / "service-events" / (str(uuid.uuid4()) + ".jsonl")
        self.audit_path.parent.mkdir(parents=True, exist_ok=True)
        self.hcp_token = load_hcp_token()
        self.github_token: str = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN") or ""
        if not self.github_token:
            self.github_token = command(["gh", "auth", "token"], root)
        # Existing governed review/dispatch functions consume these in-process only.
        os.environ["TFC_TOKEN"] = self.hcp_token
        os.environ["GH_TOKEN"] = self.github_token

    def audit(self, service: str, method: str, phase: str) -> None:
        # Deliberately omit URL, body, headers and subprocess output, which may contain secrets.
        with self.audit_path.open("a", encoding="utf-8") as stream:
            stream.write(
                json.dumps(
                    {
                        "at": datetime.now(UTC).isoformat(),
                        "service": service,
                        "method": method,
                        "phase": phase,
                    }
                )
                + "\n"
            )

    def hcp(self, path: str, method: str = "GET", body: Any = None) -> Any:
        if not path.startswith("/") or path.startswith("//") or "://" in path:
            raise ServiceError("HCP_PATH_INVALID")
        self.audit("HCP", method, "START")
        result = release._hcp_request(method, path, self.hcp_token, body)[1]
        self.audit("HCP", method, "RETURNED")
        return result

    def github(self, path: str, method: str = "GET", body: Any = None) -> Any:
        self.audit("GITHUB", method, "START")
        result = release._github_request(method, path, self.github_token, body)[1]
        self.audit("GITHUB", method, "RETURNED")
        return result

    def hcp_pages(self, path: str) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = []
        seen: set[str] = set()
        while path:
            if path in seen or len(seen) >= 100:
                raise ServiceError("HCP_PAGINATION_LIMIT")
            seen.add(path)
            response = self.hcp(path)
            if not isinstance(response.get("data"), list):
                raise ServiceError("HCP_LIST_INVALID")
            result.extend(response["data"])
            next_link = response.get("links", {}).get("next")
            if next_link:
                parsed = urlsplit(next_link)
                if parsed.netloc and (parsed.scheme, parsed.netloc) != (
                    "https",
                    "app.terraform.io",
                ):
                    raise ServiceError("HCP_PAGINATION_HOST")
                path = parsed.path.removeprefix("/api/v2")
                if parsed.query:
                    path += "?" + parsed.query
            else:
                path = ""
        return result

    def github_pages(self, path: str, key: str) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = []
        for page in range(1, 101):
            separator = "&" if "?" in path else "?"
            response = self.github(f"{path}{separator}per_page=100&page={page}")
            entries = response if key == "" else response[key]
            if not isinstance(entries, list):
                raise ServiceError("GITHUB_LIST_INVALID")
            result.extend(entries)
            if len(entries) < 100:
                return result
        raise ServiceError("GITHUB_PAGINATION_LIMIT")

    def aws(self, *args: str) -> dict[str, Any]:
        raw = command(
            [
                "aws",
                *args,
                "--profile",
                self.profile,
                "--region",
                "ap-southeast-1",
                "--output",
                "json",
                "--no-cli-pager",
            ],
            self.root,
        )
        return json.loads(raw) if raw else {}

    def current_state(self, workspace: str) -> dict[str, Any]:
        # A 404 is not evidence of an empty state. Ask the state listing as well.
        try:
            item = self.hcp(f"/workspaces/{workspace}/current-state-version")["data"]
        except release.ReleaseError as exc:
            if exc.code != "HCP_HTTP_404":
                raise
            from urllib.parse import quote

            name = self.hcp(f"/workspaces/{workspace}")["data"]["attributes"]["name"]
            org = release._config()["hcp_organization"]
            states = self.hcp_pages(
                f"/state-versions?filter[organization][name]={quote(org)}"
                f"&filter[workspace][name]={quote(name)}&page[size]=100"
            )
            if states:
                raise ServiceError("CURRENT_STATE_UNAVAILABLE", "INDETERMINATE") from exc
            return {"id": None, "lineage": None, "serial": None}
        if item.get("attributes", {}).get("status") != "finalized":
            raise ServiceError("STATE_NOT_FINALIZED")
        exact, lineage, serial = release._hcp_state_identity(item["id"], self.hcp_token, state=item)
        return {"id": exact["id"], "lineage": lineage, "serial": serial}

    def resources(self, workspace: str) -> list[dict[str, Any]]:
        state = self.current_state(workspace)
        if state["id"] is None:
            return []
        metadata = self.hcp(f"/state-versions/{state['id']}")["data"]
        if metadata["attributes"].get("resources-processed") is not True:
            raise ServiceError("STATE_RESOURCES_STILL_PROCESSING", "INDETERMINATE")
        resources = self.hcp_pages(f"/workspaces/{workspace}/resources?page[size]=100")
        if self.current_state(workspace) != state:
            raise ServiceError("STATE_CHANGED_DURING_RESOURCE_INVENTORY")
        return resources

    def configuration(self, workspace: str, commit: str) -> str:
        versions = self.hcp_pages(f"/workspaces/{workspace}/configuration-versions?page[size]=100")
        candidates: list[str] = []
        for item in versions:
            if item.get("attributes", {}).get("status") != "uploaded":
                continue
            response = self.hcp(f"/configuration-versions/{item['id']}?include=ingress_attributes")
            data = response["data"]
            ingress = relationship(data, "ingress-attributes")
            bound = [v for v in response.get("included", []) if v.get("id") == ingress]
            sha = data.get("attributes", {}).get("vcs-commit-sha")
            if not sha and len(bound) == 1:
                sha = bound[0]["attributes"].get("commit-sha")
            if sha == commit and data["attributes"].get("speculative") is False:
                candidates.append(data["id"])
        if len(candidates) != 1:
            raise ServiceError("EXACT_VCS_CONFIGURATION_MISSING_OR_AMBIGUOUS")
        return candidates[0]
