#!/usr/bin/env python3
"""Cycode release gate: go / no-go for one repository branch.

No scan runs in the pipeline. The gate only reads platform results through the Cycode API:

  1. Scan status   Wait until the platform has finished scanning the branch.
  2. Thresholds    Read the security team's thresholds from Cycode: the PR status-check
                   minimum severity set on the Cycode project, per scanner. Each gated
                   scanner must use Project Settings on that project. SCA dependencies and
                   SCA licenses each have their own threshold.
  3. Violations    Count open violations on the branch at or above each threshold.
                   Secrets are matched to the branch by commit history. See --secrets-by.

Exit codes
  0  GO      every gated scanner has zero open violations at or above its threshold
  1  NO-GO   blocking violations found
  2  NO-GO   the gate could not evaluate (scan missing or failed, threshold not set, API error)

A missing or failed required scan, a missing threshold or an API error is a no-go.

Notes
  - Cycode gives no signal that findings are fully published. A scan can report Completed
    before its findings appear as violations, and counts can change for several minutes while
    findings are ingested. The gate waits a minimum time after the push (--pushed-at, --min-age)
    and then requires the counts to stay unchanged for --stable-seconds.
  - SCA and IaC record a scan of the branch, which the gate waits for. SAST and Secrets scans
    of a push leave no scan record. --trigger-scans sast requests a full SAST scan of the
    branch and waits for it.
  - --trigger-scans does not accept secrets. An on-demand Secrets scan covers the whole
    repository, not one branch.
  - Cycode records a secret against the commit that added it and the branch where that commit
    was first pushed. A release branch that shares history with an earlier branch holds the
    same secrets. The gate therefore lists the repository's open secrets and keeps those whose
    commit is in the branch's history, which it asks GitHub (GITHUB_TOKEN or GH_TOKEN).

Python standard library only. Credentials come from CYCODE_CLIENT_ID / CYCODE_CLIENT_SECRET.
"""
import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

API = os.environ.get("CYCODE_API_URL", "https://api.cycode.com").rstrip("/")
GITHUB_API = os.environ.get("GITHUB_API_URL", "https://api.github.com").rstrip("/")
SEVERITIES = ["Info", "Low", "Medium", "High", "Critical"]  # ascending
# gate key -> (PR settings scan_type, scans API scan_type, violations API category, display name)
SCANNERS = {
    "secrets": ("Secrets", "Secrets", "SecretDetection", "Secrets"),
    "sca": ("SCA", "SCA", "SCA", "SCA dependencies"),
    "licenses": ("Licenses", "SCA", "SCA", "SCA licenses"),
    "sast": ("SAST", "SAST", "SAST", "SAST"),
    "iac": ("InfraConfiguration", "InfraConfiguration", "IaC", "IaC"),
}
SCA_KEYS = ("sca", "licenses")              # one violations category, two thresholds
LICENSE_SUB_CATEGORY = "License Compliance"  # sub_category_v2 of a license finding
IN_PROGRESS = {"Pending", "Running", "Analyzing", "PendingArtifact"}


class GateError(Exception):
    """The gate cannot produce a trustworthy answer. Always a no-go."""


class Api:
    def __init__(self):
        self.client_id = os.environ.get("CYCODE_CLIENT_ID", "")
        self.secret = os.environ.get("CYCODE_CLIENT_SECRET", "")
        if not self.client_id or not self.secret:
            raise GateError("CYCODE_CLIENT_ID and CYCODE_CLIENT_SECRET must be set")
        self.token = None

    def _auth(self):
        body = json.dumps({"clientId": self.client_id, "secret": self.secret}).encode()
        last = "no response"
        for attempt in range(4):
            req = urllib.request.Request(API + "/api/v1/auth/api-token", data=body, method="POST",
                                         headers={"Content-Type": "application/json"})
            try:
                with urllib.request.urlopen(req, timeout=30) as r:
                    self.token = json.load(r)["token"]
                    return
            except urllib.error.HTTPError as e:   # never echo the request body
                last = f"HTTP {e.code}"
                if e.code in (400, 401, 403):     # bad credentials: retrying will not help
                    break
            except Exception as e:
                last = type(e).__name__
            time.sleep(5 * (attempt + 1))
        raise GateError(f"Cycode authentication failed ({last})")

    def call(self, method, path, params=None, body=None, ok=(200,)):
        url = API + path + ("?" + urllib.parse.urlencode(params) if params else "")
        for attempt in range(5):
            if not self.token:
                self._auth()
            req = urllib.request.Request(
                url, method=method, data=(json.dumps(body).encode() if body is not None else None),
                headers={"Authorization": "Bearer " + self.token, "Content-Type": "application/json"})
            try:
                with urllib.request.urlopen(req, timeout=60) as r:
                    raw, code = r.read().decode(), r.status
            except urllib.error.HTTPError as e:
                raw, code = e.read().decode(errors="replace"), e.code
            except urllib.error.URLError as e:
                raw, code = str(e.reason), 599
            if code == 401:          # token expired mid-wait
                self.token = None
                continue
            if code in (429, 502, 503, 504, 599):
                time.sleep(5 * (attempt + 1))
                continue
            if code not in ok:
                return code, raw
            try:
                return code, json.loads(raw) if raw else None
            except ValueError:
                return code, raw
        raise GateError(f"{method} {path} kept failing (last HTTP {code})")


class History:
    """Is a commit in the branch's history? Answered by GitHub's compare API, once per commit."""

    def __init__(self, repo_name, branch):
        self.token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN") or ""
        self.repo, self.branch, self.cache = repo_name or "", branch, {}
        if not self.token or self.repo.count("/") != 1:
            raise GateError("matching Secrets by commit history needs --repo-name owner/repo and a GitHub token in "
                            "GITHUB_TOKEN or GH_TOKEN. --secrets-by branch counts by the recorded branch instead")
        # The branch must resolve, or a 404 from compare could not be read as "commit not in this branch".
        code, _ = self._get(f"/repos/{self.repo}/git/ref/heads/{urllib.parse.quote(branch)}")
        if code != 200:
            raise GateError(f"GitHub could not find branch {branch} in {self.repo} (HTTP {code})")

    def _get(self, path):
        code = 599
        for attempt in range(4):
            req = urllib.request.Request(GITHUB_API + path, headers={
                "Authorization": "Bearer " + self.token, "Accept": "application/vnd.github+json"})
            try:
                with urllib.request.urlopen(req, timeout=60) as r:
                    return r.status, json.load(r)
            except urllib.error.HTTPError as e:
                code = e.code
                if code not in (403, 429, 500, 502, 503, 504):
                    return code, None
            except urllib.error.URLError:
                code = 599
            time.sleep(5 * (attempt + 1))
        raise GateError(f"GitHub API kept failing (last HTTP {code})")

    def contains(self, commit):
        if commit not in self.cache:
            q = urllib.parse.quote
            code, data = self._get(f"/repos/{self.repo}/compare/{q(commit, safe='')}...{q(self.branch, safe='')}?per_page=1")
            if code == 200:
                self.cache[commit] = (data or {}).get("status") in ("ahead", "identical")
            elif code == 404:  # the commit is not in the repository, or shares no history with the branch
                self.cache[commit] = False
            else:
                raise GateError(f"GitHub could not compare a commit with branch {self.branch} (HTTP {code})")
        return self.cache[commit]


def at_or_above(threshold):
    return SEVERITIES[SEVERITIES.index(threshold):]


def read_thresholds(api, project_id, scanners):
    """Thresholds live in Cycode: the PR status-check minimum severity set on the project, per scanner."""
    code, data = api.call("GET", f"/v4/scans/pull-request-scoped-settings/Project/{project_id}")
    if code == 404:
        raise GateError(f"no PR scanning settings found for Cycode project {project_id}. "
                        "Check the project ID and set the PR settings on the project")
    if code != 200 or not isinstance(data, dict):
        raise GateError(f"could not read the PR scanning settings of Cycode project {project_id} (HTTP {code})")
    by_type = {s.get("scan_type"): s for s in data.get("scan_type_settings", [])}
    out = {}
    for key in scanners:
        scan_type, name = SCANNERS[key][0], SCANNERS[key][3]
        s = by_type.get(scan_type)
        if not s or s.get("selected_scope_type", "Project") != "Project":
            raise GateError(f"{name} is not set on Cycode project {project_id}. In the project's PR settings, "
                            f"select Project Settings for {name} and set its status check severity")
        sev = s.get("status_check_minimum_severity")
        if not s.get("is_enabled") or sev not in SEVERITIES:
            raise GateError(f"{name} uses project settings on Cycode project {project_id}, "
                            "but PR scanning is off or no severity threshold is set")
        out[key] = sev
    return out


def latest_scans(api, repo_id, branch):
    """Latest platform scan per scan type for this branch. Branch scans are hidden by default."""
    scans, token = [], None
    while True:
        params = [("entity_id", repo_id), ("branch_name", branch), ("include_hidden", "true"), ("page_size", 100)]
        if token:
            params.append(("next_page_token", token))
        code, data = api.call("GET", "/v4/scans", params)
        if code != 200 or not isinstance(data, dict):
            raise GateError(f"could not read scan status (HTTP {code})")
        scans += data.get("items", [])
        token = data.get("next_page_token")
        if not token or not data.get("items"):
            break
    latest = {}
    for s in scans:
        t = s.get("scan_type")
        if t not in latest or (s.get("started_at") or "") > (latest[t].get("started_at") or ""):
            latest[t] = s
    return latest


def trigger_scans(api, repo_id, branch, scanners):
    """Optional: ask Cycode to scan the branch now instead of relying on branch scanning rules."""
    for scan_type in dict.fromkeys(SCANNERS[key][1] for key in scanners):
        body = {"scan_type": scan_type, "entity_type": "Repository", "entity_id": repo_id, "branch_name": branch}
        code, data = api.call("POST", "/v4/scans", body=body, ok=(200, 201, 202))
        print(f"  on-demand {scan_type} scan requested: HTTP {code} {str(data)[:120]}")
        if code not in (200, 201, 202):
            raise GateError(f"could not trigger the {scan_type} scan (HTTP {code})")


def wait_for_scans(api, repo_id, branch, required, timeout, interval, not_before):
    deadline = time.time() + timeout
    while True:
        latest = latest_scans(api, repo_id, branch)
        state = {}
        for key in required:
            s = latest.get(SCANNERS[key][1])
            marker = not_before.get(SCANNERS[key][1])
            if s and marker and (s.get("started_at") or "") < marker:
                s = None  # a scan from before the marker does not count
            state[key] = (s or {}).get("scan_status") or "NotFound"
        line = ", ".join(f"{SCANNERS[k][3]}={v}" for k, v in state.items()) or "none required"
        print(f"  scan status: {line}", flush=True)
        if any(v == "Error" for v in state.values()):
            raise GateError(f"a platform scan of this branch failed ({line})")
        if all(v == "Completed" for v in state.values()):
            return latest
        if time.time() >= deadline:
            raise GateError(f"platform scans did not complete within {timeout}s ({line})")
        time.sleep(interval)


def count(api, repo_id, branch, category, severity=None, status="Open"):
    """branch=None counts across the whole repository."""
    params = [("repository_ids", repo_id), ("category", category)]
    if branch:
        params.append(("branches", branch))
    if status:
        params.append(("status", status))
    if severity:
        params.append(("severity", severity))
    code, data = api.call("GET", "/v4/violations/count", params)
    if code != 200 or not isinstance(data, dict) or "count" not in data:
        raise GateError(f"could not count {category} violations (HTTP {code})")
    return int(data["count"])


def sca_open_by_kind(api, repo_id, branch):
    """Open SCA findings split into dependencies and licenses. The count endpoint cannot split them."""
    out = {key: dict.fromkeys(SEVERITIES, 0) for key in SCA_KEYS}
    seen, token = set(), None
    while True:
        params = [("repository_ids", repo_id), ("category", "SCA"), ("status", "Open"), ("page_size", 100)]
        if branch:
            params.append(("branches", branch))
        if token:
            params.append(("next_page_token", token))
        code, data = api.call("GET", "/v4/violations", params)
        if code != 200 or not isinstance(data, dict):
            raise GateError(f"could not list SCA violations (HTTP {code})")
        for v in data.get("items", []):
            if v.get("id") in seen:
                continue
            seen.add(v.get("id"))
            key = "licenses" if v.get("sub_category_v2") == LICENSE_SUB_CATEGORY else "sca"
            if v.get("severity") in SEVERITIES:
                out[key][v["severity"]] += 1
        token = data.get("next_page_token")
        if not token or not data.get("items"):
            break
    return out, len(seen)


def secrets_open_in_history(api, repo_id, branch, history):
    """Open secrets in the repository whose commit is in the branch's history, per severity.

    Returns (per severity, secrets listed, secrets that could not be placed).
    """
    out, seen, unplaced, token = dict.fromkeys(SEVERITIES, 0), set(), 0, None
    while True:
        params = [("repository_ids", repo_id), ("category", "SecretDetection"), ("status", "Open"), ("page_size", 100)]
        if token:
            params.append(("next_page_token", token))
        code, data = api.call("GET", "/v4/violations", params)
        if code != 200 or not isinstance(data, dict):
            raise GateError(f"could not list Secrets violations (HTTP {code})")
        for v in data.get("items", []):
            if v.get("id") in seen:
                continue
            seen.add(v.get("id"))
            details = v.get("detection_details") or {}
            if details.get("commit_id"):
                here = history.contains(details["commit_id"])
            elif details.get("branch_name"):
                here = details["branch_name"] == branch
            else:  # no commit and no branch: it cannot be placed, so it counts
                here, unplaced = True, unplaced + 1
            if here and v.get("severity") in SEVERITIES:
                out[v["severity"]] += 1
        token = data.get("next_page_token")
        if not token or not data.get("items"):
            break
    return out, len(seen), unplaced


def read_counts(api, repo_id, branch, gated, repo_scope=(), history=None):
    """Open violations per severity, plus violations in any status, for each gated scanner.

    Scanners in repo_scope are counted across the whole repository instead of the branch.
    With history, Secrets are the repository's open secrets whose commit is in the branch's history.
    Returns (counts, consistent). consistent is False when a list and its count disagree,
    which happens while findings are being ingested.
    """
    out, consistent = {}, True
    if any(key in SCA_KEYS for key in gated):
        split, listed = sca_open_by_kind(api, repo_id, branch)
        consistent = listed == count(api, repo_id, branch, "SCA")
        any_status = count(api, repo_id, branch, "SCA", status=None)
        for key in gated:
            if key in SCA_KEYS:
                out[key] = {"open": split[key], "any_status": any_status}
    for key in gated:
        if key == "secrets" and history and key not in repo_scope:
            by_severity, listed, unplaced = secrets_open_in_history(api, repo_id, branch, history)
            consistent = consistent and listed == count(api, repo_id, None, "SecretDetection")
            out[key] = {"open": by_severity, "any_status": count(api, repo_id, None, "SecretDetection", status=None),
                        "repository_open": listed, "unplaced": unplaced}
        elif key not in SCA_KEYS:
            category, where = SCANNERS[key][2], (None if key in repo_scope else branch)
            out[key] = {"open": {sev: count(api, repo_id, where, category, sev) for sev in SEVERITIES},
                        "any_status": count(api, repo_id, where, category, status=None)}
    return out, consistent


def settled_counts(api, repo_id, branch, gated, latest, deadline, interval, readings, stable_seconds,
                   repo_scope=(), history=None):
    """Read counts until they are published and have stayed unchanged for stable_seconds."""
    previous, streak, since = None, 0, time.time()
    while True:
        counts, consistent = read_counts(api, repo_id, branch, gated, repo_scope, history)
        unpublished = sorted({SCANNERS[k][1] for k in gated
                              if ((latest.get(SCANNERS[k][1]) or {}).get("results_count") or 0) > 0
                              and counts[k]["any_status"] == 0})
        if consistent and counts == previous:
            streak += 1
        else:
            streak, since = (1 if consistent else 0), time.time()
        if not unpublished and streak >= readings and time.time() - since >= stable_seconds:
            return counts
        if time.time() >= deadline:
            why = (f"scan results for {', '.join(unpublished)} are not published as violations yet"
                   if unpublished else "violation counts were still changing")
            raise GateError(f"{why} when the wait ended")
        note = f"waiting for {', '.join(unpublished)} findings to be published" if unpublished else "confirming counts are stable"
        print(f"  {note}", flush=True)
        previous = counts if consistent else None
        time.sleep(interval)


def wait_min_age(pushed_at, min_age, deadline):
    """Secrets push scans have no per-branch record, so give the platform a minimum time after the push."""
    import datetime
    try:
        t = datetime.datetime.fromisoformat(pushed_at.replace("Z", "+00:00")).timestamp()
    except ValueError:
        raise GateError(f"--pushed-at is not an ISO timestamp: {pushed_at}") from None
    remaining = t + min_age - time.time()
    if remaining > 0:
        if time.time() + remaining > deadline:
            raise GateError(f"the branch was pushed less than {min_age}s ago and the wait would exceed the timeout")
        print(f"  branch pushed {int(time.time() - t)}s ago, waiting {int(remaining)}s more before evaluating", flush=True)
        time.sleep(remaining)


def write_summary(path, title, rows, result, reason, project_id, note=""):
    lines = [f"## Cycode release gate: {result}", "", title, "",
             f"Thresholds read from Cycode: the PR settings of project `{project_id}`. "
             "Counts are open violations on this branch.", "",
             "| Scanner | Threshold | Platform scan | Critical | High | Medium | Low | Info | Blocking |",
             "|---|---|---|---|---|---|---|---|---|"]
    for r in rows:
        c = r["counts"]
        lines.append(f"| {r['name']} | {r['threshold']} and above | {r['scan']} | "
                     f"{c['Critical']} | {c['High']} | "
                     f"{c['Medium']} | {c['Low']} | {c['Info']} | **{r['blocking']}** |")
    lines += ["", reason, ""] + ([note, ""] if note else [])
    with open(path, "a", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")


def main():
    env = os.environ.get
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--repo-id", default=env("GATE_REPO_ID"), help="SCM repository ID. GitHub: the GraphQL node ID (R_kgDO...).")
    ap.add_argument("--repo-name", default=env("GATE_REPO_NAME", ""), help="Display only, e.g. org/repo.")
    ap.add_argument("--branch", default=env("GATE_BRANCH"), help="Release branch to evaluate.")
    ap.add_argument("--project-id", default=env("GATE_PROJECT_ID"), help="Cycode project whose PR thresholds define the gate. Each gated scanner must use Project Settings there.")
    ap.add_argument("--scanners", default=env("GATE_SCANNERS", "secrets,sca,licenses,sast,iac"),
                    help="Thresholds that can block. sca is SCA dependencies, licenses is SCA licenses.")
    ap.add_argument("--require-scans", default=env("GATE_REQUIRE_SCANS", "sca,iac"),
                    help="Scanners that must show a completed platform scan of the branch. Empty to skip the wait. "
                         "SCA and IaC record a scan when a branch matching their branch rules is created. "
                         "SAST and Secrets push scans leave no scan record. A requested SAST scan does.")
    ap.add_argument("--trigger-scans", default=env("GATE_TRIGGER_SCANS", ""),
                    help="Optional. Scanners to scan on demand before waiting: sast, sca, iac. "
                         "secrets is not accepted: an on-demand Secrets scan covers the whole repository, not one branch.")
    ap.add_argument("--wait-timeout", type=int, default=int(env("GATE_WAIT_TIMEOUT", "2700")))
    ap.add_argument("--poll-interval", type=int, default=int(env("GATE_POLL_INTERVAL", "30")))
    ap.add_argument("--not-before", default=env("GATE_NOT_BEFORE", ""),
                    help="Optional ISO timestamp. Ignore scans that started before it.")
    ap.add_argument("--pushed-at", default=env("GATE_PUSHED_AT", ""),
                    help="Optional ISO timestamp of the push that created the branch.")
    ap.add_argument("--min-age", type=int, default=int(env("GATE_MIN_AGE", "1200")),
                    help="With --pushed-at: do not evaluate until this many seconds after the push.")
    ap.add_argument("--stable-readings", type=int, default=int(env("GATE_STABLE_READINGS", "3")),
                    help="Consecutive identical readings of the counts required before answering.")
    ap.add_argument("--stable-seconds", type=int, default=int(env("GATE_STABLE_SECONDS", "300")),
                    help="The counts must also stay unchanged for this long before answering.")
    ap.add_argument("--repository-scope", default=env("GATE_REPOSITORY_SCOPE", ""),
                    help="Optional. Scanners counted across the whole repository instead of the branch, "
                         "for example secrets.")
    ap.add_argument("--secrets-by", default=env("GATE_SECRETS_BY", "history"),
                    help="history (default): open secrets in the repository whose commit is in the branch's history. "
                         "Needs --repo-name owner/repo and a GitHub token in GITHUB_TOKEN or GH_TOKEN. "
                         "branch: open secrets Cycode records against the branch, which leaves out secrets "
                         "the branch inherited from an earlier branch.")
    ap.add_argument("--json-out", default=env("GATE_JSON_OUT", ""), help="Optional path for a machine-readable result.")
    a = ap.parse_args()

    def keys(csv):
        ks = [k.strip().lower() for k in (csv or "").split(",") if k.strip()]
        bad = [k for k in ks if k not in SCANNERS]
        if bad:
            ap.error(f"unknown scanner(s): {', '.join(bad)}. Choose from {', '.join(SCANNERS)}")
        return ks

    for name in ("repo_id", "branch", "project_id"):
        if not getattr(a, name):
            ap.error(f"--{name.replace('_', '-')} is required")
    gated, required, triggered = keys(a.scanners), keys(a.require_scans), keys(a.trigger_scans)
    repo_scope = [k for k in keys(a.repository_scope) if k not in SCA_KEYS]
    if a.secrets_by not in ("history", "branch"):
        ap.error("--secrets-by must be history or branch")
    by_history = a.secrets_by == "history" and "secrets" in gated and "secrets" not in repo_scope
    if "secrets" in triggered:  # that scan is repository-wide, so it cannot answer for one branch
        ap.error("--trigger-scans secrets is not supported. An on-demand Secrets scan covers the whole repository, "
                 "not one branch")
    title = f"`{a.repo_name or a.repo_id}` at branch `{a.branch}`"
    print(f"Cycode release gate: {a.repo_name or a.repo_id} @ {a.branch}")
    rows, result, reason, code, note = [], "NO-GO", "", 2, ""
    try:
        api = Api()
        history = History(a.repo_name, a.branch) if by_history else None
        thresholds = read_thresholds(api, a.project_id, gated)
        print("  thresholds from Cycode project " + str(a.project_id) + ": " +
              ", ".join(f"{SCANNERS[k][3]}>={v}" for k, v in thresholds.items()))
        # scan type -> earliest start time that counts
        not_before = {SCANNERS[k][1]: a.not_before for k in SCANNERS} if a.not_before else {}
        if triggered:
            now = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(time.time() - 5))
            for key in triggered:  # a requested scan must be waited for, and an older one does not count
                not_before[SCANNERS[key][1]] = max(not_before.get(SCANNERS[key][1], ""), now)
            required = list(dict.fromkeys(required + triggered))
            trigger_scans(api, a.repo_id, a.branch, triggered)
        deadline = time.time() + a.wait_timeout
        if a.pushed_at:
            wait_min_age(a.pushed_at, a.min_age, deadline)
        latest = wait_for_scans(api, a.repo_id, a.branch, required, max(0, int(deadline - time.time())),
                                a.poll_interval, not_before) \
            if required else latest_scans(api, a.repo_id, a.branch)
        settled = settled_counts(api, a.repo_id, a.branch, gated, latest, deadline, a.poll_interval,
                                 max(2, a.stable_readings), max(0, a.stable_seconds), repo_scope, history)
        if by_history:
            s = settled["secrets"]
            note = (f"Secrets: {sum(s['open'].values())} of the repository's {s['repository_open']} open secrets "
                    "are on commits in this branch's history.")
            if s["unplaced"]:
                note += f" {s['unplaced']} carry no commit or branch and are counted."
        for key in gated:
            _, scan_type, _, name = SCANNERS[key]
            counts = settled[key]["open"]
            threshold = thresholds[key]
            blocking = sum(counts[s] for s in at_or_above(threshold))
            scan = (latest.get(scan_type) or {}).get("scan_status") or "No branch scan record"
            rows.append({"scanner": key, "name": name + (" (repo)" if key in repo_scope else ""),
                         "threshold": threshold, "scan": scan,
                         "counts": counts, "blocking": blocking})
        total = sum(r["blocking"] for r in rows)
        if total == 0:
            result, code = "GO", 0
            reason = "No open violations at or above the thresholds."
        else:
            code = 1
            reason = "Blocking violations: " + ", ".join(f"{r['blocking']} {r['name']}" for r in rows if r["blocking"]) + "."
    except GateError as e:
        reason = f"Gate could not evaluate: {e}"

    if rows:
        print(f"\n  {'Scanner':16} {'Threshold':10} {'Scan':24} {'Crit':>5} {'High':>5} {'Med':>5} {'Low':>5} {'Info':>5} {'Blocking':>9}")
        for r in rows:
            c = r["counts"]
            print(f"  {r['name']:16} {r['threshold']:10} {r['scan']:24} "
                  f"{c['Critical']:>5} {c['High']:>5} {c['Medium']:>5} "
                  f"{c['Low']:>5} {c['Info']:>5} {r['blocking']:>9}")
    if note:
        print(f"\n  {note}")
    print(f"\nResult: {result}. {reason}")

    out = {"result": result, "exit_code": code, "reason": reason, "repository_id": a.repo_id, "branch": a.branch,
           "project_id": str(a.project_id), "secrets_by": "repository" if "secrets" in repo_scope else a.secrets_by,
           "scanners": rows}
    if a.json_out:
        with open(a.json_out, "w", encoding="utf-8") as fh:
            json.dump(out, fh, indent=2)
    if env("GITHUB_STEP_SUMMARY"):
        write_summary(env("GITHUB_STEP_SUMMARY"), title, rows, result, reason, a.project_id, note)
    if env("GITHUB_OUTPUT"):
        with open(env("GITHUB_OUTPUT"), "a", encoding="utf-8") as fh:
            fh.write(f"result={result}\nblocking={sum(r['blocking'] for r in rows)}\n")
    return code


if __name__ == "__main__":
    sys.exit(main())
