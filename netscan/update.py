"""Self-update from the git checkout netScan was installed from.

The dashboard asks `Updater.check()` whether the remote branch has new commits and, when told to, `apply()` fast-forwards
the checkout, reinstalls into the running virtualenv and verifies the result still imports (rolling back if not).
Nothing here runs unless someone presses Update or switches automatic updates on: whoever can push to the remote
effectively gets to run code on this machine, so it only ever follows the branch that is already checked out.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable
from urllib.parse import unquote, urlparse


class UpdateError(Exception):
    pass


Runner = Callable[[list[str], Path, float], "subprocess.CompletedProcess[str]"]


def find_source() -> tuple[Path, bool] | None:
    """The git checkout this install came from, and whether it is an editable install."""
    env = os.environ.get("NETSCAN_SOURCE")
    if env:
        p = Path(env).expanduser()
        return (p, False) if (p / ".git").exists() else None
    try:
        from importlib.metadata import distribution

        raw = distribution("netscan").read_text("direct_url.json")
        if raw:
            data = json.loads(raw)
            url = urlparse(data.get("url", ""))
            if url.scheme == "file":
                p = Path(unquote(url.path))
                if (p / ".git").exists():
                    return p, bool(data.get("dir_info", {}).get("editable"))
    except Exception:  # noqa: BLE001 not installed from a directory (or no metadata): try the import location
        pass
    here = Path(__file__).resolve().parents[1]
    return (here, True) if (here / ".git").exists() else None


def _owner_ids(path: Path) -> tuple[int, int] | None:
    """Run git and pip as whoever owns the checkout, so a root-run dashboard never leaves root-owned files behind."""
    if not hasattr(os, "geteuid") or os.geteuid() != 0:
        return None
    st = path.stat()
    return (st.st_uid, st.st_gid) if st.st_uid != 0 else None


def default_runner(cmd: list[str], cwd: Path, timeout: float) -> "subprocess.CompletedProcess[str]":
    env = dict(os.environ, GIT_TERMINAL_PROMPT="0", GIT_ASKPASS="true", PIP_DISABLE_PIP_VERSION_CHECK="1")
    kwargs: dict = {}
    ids = _owner_ids(cwd)
    if ids:
        import pwd

        kwargs.update(user=ids[0], group=ids[1], extra_groups=[])
        try:
            env["HOME"] = pwd.getpwuid(ids[0]).pw_dir
        except KeyError:
            pass
    try:
        return subprocess.run(cmd, cwd=cwd, env=env, capture_output=True, text=True, timeout=timeout, **kwargs)
    except subprocess.TimeoutExpired as exc:
        raise UpdateError(f"{cmd[0]} timed out after {int(timeout)}s") from exc
    except OSError as exc:
        raise UpdateError(f"cannot run {cmd[0]}: {exc}") from exc


@dataclass
class Check:
    data: dict
    at: float


class Updater:
    def __init__(self, source: tuple[Path, bool] | None = None, *, runner: Runner = default_runner, clock: Callable[[], float] = time.time,
                 ttl: float = 60.0, install: bool = True, python: str | None = None, disabled_reason: str = ""):
        self.source, self.editable = (source if source is not None else (find_source() or (None, False)))
        self.runner = runner
        self.clock = clock
        self.ttl = ttl
        self.install = install
        self.python = python or sys.executable
        self.disabled_reason = disabled_reason
        self._lock = threading.Lock()
        self._cache: Check | None = None

    # git helpers
    def _git(self, *args: str, timeout: float = 30.0, check: bool = True) -> str:
        assert self.source is not None
        res = self.runner(["git", *args], self.source, timeout)
        if check and res.returncode != 0:
            raise UpdateError((res.stderr or res.stdout or f"git {args[0]} failed").strip().splitlines()[-1][:300])
        return (res.stdout or "").strip()

    def _unsupported(self, reason: str) -> dict:
        return {"supported": False, "reason": reason, "behind": 0, "ahead": 0, "dirty": False, "new_commits": [], "error": "", "checked_at": None}

    def check(self, force: bool = False) -> dict:
        if self.disabled_reason:
            return self._unsupported(self.disabled_reason)
        if self.source is None:
            return self._unsupported("netScan was not installed from a git checkout, so it cannot update itself. Install it with git clone and pip install.")
        with self._lock:
            now = self.clock()
            if not force and self._cache and now - self._cache.at < self.ttl:
                return dict(self._cache.data)
            data = self._check_locked(now)
            self._cache = Check(data, now)
            return dict(data)

    def _check_locked(self, now: float) -> dict:
        try:
            branch = self._git("rev-parse", "--abbrev-ref", "HEAD")
            if branch == "HEAD":
                return self._unsupported("The checkout is on a detached commit, not a branch, so there is nothing to follow.")
            data: dict = {
                "supported": True, "reason": "", "branch": branch, "editable": self.editable, "source": str(self.source),
                "commit": self._git("rev-parse", "--short", "HEAD"), "subject": self._git("log", "-1", "--format=%s"),
                "dirty": bool(self._git("status", "--porcelain", "--untracked-files=no")),
                "behind": 0, "ahead": 0, "new_commits": [], "error": "", "checked_at": now,
            }
        except UpdateError as exc:
            return {**self._unsupported(str(exc)), "checked_at": now}
        try:
            self._git("fetch", "--quiet", "origin", branch, timeout=20.0)
            data["behind"] = int(self._git("rev-list", "--count", "HEAD..FETCH_HEAD") or 0)
            data["ahead"] = int(self._git("rev-list", "--count", "FETCH_HEAD..HEAD") or 0)
            if data["behind"]:
                log = self._git("log", "--format=%h\t%s", "-n", "10", "HEAD..FETCH_HEAD")
                data["new_commits"] = [dict(zip(("sha", "subject"), line.split("\t", 1))) for line in log.splitlines() if "\t" in line]
        except (UpdateError, ValueError) as exc:
            data["error"] = f"Could not reach GitHub: {exc}"
        return data

    def blocker(self, info: dict) -> str:
        """Why an update cannot be applied right now ('' when it can)."""
        if not info["supported"]:
            return info["reason"]
        if info["error"]:
            return info["error"]
        if info["dirty"]:
            return "The checkout has uncommitted changes. Commit or stash them first."
        if info["ahead"]:
            return "This checkout has commits that are not on GitHub, so it cannot fast-forward. Push or reset them first."
        if not info["behind"]:
            return "Already up to date."
        return ""

    def apply(self) -> dict:
        info = self.check(force=True)
        why = self.blocker(info)
        if why:
            raise UpdateError(why)
        assert self.source is not None
        with self._lock:
            old = self._git("rev-parse", "HEAD")
            self._git("merge", "--ff-only", "FETCH_HEAD")
            new = self._git("rev-parse", "HEAD")
            try:
                if self.install:
                    self._reinstall()
            except UpdateError as exc:
                self._rollback(old)
                raise UpdateError(f"The update failed and was rolled back ({exc}).") from exc
            self._cache = None
        return {"from": old[:7], "to": new[:7], "commits": info["behind"], "reinstalled": self.install and not self.editable}

    def _reinstall(self) -> None:
        assert self.source is not None
        if not self.editable:
            res = self.runner([self.python, "-m", "pip", "install", "--quiet", str(self.source)], self.source, 900.0)
            if res.returncode != 0:
                raise UpdateError("pip install failed: " + ((res.stderr or res.stdout).strip().splitlines() or ["unknown error"])[-1][:300])
        res = self.runner([self.python, "-c", "import netscan.cli, netscan.web.server"], Path("/"), 60.0)
        if res.returncode != 0:
            raise UpdateError("the new version does not start: " + ((res.stderr or res.stdout).strip().splitlines() or ["import failed"])[-1][:300])

    def _rollback(self, old: str) -> None:
        try:
            self._git("reset", "--hard", old)
            if self.install and not self.editable:
                assert self.source is not None
                self.runner([self.python, "-m", "pip", "install", "--quiet", str(self.source)], self.source, 900.0)
        except UpdateError:
            pass
        self._cache = None
