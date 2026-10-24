"""Self-update against real throwaway git repositories (no network, no real pip)."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from netscan.update import UpdateError, Updater, default_runner
from netscan.web.controller import ApiError
from test_web import make_ctl, home, wait_store  # noqa: F401 fixtures


def git(cwd: Path, *args: str) -> str:
    env = {"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t", "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t", "PATH": "/usr/bin:/bin:/usr/local/bin", "HOME": str(cwd)}
    return subprocess.run(["git", *args], cwd=cwd, env=env, check=True, capture_output=True, text=True).stdout.strip()


@pytest.fixture
def repos(tmp_path):
    origin = tmp_path / "origin.git"
    origin.mkdir()
    git(origin, "init", "--bare", "-b", "main")
    work = tmp_path / "work"
    git(tmp_path, "clone", str(origin), "work")
    (work / "a.txt").write_text("one")
    git(work, "add", "."), git(work, "commit", "-m", "first")
    git(work, "push", "origin", "main")
    mine = tmp_path / "mine"
    git(tmp_path, "clone", str(origin), "mine")

    def push(name="b.txt", msg="second change"):
        (work / name).write_text(msg)
        git(work, "add", "."), git(work, "commit", "-m", msg), git(work, "push", "origin", "main")

    return mine, push


def updater(mine, **kw):
    kw.setdefault("install", False)
    return Updater((mine, False), **kw)


def test_up_to_date_then_behind_then_applied(repos):
    mine, push = repos
    up = updater(mine, ttl=0)
    info = up.check()
    assert info["supported"] and info["behind"] == 0 and info["branch"] == "main" and not info["dirty"]
    assert up.blocker(info) == "Already up to date."
    push(msg="add the thing")
    info = up.check()
    assert info["behind"] == 1 and info["new_commits"][0]["subject"] == "add the thing"
    assert up.blocker(info) == ""
    done = up.apply()
    assert done["commits"] == 1 and done["from"] != done["to"]
    assert (mine / "b.txt").exists()
    assert up.check(force=True)["behind"] == 0


def test_check_is_cached_until_forced(repos):
    mine, push = repos
    up = updater(mine, ttl=3600)
    assert up.check()["behind"] == 0
    push()
    assert up.check()["behind"] == 0
    assert up.check(force=True)["behind"] == 1


def test_dirty_or_diverged_checkout_is_never_touched(repos):
    mine, push = repos
    push()
    (mine / "a.txt").write_text("local edit")
    up = updater(mine)
    assert "uncommitted" in up.blocker(up.check(force=True))
    with pytest.raises(UpdateError):
        up.apply()
    assert (mine / "a.txt").read_text() == "local edit" and not (mine / "b.txt").exists()
    git(mine, "checkout", "a.txt")
    (mine / "c.txt").write_text("c")
    git(mine, "add", "."), git(mine, "commit", "-m", "local only")
    assert "not on GitHub" in up.blocker(up.check(force=True))


def test_failed_install_rolls_back(repos):
    mine, push = repos
    before = git(mine, "rev-parse", "HEAD")
    push()

    def runner(cmd, cwd, timeout):
        if "pip" in cmd:
            return subprocess.CompletedProcess(cmd, 1, "", "ERROR: could not build")
        return default_runner(cmd, cwd, timeout)

    up = Updater((mine, False), runner=runner)
    with pytest.raises(UpdateError, match="rolled back"):
        up.apply()
    assert git(mine, "rev-parse", "HEAD") == before and not (mine / "b.txt").exists()


def test_editable_install_skips_pip_and_checks_import(repos):
    mine, push = repos
    push()
    seen = []

    def runner(cmd, cwd, timeout):
        seen.append(cmd)
        if cmd[0] == "git":
            return default_runner(cmd, cwd, timeout)
        return subprocess.CompletedProcess(cmd, 0, "", "")

    done = Updater((mine, True), runner=runner).apply()
    assert not done["reinstalled"]
    assert not any("pip" in c for c in seen) and any("-c" in c for c in seen)


def test_unreachable_remote_and_unsupported(repos, tmp_path, monkeypatch):
    mine, _ = repos
    git(mine, "remote", "set-url", "origin", str(tmp_path / "gone.git"))
    info = updater(mine).check(force=True)
    assert "Could not reach GitHub" in info["error"] and info["behind"] == 0
    monkeypatch.setattr("netscan.update.find_source", lambda: None)
    assert "git checkout" in Updater().check()["reason"]
    assert Updater(disabled_reason="off").check()["reason"] == "off"


def test_api_status_switch_and_apply(home, repos, tmp_path):
    mine, push = repos
    restarted = []
    ctl = make_ctl(home, updater=Updater((mine, False), install=False, ttl=0))
    ctl.on_restart = lambda: restarted.append(1)
    ctl.start()
    try:
        assert ctl.status()["boot_id"] and ctl.update_status()["behind"] == 0
        with pytest.raises(ApiError) as exc:
            ctl.submit_update()
        assert exc.value.status == 409
        push()
        assert ctl.update_status()["can_apply"] and ctl.update_status()["auto"] is False
        with pytest.raises(ApiError):
            ctl.set_update_auto({"auto": "yes"})
        row = wait_store(ctl, ctl.submit_update()["id"])
        assert row.state == "done" and row.summary["restarting"] and row.summary["commits"] == 1
        import time
        time.sleep(2.2)
        assert restarted == [1]
        assert (mine / "b.txt").exists()
    finally:
        ctl.close()


def test_auto_update_applies_when_status_is_checked(home, repos):
    mine, push = repos
    ctl = make_ctl(home, updater=Updater((mine, False), install=False, ttl=0))
    ctl.start()
    try:
        assert ctl.set_update_auto({"auto": True})["auto"] is True
        push()
        out = ctl.update_status()
        assert out["applying"]
        job = next(j for j in ctl.store.recent_jobs(5) if j.kind == "update")
        assert job.source == "auto"
        assert wait_store(ctl, job.id).state == "done"
        assert ctl.update_status()["behind"] == 0
    finally:
        ctl.close()


def test_background_loop_follows_github_only_when_auto_is_on(home, repos):
    import time

    mine, push = repos
    ctl = make_ctl(home, updater=Updater((mine, False), install=False, ttl=0), update_tick=0.1)
    ctl.start()
    try:
        push()
        time.sleep(0.6)
        assert not (mine / "b.txt").exists() and not any(j.kind == "update" for j in ctl.store.recent_jobs(5))
        ctl.set_update_auto({"auto": True})
        end = time.time() + 5
        while time.time() < end and not (mine / "b.txt").exists():
            time.sleep(0.1)
        assert (mine / "b.txt").exists()
    finally:
        ctl.close()
