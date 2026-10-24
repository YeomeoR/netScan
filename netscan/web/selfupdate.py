"""Controller methods for self-update: status (and optional auto-apply), the on/off switch, and the update job."""
from __future__ import annotations

import logging
import threading

from netscan.update import UpdateError, Updater
from netscan.web.errors import ApiError

log = logging.getLogger("netscan.web")
RESTART_DELAY = 1.5


class UpdateMixin:
    updater: Updater
    on_restart: object

    def update_auto(self) -> bool:
        return bool((self.store.get_setting("update", {}) or {}).get("auto"))  # type: ignore[attr-defined]

    def _update_job_active(self) -> bool:
        return any(j.kind == "update" for j in self.store.active_jobs())  # type: ignore[attr-defined]

    def update_status(self, force: bool = False) -> dict:
        info = self.updater.check(force)
        why = self.updater.blocker(info)
        applying = self._update_job_active()
        auto = self.update_auto()
        out = {**info, "auto": auto, "applying": applying, "can_apply": not why and not applying, "blocker": "" if info.get("behind") and not why else why}
        if auto and out["can_apply"] and not self.store.active_jobs():  # type: ignore[attr-defined]
            try:
                self._submit("update", {}, "auto")  # type: ignore[attr-defined]
                out["applying"], out["can_apply"] = True, False
            except ApiError:
                pass
        return out

    def set_update_auto(self, body: dict) -> dict:
        if not isinstance(body, dict) or not isinstance(body.get("auto"), bool):
            raise ApiError(400, "auto must be true or false")
        self.store.set_setting("update", {"auto": body["auto"]})  # type: ignore[attr-defined]
        return self.update_status()

    def submit_update(self) -> dict:
        if self._update_job_active():
            raise ApiError(409, "an update is already running")
        info = self.updater.check(force=True)
        why = self.updater.blocker(info)
        if why:
            raise ApiError(409, why)
        return self._submit("update", {})  # type: ignore[attr-defined]

    def _do_update(self) -> dict:
        try:
            summary = self.updater.apply()
        except UpdateError as exc:
            raise ApiError(409, str(exc)) from exc
        restart = self.on_restart
        summary["restarting"] = callable(restart)
        if callable(restart):
            timer = threading.Timer(RESTART_DELAY, restart)
            timer.daemon = True
            timer.start()
        return summary
