"""Controller methods for moving this machine between networks: the follow-network switch and Wi-Fi scan/join."""
from __future__ import annotations

import logging

from netscan.config import ConfigError, load_config, write_follow_network
from netscan.web.errors import ApiError
from netscan.wifi import WifiError, WifiManager

log = logging.getLogger("netscan.web")
SETTLE_TRIES = 10


class NetworkMixin:
    wifi: WifiManager

    def wifi_status(self) -> dict:
        reason = self.wifi.unsupported
        if not reason and self.daemon_mode:  # type: ignore[attr-defined]
            reason = "This copy runs as an always-on monitor, so switching its Wi-Fi would cut it off. Use the dashboard on your laptop instead."
        return {"supported": not reason, "reason": reason}

    def _wifi_guard(self) -> None:
        status = self.wifi_status()
        if not status["supported"]:
            raise ApiError(409, status["reason"])

    def set_follow_network(self, body: dict) -> dict:
        value = body.get("follow_network") if isinstance(body, dict) else None
        if not isinstance(value, bool):
            raise ApiError(400, "follow_network must be true or false")
        if not self.cfg.config_path.exists():  # type: ignore[attr-defined]
            raise ApiError(409, "set netScan up first (Devices tab), then this can be switched")
        if any(s.running for s in self._services.values()):  # type: ignore[attr-defined]
            raise ApiError(409, "stop the running services before changing which networks are allowed")
        try:
            write_follow_network(self.cfg.config_path, value)  # type: ignore[attr-defined]
            cfg = load_config(self.cfg.config_path, self.cfg.home)  # type: ignore[attr-defined]
        except (ConfigError, OSError) as exc:
            raise ApiError(409, f"could not update config.toml: {exc}") from exc
        with self._rt_lock:  # type: ignore[attr-defined]
            self.cfg = cfg  # type: ignore[attr-defined]
            self._rt = None  # type: ignore[attr-defined]
            self._rt_error = ""  # type: ignore[attr-defined]
        return self.status()  # type: ignore[attr-defined]

    def wifi_scan(self) -> dict:
        self._wifi_guard()
        try:
            return self.wifi.scan()
        except WifiError as exc:
            raise ApiError(409, str(exc)) from exc

    def wifi_connect(self, body: dict) -> dict:
        if not isinstance(body, dict):
            raise ApiError(400, "expected a JSON object")
        self._wifi_guard()
        ssid, password = body.get("ssid"), body.get("password", "")
        if not isinstance(ssid, str) or not ssid.strip() or len(ssid.encode()) > 32:
            raise ApiError(400, "enter the network name (1 to 32 characters)")
        if not isinstance(password, str) or len(password) > 63:
            raise ApiError(400, "the password must be text of at most 63 characters")
        if any(s.running for s in self._services.values()):  # type: ignore[attr-defined]
            raise ApiError(409, "stop the running services first; they would lose the network under them")
        if self.store.active_jobs():  # type: ignore[attr-defined]
            raise ApiError(409, "wait for the running scan or job to finish first")
        try:
            self.wifi.connect(ssid.strip(), password)
        except WifiError as exc:
            raise ApiError(409, str(exc)) from exc
        log.info("joined wifi network %r", ssid.strip())  # the password is never logged
        error = ""
        for _ in range(SETTLE_TRIES):  # the address can lag the association by a few seconds
            try:
                self.refresh_runtime()  # type: ignore[attr-defined]
                error = ""
                break
            except ApiError as exc:
                error = exc.message
                if exc.status == 403 or self._closed.wait(1.0):  # type: ignore[attr-defined]
                    break
        return {"connected": ssid.strip(), "ready": not error, "problem": error}
