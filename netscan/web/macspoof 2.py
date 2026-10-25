"""Controller methods for temporarily changing this machine's MAC address (and putting it back)."""
from __future__ import annotations

import logging
import threading
import time

from netscan.macutil import normalise_mac
from netscan.spoof import DEFAULT_MINUTES, MAX_MINUTES, SpoofError, Spoofer
from netscan.web.errors import ApiError

log = logging.getLogger("netscan.web")
RECONNECT_WAIT = 30.0


class SpoofMixin:
    spoofer: Spoofer

    def spoof_status(self) -> dict:
        saved = self.spoofer.state()
        now = self.clock()  # type: ignore[attr-defined]
        out = {
            "supported": not self.spoofer.unsupported, "reason": self.spoofer.unsupported, "active": bool(saved),
            "max_minutes": MAX_MINUTES, "default_minutes": DEFAULT_MINUTES,
            "busy": any(j.kind in ("spoof", "unspoof") for j in self.store.active_jobs()),  # type: ignore[attr-defined]
        }
        if saved:
            out.update(interface=saved["interface"], original=saved["original"], spoofed=saved["spoofed"],
                       started=saved["started"], expires=saved["expires"], seconds_left=max(0, int(saved["expires"] - now)))
        return out

    def _spoof_guard(self) -> None:
        if self.spoofer.unsupported:
            raise ApiError(409, self.spoofer.unsupported)
        if any(j.kind in ("spoof", "unspoof") for j in self.store.active_jobs()):  # type: ignore[attr-defined]
            raise ApiError(409, "a MAC change is already in progress")
        if self.store.active_jobs():  # type: ignore[attr-defined]
            raise ApiError(409, "wait for the running scan or job to finish first; changing the address interrupts the network connection")

    def submit_spoof(self, body: dict) -> dict:
        if not isinstance(body, dict):
            raise ApiError(400, "expected a JSON object")
        self._spoof_guard()
        rt = self._runtime()  # type: ignore[attr-defined]
        minutes = body.get("minutes", DEFAULT_MINUTES)
        if not isinstance(minutes, int) or isinstance(minutes, bool) or not 1 <= minutes <= MAX_MINUTES:
            raise ApiError(400, f"minutes must be a whole number between 1 and {MAX_MINUTES}")
        forbidden = {m for m in (rt.gateway_mac, normalise_mac(self.cfg.gateway_mac)) if m}  # type: ignore[attr-defined]
        try:
            mac = self.spoofer.validate(str(body.get("mac", "")), forbidden)
        except SpoofError as exc:
            raise ApiError(400, str(exc)) from exc
        if any(b.mac == mac for b in self.store.list_blocks()):  # type: ignore[attr-defined]
            raise ApiError(409, "that device is blocked right now; unblock it first so the block does not get tangled with this change")
        dev = self.store.find_device(mac)  # type: ignore[attr-defined]
        if dev and dev.online and body.get("confirm") is not True:
            raise ApiError(409, f"{dev.hostname or dev.vendor or mac} is online right now. Two devices sharing one address knock each other off the network. Switch it off first, or confirm that you want to go ahead.")
        saved = self.spoofer.state()
        if saved and saved["interface"] != rt.local.interface:
            raise ApiError(409, f"{saved['interface']} is already changed; put it back first")
        params = {"mac": mac, "minutes": minutes, "interface": saved["interface"] if saved else rt.local.interface}
        return self._submit("spoof", params)  # type: ignore[attr-defined]

    def submit_unspoof(self, source: str = "manual") -> dict:
        if not self.spoofer.state():
            raise ApiError(409, "the MAC address is not changed")
        if any(j.kind in ("spoof", "unspoof") for j in self.store.active_jobs()):  # type: ignore[attr-defined]
            raise ApiError(409, "a MAC change is already in progress")
        return self._submit("unspoof", {}, source)  # type: ignore[attr-defined]

    def _services_running(self) -> list[str]:
        return [n for n, s in self._services.items() if s.running]  # type: ignore[attr-defined]

    def _around_network_change(self, change) -> None:
        """Stop the watchers, change the address, wait for the network to come back, then start the watchers again."""
        running = self._services_running()
        for name in running:
            self._stop_service(name)  # type: ignore[attr-defined]
        try:
            change()
        finally:
            with self._rt_lock:  # type: ignore[attr-defined]
                self._rt = None  # type: ignore[attr-defined]
            deadline = time.monotonic() + RECONNECT_WAIT
            while not self._closed.is_set():  # type: ignore[attr-defined]
                try:
                    self._runtime()  # type: ignore[attr-defined]
                    break
                except ApiError:
                    if time.monotonic() > deadline:
                        log.error("network did not come back within %ss after changing the MAC address", RECONNECT_WAIT)
                        break
                    time.sleep(1.0)
            for name in running:
                try:
                    self.start_service(name)  # type: ignore[attr-defined]
                except ApiError as exc:
                    log.error("could not restart %s: %s", name, exc.message)

    def _do_spoof(self, params: dict) -> dict:
        saved = self.spoofer.state()
        out: dict = {}

        def change() -> None:
            try:
                out.update(self.spoofer.apply(params["interface"], params["mac"], params["minutes"]))
            except SpoofError as exc:
                raise ApiError(409, str(exc)) from exc

        self._around_network_change(change)
        self.store.add_event("mac_spoof", out["spoofed"], "", f"this machine now uses {out['spoofed']} on {out['interface']} until {time.strftime('%H:%M', time.localtime(out['expires']))} (was {out['original']})", self.clock())  # type: ignore[attr-defined]
        return {"interface": out["interface"], "mac": out["spoofed"], "original": out["original"], "minutes": params["minutes"], "extended": bool(saved)}

    def _do_unspoof(self) -> dict:
        out: dict = {}

        def change() -> None:
            try:
                out.update(self.spoofer.restore())
            except SpoofError as exc:
                raise ApiError(409, str(exc)) from exc

        self._around_network_change(change)
        self.store.add_event("mac_restore", out["original"], "", f"this machine's own MAC {out['original']} is back on {out['interface']}", self.clock())  # type: ignore[attr-defined]
        return {"interface": out["interface"], "mac": out["original"]}

    def spoof_tick(self) -> None:
        if self.spoofer.expired() and not self.store.active_jobs():  # type: ignore[attr-defined]
            try:
                self.submit_unspoof("auto")
            except ApiError:
                pass

    def spoof_startup(self) -> None:
        def run() -> None:
            try:
                self.spoofer.reconcile()
            except Exception:  # noqa: BLE001 a failed check must not stop start-up
                log.exception("could not reconcile the saved MAC change")

        threading.Thread(target=run, name="netscan-spoof-reconcile", daemon=True).start()
