"""OUI vendor lookup: bundled IEEE MA-L table, optionally overridden by a downloaded copy."""

from __future__ import annotations

import gzip
import urllib.request
from importlib import resources
from pathlib import Path

from netscan.macutil import is_locally_administered, normalise_mac

IEEE_CSV_URL = "https://standards-oui.ieee.org/oui/oui.csv"
# IEEE rejects urllib's default User-Agent (HTTP 418), so identify as a normal client.
FETCH_HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; netScan OUI updater; +https://github.com/YeomeoR/netScan)",
    "Accept": "text/csv,text/plain,*/*",
}
FALLBACK_URLS = ("http://standards-oui.ieee.org/oui/oui.csv",)
RANDOMISED = "(randomised MAC)"


def parse_oui_lines(lines) -> dict[str, str]:
    """Parse `PREFIX<TAB>vendor` lines; PREFIX is 6 hex chars, any separators tolerated."""
    table: dict[str, str] = {}
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or "\t" not in line:
            continue
        prefix, name = line.split("\t", 1)
        prefix = prefix.replace(":", "").replace("-", "").upper()
        if len(prefix) == 6 and all(c in "0123456789ABCDEF" for c in prefix):
            table[prefix] = name.strip()
    return table


def parse_ieee_csv(text: str) -> dict[str, str]:
    import csv
    import io

    table: dict[str, str] = {}
    for row in csv.DictReader(io.StringIO(text)):
        if row.get("Registry") == "MA-L" and row.get("Assignment"):
            table[row["Assignment"].upper()] = " ".join(row["Organization Name"].split())
    return table


class OuiDb:
    def __init__(self, table: dict[str, str]):
        self.table = table

    @classmethod
    def load(cls, override: Path | None = None) -> "OuiDb":
        if override and Path(override).exists():
            return cls(parse_oui_lines(Path(override).read_text(encoding="utf-8").splitlines()))
        try:
            with resources.files("netscan").joinpath("data/oui.tsv.gz").open("rb") as raw:
                with gzip.open(raw, "rt", encoding="utf-8") as fh:
                    return cls(parse_oui_lines(fh))
        except (FileNotFoundError, OSError):
            return cls({})

    def lookup(self, mac: str) -> str:
        norm = normalise_mac(mac)
        if not norm:
            return ""
        if is_locally_administered(norm):
            return RANDOMISED
        return self.table.get(norm[:8].replace(":", "").upper(), "")


def update_oui(dest: Path, fetch=None, timeout: float = 60.0) -> int:
    """Download the IEEE registry into dest as TSV. `fetch` is injectable for tests."""
    if fetch is None:
        def fetch(url: str) -> str:
            req = urllib.request.Request(url, headers=FETCH_HEADERS)  # noqa: S310 fixed url
            with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 fixed url
                return resp.read().decode("utf-8", errors="replace")

    errors: list[str] = []
    table: dict[str, str] = {}
    for url in (IEEE_CSV_URL, *FALLBACK_URLS):
        try:
            table = parse_ieee_csv(fetch(url))
        except Exception as exc:  # network/HTTP errors vary widely; try the next source
            errors.append(f"{url}: {exc}")
            continue
        if table:
            break
        errors.append(f"{url}: response was empty or not the IEEE CSV")
    if not table:
        raise RuntimeError("could not download the vendor registry (" + "; ".join(errors) + "); keeping existing data")
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(".tmp")
    tmp.write_text("".join(f"{k}\t{v}\n" for k, v in sorted(table.items())), encoding="utf-8")
    tmp.replace(dest)
    return len(table)
