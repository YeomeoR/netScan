import ipaddress

import pytest

from netscan.macutil import is_locally_administered, normalise_mac
from netscan.net import compute_local_network
from netscan.oui import RANDOMISED, OuiDb, parse_ieee_csv, parse_oui_lines, update_oui
from netscan.parsing import Host, parse_arp_an, parse_ip_neigh, parse_neighbours

MAC_ARP = """\
? (192.168.1.1) at 0:11:22:33:44:5 on en0 ifscope [ethernet]
? (192.168.1.20) at b8:27:eb:12:34:56 on en0 ifscope [ethernet]
? (192.168.1.99) at (incomplete) on en0 ifscope [ethernet]
? (224.0.0.251) at 1:0:5e:0:0:fb on en0 ifscope permanent [ethernet]
? (192.168.1.255) at ff:ff:ff:ff:ff:ff on en0 ifscope [ethernet]
"""

LINUX_NEIGH = """\
192.168.1.1 dev eth0 lladdr 00:11:22:33:44:55 REACHABLE
192.168.1.20 dev eth0 lladdr b8:27:eb:12:34:56 STALE
192.168.1.77 dev eth0  FAILED
192.168.1.78 dev eth0 lladdr 00:aa:bb:cc:dd:ee FAILED
"""


def test_normalise_mac_pads_macos_short_octets():
    assert normalise_mac("0:11:22:33:44:5") == "00:11:22:33:44:05", "macOS drops leading zeros; they must be restored"
    assert normalise_mac("B8-27-EB-12-34-56") == "b8:27:eb:12:34:56", "dash separated, upper case input must normalise"
    assert normalise_mac("b827.eb12.3456") == "b8:27:eb:12:34:56", "cisco style dotted mac must normalise"
    assert normalise_mac("ff:ff:ff:ff:ff:ff") is None, "broadcast is not a device"
    assert normalise_mac("garbage") is None
    assert normalise_mac("") is None


def test_parse_macos_arp_an_skips_incomplete_multicast_broadcast():
    hosts = parse_arp_an(MAC_ARP)
    assert hosts == [Host("192.168.1.1", "00:11:22:33:44:05"), Host("192.168.1.20", "b8:27:eb:12:34:56")], (
        "only complete unicast entries may be returned"
    )


def test_parse_ip_neigh_skips_failed_and_empty():
    hosts = parse_ip_neigh(LINUX_NEIGH)
    assert [h.ip for h in hosts] == ["192.168.1.1", "192.168.1.20"], "FAILED/no-lladdr neighbours are not devices"


def test_parse_neighbours_autodetects_and_dedupes():
    hosts = parse_neighbours(MAC_ARP + LINUX_NEIGH)
    assert sorted(h.ip for h in hosts) == ["192.168.1.1", "192.168.1.20"], "both formats parsed, duplicates by ip collapsed"


def test_oui_bundled_table_resolves_known_vendors():
    db = OuiDb.load()
    assert "raspberry" in db.lookup("b8:27:eb:00:11:22").lower(), "bundled IEEE table must know Raspberry Pi"
    assert db.lookup("00:00:00:00:00:00") == "", "invalid mac gives no vendor"


def test_oui_flags_randomised_macs():
    db = OuiDb({"B827EB": "Raspberry Pi"})
    assert is_locally_administered("da:a1:19:00:00:01")
    assert db.lookup("da:a1:19:00:00:01") == RANDOMISED, "private/randomised MACs have no real vendor"


def test_parse_oui_lines_and_override_file(tmp_path):
    table = parse_oui_lines(["# c", "B827EB\tRaspberry Pi", "bad\tx", "00-11-22\tAcme Ltd", ""])
    assert table == {"B827EB": "Raspberry Pi", "001122": "Acme Ltd"}
    f = tmp_path / "oui.tsv"
    f.write_text("001122\tAcme Ltd\n")
    assert OuiDb.load(f).lookup("00:11:22:33:44:55") == "Acme Ltd", "downloaded file overrides bundled table"


CSV = 'Registry,Assignment,Organization Name,Organization Address\nMA-L,001122,"Acme,  Ltd",x\nMA-M,AABBCC1,Other,y\n'


def test_update_oui_writes_only_ma_l_and_rejects_empty(tmp_path):
    assert parse_ieee_csv(CSV) == {"001122": "Acme, Ltd"}
    dest = tmp_path / "oui.tsv"
    assert update_oui(dest, fetch=lambda url: CSV) == 1
    assert dest.read_text() == "001122\tAcme, Ltd\n"
    with pytest.raises(RuntimeError):
        update_oui(tmp_path / "x.tsv", fetch=lambda url: "Registry,Assignment\n")
    assert not (tmp_path / "x.tsv").exists(), "an empty download must not clobber/create data"


def test_compute_local_network_from_routes():
    routes = [
        (0, 0, "192.168.1.1", "en0", "192.168.1.10", 100),
        (0xC0A80100, 0xFFFFFF00, "0.0.0.0", "en0", "192.168.1.10", 0),
        (0xA9FE0000, 0xFFFF0000, "0.0.0.0", "en0", "169.254.1.1", 0),
        (0x0A000000, 0xFF000000, "0.0.0.0", "utun1", "10.0.0.2", 0),
    ]
    iface, ip, net, gw = compute_local_network(routes, "", lambda i: "192.168.1.10")
    assert (iface, ip, net, gw) == ("en0", "192.168.1.10", ipaddress.ip_network("192.168.1.0/24"), "192.168.1.1")


def test_compute_local_network_requires_default_route():
    with pytest.raises(RuntimeError):
        compute_local_network([], "", lambda i: "1.2.3.4")


def test_ip_neigh_flags_before_state_do_not_hide_failed_entries():
    text = (
        "192.168.1.5 dev eth0 lladdr aa:bb:cc:dd:ee:01 router FAILED\n"
        "192.168.1.6 dev eth0 lladdr aa:bb:cc:dd:ee:02 router REACHABLE\n"
        "192.168.1.7 dev eth0 lladdr aa:bb:cc:dd:ee:03 used 1/0/1 probes 1 STALE\n"
    )
    assert [h.ip for h in parse_ip_neigh(text)] == ["192.168.1.6", "192.168.1.7"], "state is the last token, whatever flags precede it"


def test_compute_local_network_honours_explicit_interface_when_vpn_owns_default_route():
    routes = [
        (0, 0, "10.8.0.1", "utun3", "10.8.0.2", 1),
        (0xC0A80100, 0xFFFFFF00, "0.0.0.0", "en0", "192.168.1.10", 0),
    ]
    iface, ip, net, gw = compute_local_network(routes, "en0", lambda i: "192.168.1.10")
    assert (iface, str(net), gw) == ("en0", "192.168.1.0/24", ""), "network.interface must work without a default route on it"
