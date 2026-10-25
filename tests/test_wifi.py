import json

import pytest

from netscan import wifi
from netscan.config import ConfigError, load_config, render_config, write_follow_network
from netscan.wifi import WifiError, WifiManager

PROFILER = json.dumps({"SPAirPortDataType": [{"spairport_airport_interfaces": [{
    "_name": "en0",
    "spairport_current_network_information": {"_name": "Home Wi-Fi", "spairport_network_channel": "36 (5GHz, 80MHz)", "spairport_signal_noise": "-48 dBm / -92 dBm", "spairport_security_mode": "spairport_security_mode_wpa2_personal"},
    "spairport_airport_other_local_wireless_networks": [
        {"_name": "Gran's Wi-Fi", "spairport_network_channel": "6 (2GHz, 20MHz)", "spairport_signal_noise": "-70 dBm / -95 dBm", "spairport_security_mode": "spairport_security_mode_wpa3_personal"},
        {"_name": "Cafe Guest", "spairport_signal_noise": "-85 dBm / -95 dBm", "spairport_security_mode": "spairport_security_mode_none"},
        {"_name": "<redacted>", "spairport_signal_noise": "-60 dBm / -90 dBm"},
    ]}]}]})

HW_PORTS = "Hardware Port: Ethernet\nDevice: en5\n\nHardware Port: Wi-Fi\nDevice: en0\nEthernet Address: aa:bb:cc:dd:ee:ff\n"
NMCLI = "*:Home Wi-Fi:80:WPA2:36\n :Gran\\:s Wi-Fi:55:WPA2 WPA3:6\n : :70:WPA2:1\n :Cafe Guest:30::11\n"


class Fake:
    """Records every command and answers from a table keyed by the command's first words."""

    def __init__(self, answers):
        self.answers, self.calls = answers, []

    def __call__(self, cmd, timeout):
        self.calls.append(cmd)
        for prefix, reply in self.answers.items():
            if " ".join(cmd).startswith(prefix):
                return reply(cmd) if callable(reply) else reply
        return 1, ""


def mac_manager(extra=None, **kw):
    answers = {"networksetup -listallhardwareports": (0, HW_PORTS), "system_profiler": (0, PROFILER),
               "networksetup -listpreferredwirelessnetworks": (0, "Preferred networks on en0:\n\tHome Wi-Fi\n\tOffice\n"),
               "networksetup -getairportnetwork": (0, "Current Wi-Fi Network: Gran's Wi-Fi\n"), "networksetup -setairportnetwork": (0, "")}
    answers.update(extra or {})
    run = Fake(answers)
    return WifiManager(run=run, system="Darwin", sleep=lambda s: None, settle=0, **kw), run


def test_system_profiler_parser_sorts_out_names_security_and_hidden_networks():
    out = wifi.parse_system_profiler(PROFILER)
    names = {n["ssid"]: n for n in out["networks"]}
    assert set(names) == {"Home Wi-Fi", "Gran's Wi-Fi", "Cafe Guest"}, "redacted names must not be listed as networks"
    assert out["redacted"] and out["current"] == "Home Wi-Fi"
    assert names["Gran's Wi-Fi"]["security"] == "WPA3" and names["Cafe Guest"]["security"] == "Open" and names["Home Wi-Fi"]["channel"] == 36
    assert names["Home Wi-Fi"]["quality"] > names["Gran's Wi-Fi"]["quality"] > names["Cafe Guest"]["quality"], "stronger signal must read as better quality"


@pytest.mark.parametrize("text", ["", "not json", "{}", '{"SPAirPortDataType": []}', '{"SPAirPortDataType": [{"spairport_airport_interfaces": ["x", 3]}]}'])
def test_system_profiler_parser_shrugs_off_missing_or_odd_output(text):
    assert wifi.parse_system_profiler(text) == {"networks": [], "current": "", "redacted": False}


def test_nmcli_parser_handles_escaped_colons_blank_names_and_open_networks():
    out = wifi.parse_nmcli(NMCLI)
    names = {n["ssid"]: n for n in out["networks"]}
    assert set(names) == {"Home Wi-Fi", "Gran:s Wi-Fi", "Cafe Guest"}, "a literal colon in a name must survive and blank names must be dropped"
    assert out["current"] == "Home Wi-Fi" and names["Cafe Guest"]["security"] == "Open"


def test_hardware_port_and_saved_networks_parsers():
    assert wifi.parse_hardware_ports(HW_PORTS) == "en0"
    assert wifi.parse_hardware_ports("Hardware Port: Ethernet\nDevice: en5\n") == ""
    assert wifi.parse_preferred("Preferred networks on en0:\n\tA\n\tB\n") == ["A", "B"]
    assert wifi.parse_preferred("Error: no wifi") == []


def test_scan_lists_current_first_and_saved_networks_not_already_seen():
    mgr, _ = mac_manager()
    out = mgr.scan()
    assert out["interface"] == "en0" and out["networks"][0]["ssid"] == "Home Wi-Fi", "the connected network is listed first"
    assert out["saved"] == ["Office"], "saved networks already in the scan are not repeated"


def test_scan_keeps_saved_names_when_macos_hides_the_scan():
    hidden = json.dumps({"SPAirPortDataType": [{"spairport_airport_interfaces": [{"_name": "en0", "spairport_airport_other_local_wireless_networks": [{"_name": "<redacted>"}]}]}]})
    mgr, _ = mac_manager({"system_profiler": (0, hidden)})
    out = mgr.scan()
    assert out["networks"] == [] and out["redacted"] and "Office" in out["saved"], "a hidden scan must still let a saved network be picked"


def test_unsupported_systems_and_missing_adapter_are_explained():
    assert "not supported" in WifiManager(system="Windows").unsupported
    assert "nmcli" in WifiManager(system="Linux", which=lambda n: None).unsupported
    mgr, _ = mac_manager({"networksetup -listallhardwareports": (0, "Hardware Port: Ethernet\nDevice: en5\n")})
    with pytest.raises(WifiError, match="no Wi-Fi adapter"):
        mgr.scan()


def test_connect_passes_password_only_to_the_join_command_and_waits_for_the_network():
    mgr, run = mac_manager()
    assert mgr.connect("Gran's Wi-Fi", "s3cretpass") == "en0"
    joins = [c for c in run.calls if c[:2] == ["networksetup", "-setairportnetwork"]]
    assert joins == [["networksetup", "-setairportnetwork", "en0", "Gran's Wi-Fi", "s3cretpass"]]
    assert sum("s3cretpass" in " ".join(c) for c in run.calls) == 1, "the password must appear in no other command"


def test_connect_failure_messages_never_repeat_the_password():
    mgr, _ = mac_manager({"networksetup -setairportnetwork": (0, "Failed to join network Gran's Wi-Fi. s3cretpass rejected")})
    with pytest.raises(WifiError) as err:
        mgr.connect("Gran's Wi-Fi", "s3cretpass")
    assert "s3cretpass" not in str(err.value) and "could not join" in str(err.value)
    mgr, _ = mac_manager({"networksetup -setairportnetwork": (0, "Could not find network Nope.")})
    with pytest.raises(WifiError, match="not found"):
        mgr.connect("Nope", "x")


def test_connect_that_never_becomes_the_current_network_is_reported():
    mgr, _ = mac_manager({"networksetup -getairportnetwork": (0, "Current Wi-Fi Network: Home Wi-Fi\n")})
    with pytest.raises(WifiError, match="did not connect"):
        mgr.connect("Gran's Wi-Fi", "pw123456")


def test_linux_connect_uses_nmcli_with_the_adapter():
    run = Fake({"nmcli -t -f DEVICE,TYPE": (0, "eth0:ethernet\nwlan0:wifi\n"), "nmcli dev wifi connect": (0, "ok"),
                "nmcli -t -f ACTIVE,SSID": (0, "no:Other\nyes:Gran's Wi-Fi\n")})
    mgr = WifiManager(run=run, system="Linux", which=lambda n: "/usr/bin/nmcli", sleep=lambda s: None, settle=0)
    assert mgr.connect("Gran's Wi-Fi", "pw123456") == "wlan0"
    assert ["nmcli", "dev", "wifi", "connect", "Gran's Wi-Fi", "ifname", "wlan0", "password", "pw123456"] in run.calls


# config switch

def test_write_follow_network_edits_in_place_and_keeps_the_rest(tmp_path):
    path = tmp_path / "config.toml"
    path.write_text(render_config(["192.168.1.0/24"], "aa:bb:cc:dd:ee:ff").replace("[safety]", "# my note\n[safety]"))
    write_follow_network(path, True)
    cfg = load_config(path, tmp_path)
    assert cfg.follow_network and cfg.gateway_mac == "aa:bb:cc:dd:ee:ff" and "# my note" in path.read_text(), "unrelated settings and comments are kept"
    write_follow_network(path, False)
    assert not load_config(path, tmp_path).follow_network and path.read_text().count("follow_network") == 1, "switching back leaves exactly one line"


def test_write_follow_network_adds_a_network_table_when_missing_and_refuses_a_broken_file(tmp_path):
    path = tmp_path / "config.toml"
    path.write_text("[block]\nmethod = \"arp\"\n")
    write_follow_network(path, True)
    assert load_config(path, tmp_path).follow_network
    path.write_text("[network]\nallowed_subnets = [\"8.8.8.0/24\"]\n")
    with pytest.raises(ConfigError):
        write_follow_network(path, True)
    assert "follow_network" not in path.read_text() and not (tmp_path / "config.toml.tmp").exists(), "a file that would not load is left untouched"
