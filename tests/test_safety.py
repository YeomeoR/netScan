import ipaddress

import pytest

from conftest import GW_IP, GW_MAC, HOST_IP, HOST_MAC, PHONE, FakeTransport
from netscan import cli
from netscan.blocker import BlockManager
from netscan.config import ConfigError, load_config, parse_subnets, render_config
from netscan.net import GuardedTransport
from netscan.parsing import Host
from netscan.runtime import build_runtime
from netscan.safety import (
    NoticeNotAcceptedError,
    OutOfScopeError,
    ProtectedTargetError,
    Scope,
    ensure_notice,
)

NET = ipaddress.ip_network("192.168.1.0/24")


def scope():
    return Scope([NET], gateway_ip=GW_IP, host_ips={HOST_IP}, protected_macs={GW_MAC, HOST_MAC})


# allow-list parsing

@pytest.mark.parametrize("bad", ["8.8.8.0/24", "0.0.0.0/0", "10.0.0.0/8", "172.16.0.0/12", "not-a-net", "2001:db8::/32", "127.0.0.0/24"])
def test_allow_list_rejects_public_huge_or_invalid_subnets(bad):
    with pytest.raises(ConfigError):
        parse_subnets([bad])


def test_allow_list_accepts_home_ranges():
    nets = parse_subnets(["192.168.1.0/24", "10.0.5.0/24", "172.16.0.0/16"])
    assert [str(n) for n in nets] == ["192.168.1.0/24", "10.0.5.0/24", "172.16.0.0/16"]


def test_config_roundtrip_and_validation(tmp_path):
    (tmp_path / "config.toml").write_text(render_config(["192.168.1.0/24"]))
    cfg = load_config(home=tmp_path)
    assert cfg.allowed_subnets == [NET] and cfg.block_method == "arp"
    (tmp_path / "config.toml").write_text('[network]\nallowed_subnets=["1.2.3.0/24"]\n')
    with pytest.raises(ConfigError):
        load_config(home=tmp_path)
    (tmp_path / "config.toml").write_text('[block]\nmethod="rm -rf"\n')
    with pytest.raises(ConfigError):
        load_config(home=tmp_path)


def test_empty_allow_list_refuses_everything():
    with pytest.raises(OutOfScopeError):
        Scope([])


# scope refusals

def test_scope_refuses_ips_outside_allow_list():
    s = scope()
    for ip in ("8.8.8.8", "192.168.2.5", "10.0.0.1", "not-an-ip", "192.168.1.0", "192.168.1.255"):
        with pytest.raises(OutOfScopeError):
            s.check_ip(ip)
    assert s.check_ip("192.168.1.50") == "192.168.1.50"


def test_scope_refuses_networks_not_inside_allow_list():
    s = scope()
    assert s.check_network("192.168.1.0/25") == ipaddress.ip_network("192.168.1.0/25")
    for net in ("192.168.0.0/16", "192.168.2.0/24", "8.8.8.0/24", "0.0.0.0/0"):
        with pytest.raises(OutOfScopeError):
            s.check_network(net)


def test_guarded_transport_refuses_sweep_and_arp_outside_scope():
    inner = FakeTransport()
    g = GuardedTransport(inner, scope())
    with pytest.raises(OutOfScopeError):
        g.arp_sweep(ipaddress.ip_network("192.168.2.0/24"), "en0", 1)
    with pytest.raises(OutOfScopeError):
        g.send_arp_reply("en0", "02:00:00:00:00:01", "192.168.1.1", GW_MAC, "8.8.8.8")
    with pytest.raises(OutOfScopeError):
        g.send_arp_reply("en0", "02:00:00:00:00:01", "8.8.8.8", GW_MAC, "192.168.1.5")
    with pytest.raises(OutOfScopeError):
        g.resolve_mac("1.1.1.1", "en0")
    assert inner.sweeps == [] and inner.sent == [], "nothing may reach the wire when refused"


def test_guarded_transport_filters_out_of_scope_replies():
    inner = FakeTransport(hosts=[PHONE, Host("8.8.8.8", "00:11:22:33:44:55")])
    got = GuardedTransport(inner, scope()).arp_sweep(NET, "en0", 1)
    assert got == [PHONE], "replies from outside the allow-list are dropped"


def test_runtime_refuses_when_host_is_on_a_different_network(cfg):
    other = FakeTransport(network="192.168.50.0/24", local_ip="192.168.50.7", gateway="192.168.50.1")
    with pytest.raises(OutOfScopeError):
        build_runtime(cfg, other)
    assert other.sweeps == []


def test_runtime_refuses_without_allow_list(tmp_path, fake):
    from netscan.config import Config

    with pytest.raises(OutOfScopeError):
        build_runtime(Config(home=tmp_path), fake)


# never block gateway / host

def test_never_blocks_gateway_or_host_by_ip_or_mac(rt):
    rt.tracker.observe([Host(GW_IP, GW_MAC), Host(HOST_IP, HOST_MAC), PHONE], now=1)
    mgr = BlockManager(rt.store, rt.scope)
    for ident in (GW_IP, GW_MAC, HOST_IP, HOST_MAC):
        with pytest.raises(ProtectedTargetError):
            mgr.block(ident)
    assert rt.store.list_blocks() == [], "refused blocks must not be persisted"
    mgr.block(PHONE.ip)
    assert rt.store.is_blocked(PHONE.mac)


def test_gateway_protected_even_if_it_changes_ip_record(rt):
    rt.tracker.observe([Host("192.168.1.99", GW_MAC)], now=1)
    with pytest.raises(ProtectedTargetError):
        BlockManager(rt.store, rt.scope).block(GW_MAC)


def test_extra_protected_entries_are_honoured(cfg, fake):
    cfg.extra_protected = [PHONE.mac]
    rt2 = build_runtime(cfg, fake)
    rt2.tracker.observe([PHONE], now=1)
    with pytest.raises(ProtectedTargetError):
        BlockManager(rt2.store, rt2.scope).block(PHONE.ip)
    rt2.store.close()


# first-run notice

def test_notice_refuses_non_interactive_until_accepted(tmp_path, capsys):
    path = tmp_path / "notice_accepted"
    with pytest.raises(NoticeNotAcceptedError):
        ensure_notice(path, interactive=False)
    assert not path.exists()
    assert "networks you OWN" in capsys.readouterr().err, "notice text must be shown"
    ensure_notice(path, accept=True)
    assert path.exists()
    ensure_notice(path, interactive=False)  # now silent


def test_notice_interactive_requires_literal_yes(tmp_path):
    path = tmp_path / "n"
    with pytest.raises(NoticeNotAcceptedError):
        ensure_notice(path, input_fn=lambda _: "y", interactive=True)
    ensure_notice(path, input_fn=lambda _: "YES", interactive=True)
    assert path.exists()


def test_cli_refuses_commands_before_notice_and_out_of_scope(tmp_path, capsys):
    other = FakeTransport(network="192.168.50.0/24", local_ip="192.168.50.7", gateway="192.168.50.1")
    (tmp_path / "config.toml").write_text(render_config(["192.168.1.0/24"]))
    assert cli.main(["--home", str(tmp_path), "scan"], transport=other) == 2, "scan must refuse before notice is accepted"
    assert other.sweeps == []
    rc = cli.main(["--home", str(tmp_path), "--accept-terms", "scan"], transport=other)
    assert rc == 2 and other.sweeps == [], "scan of a network outside the allow-list must be refused with no sweep"


def test_gateway_mac_pin_refuses_a_different_network_with_same_cidr(cfg, fake):
    cfg.gateway_mac = "de:ad:be:ef:00:01"
    fake.sent.clear()
    with pytest.raises(OutOfScopeError):
        build_runtime(cfg, fake)
    cfg.gateway_mac = GW_MAC.upper()
    build_runtime(cfg, fake).store.close()


def test_gateway_mac_pin_refuses_when_gateway_unresolvable(cfg, fake):
    cfg.gateway_mac = GW_MAC
    fake.macs.clear()
    with pytest.raises(OutOfScopeError):
        build_runtime(cfg, fake)


def test_init_pins_gateway_mac_and_config_loads(tmp_path):
    assert cli.main(["--home", str(tmp_path), "--accept-terms", "init"], transport=FakeTransport()) == 0
    cfg = load_config(home=tmp_path)
    assert cfg.gateway_mac == GW_MAC and cfg.allowed_subnets == [NET]


def test_config_rejects_flappy_intervals_and_bad_gateway_mac(tmp_path):
    (tmp_path / "config.toml").write_text("[daemon]\nsweep_interval=300\noffline_after=100\n")
    with pytest.raises(ConfigError):
        load_config(home=tmp_path)
    (tmp_path / "config.toml").write_text('[network]\ngateway_mac="nope"\n')
    with pytest.raises(ConfigError):
        load_config(home=tmp_path)


# follow_network (laptop use)

def test_follow_network_allows_the_connected_private_network_that_the_list_does_not_cover(cfg):
    other = FakeTransport(network="192.168.50.0/24", local_ip="192.168.50.7", gateway="192.168.50.1")
    with pytest.raises(OutOfScopeError):
        build_runtime(cfg, other)
    cfg.follow_network = True
    rt = build_runtime(cfg, other)
    assert rt.scope.contains("192.168.50.20") and rt.scope.contains("192.168.1.20"), "connected network and the listed one are both allowed"
    assert not rt.scope.contains("192.168.60.20"), "networks that are neither listed nor connected stay refused"
    assert cfg.allowed_subnets == [NET], "following must not rewrite the saved allow-list"
    rt.store.close()


def test_follow_network_still_refuses_a_public_or_huge_connected_network(cfg):
    for network, ip, gw in (("8.8.8.0/24", "8.8.8.7", "8.8.8.1"), ("10.0.0.0/8", "10.1.2.3", "10.0.0.1")):
        cfg.follow_network = True
        with pytest.raises(ConfigError):
            build_runtime(cfg, FakeTransport(network=network, local_ip=ip, gateway=gw))


def test_init_follow_writes_flag_without_pinning_and_default_init_is_unchanged(tmp_path):
    assert cli.main(["--home", str(tmp_path), "--accept-terms", "init", "--follow"], transport=FakeTransport()) == 0
    cfg = load_config(home=tmp_path)
    assert cfg.follow_network and cfg.gateway_mac == "", "a roaming config must not pin the router"
    other = tmp_path / "plain"
    assert cli.main(["--home", str(other), "--accept-terms", "init"], transport=FakeTransport()) == 0
    plain = load_config(home=other)
    assert not plain.follow_network and plain.gateway_mac == GW_MAC, "plain init keeps the home-network pin"
