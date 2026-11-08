"""Testes do módulo de descoberta de ambiente (core.environment)."""

import json
import unittest
from ipaddress import IPv4Address, IPv4Interface, IPv4Network

from core import environment as env
from core.environment import (
    GatewayInfo,
    InterfaceInfo,
    PacketCaptureInfo,
)


def make_iface(name, *cidrs, mac="aa:bb:cc:dd:ee:01", up=True,
               loopback=False, virtual=False):
    return InterfaceInfo(
        name=name,
        mac=mac,
        ipv4=tuple(IPv4Interface(c) for c in cidrs),
        is_up=up,
        is_loopback=loopback,
        is_virtual=virtual,
    )


WINDOWS_ROUTE_PRINT_PT = """\
===========================================================================
Lista de interfaces
 12...9c c7 d3 22 4a b8 ......Intel(R) Wi-Fi 6 AX201 160MHz
  1...........................Software Loopback Interface 1
===========================================================================

IPv4 Tabela de rota
===========================================================================
Rotas ativas:
Endereço de rede             Máscara     Ender. gateway    Interface  Custo
          0.0.0.0          0.0.0.0     192.168.15.1    192.168.15.17     30
          0.0.0.0          0.0.0.0         10.0.0.1         10.0.0.5     10
        127.0.0.0        255.0.0.0         No vínculo         127.0.0.1    331
     192.168.15.0    255.255.255.0         No vínculo     192.168.15.17    286
===========================================================================
Rotas persistentes:
  Nenhuma
"""

PROC_NET_ROUTE = """\
Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT
eth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0
eth0\t0001A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0
wlan0\t00000000\t010F000A\t0003\t0\t0\t50\t00000000\t0\t0\t0
"""

BSD_ROUTE_GET = """\
   route to: default
destination: default
       mask: default
    gateway: 192.168.0.1
  interface: en0
      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING>
"""


class MacAndVirtualTests(unittest.TestCase):
    def test_normalize_mac(self):
        self.assertEqual(env.normalize_mac("9C-C7-D3-22-4A-B8"), "9c:c7:d3:22:4a:b8")
        self.assertIsNone(env.normalize_mac("00-00-00-00-00-00"))
        self.assertIsNone(env.normalize_mac(""))
        self.assertIsNone(env.normalize_mac("00-00-00-00-00-00-00-e0"))

    def test_virtual_by_name(self):
        for name in ("vEthernet (WSL)", "docker0", "VirtualBox Host-Only Network",
                     "tun0", "wg0", "br-1a2b3c"):
            self.assertTrue(env.is_virtual_interface(name, None), name)
        for name in ("Wi-Fi", "Ethernet", "eth0", "wlan0", "en0"):
            self.assertFalse(env.is_virtual_interface(name, "9c:c7:d3:22:4a:b8"), name)

    def test_virtual_by_mac_oui(self):
        self.assertTrue(env.is_virtual_interface("Ethernet 3", "00:15:5d:01:02:03"))
        self.assertTrue(env.is_virtual_interface("ens33", "00:0c:29:aa:bb:cc"))


class GatewayParsingTests(unittest.TestCase):
    def test_windows_route_print_localized(self):
        gws = env.parse_windows_route_print(WINDOWS_ROUTE_PRINT_PT)
        self.assertEqual([str(g.ip) for g in gws], ["10.0.0.1", "192.168.15.1"])
        self.assertEqual(gws[0].metric, 10)
        self.assertEqual(gws[1].source_ip, IPv4Address("192.168.15.17"))

    def test_proc_net_route(self):
        gws = env.parse_proc_net_route(PROC_NET_ROUTE)
        self.assertEqual(
            [(str(g.ip), g.interface) for g in gws],
            [("10.0.15.1", "wlan0"), ("192.168.1.1", "eth0")],
        )

    def test_bsd_route_get(self):
        gws = env.parse_bsd_route_get(BSD_ROUTE_GET)
        self.assertEqual(gws, [GatewayInfo(IPv4Address("192.168.0.1"), "en0")])
        self.assertEqual(env.parse_bsd_route_get("route: not in table"), [])

    def test_gateway_matches_interface(self):
        wifi = make_iface("Wi-Fi", "192.168.15.17/24")
        self.assertTrue(env.gateway_matches_interface(
            GatewayInfo(IPv4Address("192.168.15.1")), wifi))
        self.assertTrue(env.gateway_matches_interface(
            GatewayInfo(IPv4Address("10.9.9.9"), "Wi-Fi"), wifi))
        self.assertFalse(env.gateway_matches_interface(
            GatewayInfo(IPv4Address("10.0.0.1"), "eth1"), wifi))


class DnsTests(unittest.TestCase):
    def test_resolv_conf(self):
        text = (
            "# comentário\nnameserver 1.1.1.1\nnameserver fe80::1\n"
            "nameserver 8.8.8.8 # google\nsearch lan\nnameserver 1.1.1.1\n"
        )
        self.assertEqual(
            env.parse_resolv_conf(text),
            [IPv4Address("1.1.1.1"), IPv4Address("8.8.8.8")],
        )

    def test_select_windows_dns_filters_inactive_and_prefers_primary(self):
        a = IPv4Address
        entries = [
            ({a("10.8.0.2")}, [a("10.8.0.1")]),                 # VPN desconectada
            ({a("172.20.0.5")}, [a("172.20.0.1")]),             # outra ativa
            ({a("192.168.15.17")}, [a("192.168.15.1"), a("8.8.8.8")]),
            (set(), [a("9.9.9.9")]),                            # sem IP
        ]
        active = {a("192.168.15.17"), a("172.20.0.5")}
        self.assertEqual(
            env.select_windows_dns(entries, active, a("192.168.15.17")),
            [a("192.168.15.1"), a("8.8.8.8"), a("172.20.0.1")],
        )


class CapabilityTests(unittest.TestCase):
    NPCAP_OPEN = PacketCaptureInfo(True, "Npcap", requires_admin=False)
    NPCAP_ADMIN = PacketCaptureInfo(True, "Npcap", requires_admin=True)
    NONE = PacketCaptureInfo(False, None, requires_admin=True)

    def caps(self, **overrides):
        params = dict(is_admin=False, cap_net_raw=False, raw_socket=False,
                      unprivileged_icmp=False, packet_capture=self.NPCAP_ADMIN,
                      ping_command="/bin/ping")
        params.update(overrides)
        return env.derive_capabilities(**params)

    def test_layer2_requires_privilege_or_open_driver(self):
        self.assertFalse(self.caps().layer2)
        self.assertTrue(self.caps(is_admin=True).layer2)
        self.assertTrue(self.caps(cap_net_raw=True).layer2)
        self.assertTrue(self.caps(packet_capture=self.NPCAP_OPEN).layer2)
        self.assertFalse(self.caps(is_admin=True, packet_capture=self.NONE).layer2)

    def test_icmp_method_priority(self):
        self.assertEqual(self.caps(raw_socket=True, unprivileged_icmp=True).icmp_method, "raw")
        self.assertEqual(self.caps(unprivileged_icmp=True).icmp_method, "unprivileged")
        self.assertEqual(self.caps().icmp_method, "system")
        none = self.caps(ping_command=None)
        self.assertIsNone(none.icmp_method)
        self.assertFalse(none.icmp_scan)
        self.assertTrue(none.tcp_connect)

    def test_cap_net_raw_parsing(self):
        self.assertTrue(env.parse_cap_net_raw("Name:\tpython\nCapEff:\t0000000000002000\n"))
        self.assertTrue(env.parse_cap_net_raw("CapEff:\t000001ffffffffff\n"))
        self.assertFalse(env.parse_cap_net_raw("CapEff:\t0000000000000000\n"))
        self.assertFalse(env.parse_cap_net_raw(""))

    def test_warnings(self):
        w = env.capability_warnings(self.caps(packet_capture=self.NONE), env.WINDOWS)
        self.assertTrue(any("Npcap" in m for m in w))
        w = env.capability_warnings(self.caps(), env.LINUX)
        self.assertTrue(any("root/CAP_NET_RAW" in m for m in w))
        w = env.capability_warnings(
            self.caps(is_admin=True, raw_socket=True), env.LINUX)
        self.assertEqual(w, [])


class PrimaryInterfaceTests(unittest.TestCase):
    def setUp(self):
        self.lo = make_iface("lo", "127.0.0.1/8", mac=None, loopback=True)
        self.wsl = make_iface("vEthernet (WSL)", "172.20.0.1/20", virtual=True)
        self.wifi = make_iface("Wi-Fi", "192.168.15.17/24")
        self.down = make_iface("Ethernet", "10.0.0.5/24", up=False)
        self.all = [self.lo, self.wsl, self.down, self.wifi]

    def test_by_gateway(self):
        gws = [GatewayInfo(IPv4Address("192.168.15.1"), source_ip=IPv4Address("192.168.15.17"))]
        self.assertEqual(env.select_primary_interface(self.all, gws), self.wifi)

    def test_ignores_gateway_of_down_interface(self):
        gws = [GatewayInfo(IPv4Address("10.0.0.1"), metric=1)]
        self.assertEqual(env.select_primary_interface(self.all, gws), self.wifi)

    def test_by_outbound_ip(self):
        self.assertEqual(
            env.select_primary_interface(self.all, [], IPv4Address("172.20.0.1")),
            self.wsl,
        )

    def test_fallback_prefers_physical(self):
        self.assertEqual(env.select_primary_interface(self.all, []), self.wifi)
        self.assertIsNone(env.select_primary_interface([self.lo, self.down], []))


class ScanTargetTests(unittest.TestCase):
    def test_primary_first_and_virtual_skipped(self):
        wsl = make_iface("vEthernet (WSL)", "172.20.0.1/24", virtual=True)
        eth = make_iface("Ethernet", "10.1.1.10/24")
        wifi = make_iface("Wi-Fi", "192.168.15.17/24")
        targets, warnings = env.suggest_scan_targets([wsl, eth, wifi], wifi)
        self.assertEqual(
            [(str(t.network), t.reason) for t in targets],
            [("192.168.15.0/24", "rota padrão"), ("10.1.1.0/24", "interface física")],
        )
        self.assertEqual(warnings, [])

        targets, _ = env.suggest_scan_targets([wsl, wifi], wifi, include_virtual=True)
        self.assertIn(IPv4Network("172.20.0.0/24"), [t.network for t in targets])

    def test_virtual_primary_is_kept(self):
        vm = make_iface("ens33", "192.168.56.10/24", virtual=True)
        targets, _ = env.suggest_scan_targets([vm], vm)
        self.assertEqual([str(t.network) for t in targets], ["192.168.56.0/24"])

    def test_large_network_is_narrowed_around_local_ip(self):
        corp = make_iface("eth0", "10.20.130.7/16")
        targets, warnings = env.suggest_scan_targets([corp], corp, max_hosts=254)
        self.assertEqual(targets[0].network, IPv4Network("10.20.130.0/24"))
        self.assertEqual(targets[0].truncated_from, IPv4Network("10.20.0.0/16"))
        self.assertEqual(targets[0].num_hosts, 254)
        self.assertTrue(any("limitada" in w for w in warnings))

    def test_apipa_point_to_point_and_duplicates(self):
        apipa = make_iface("Ethernet", "169.254.19.63/16")
        ptp = make_iface("ppp0", "100.64.0.2/32")
        a = make_iface("eth0", "192.168.1.10/24")
        b = make_iface("eth1", "192.168.1.11/24")
        targets, warnings = env.suggest_scan_targets([apipa, ptp, a, b], a)
        self.assertEqual([t.interface for t in targets], ["eth0"])
        self.assertTrue(any("APIPA" in w for w in warnings))

    def test_public_network_warning(self):
        pub = make_iface("eth0", "8.8.4.10/28")
        _, warnings = env.suggest_scan_targets([pub], pub)
        self.assertTrue(any("não é privada" in w for w in warnings))

    def test_only_virtual_interfaces_warning(self):
        docker = make_iface("docker0", "172.17.0.1/16", virtual=True)
        targets, warnings = env.suggest_scan_targets([docker], None)
        self.assertEqual(targets, [])
        self.assertTrue(any("docker0" in w for w in warnings))


class DiscoverEnvironmentSmokeTest(unittest.TestCase):
    """Executa a descoberta real na máquina: não deve lançar exceções."""

    def test_real_discovery_is_serializable(self):
        info = env.discover_environment()
        data = json.loads(json.dumps(info.to_dict()))
        self.assertEqual(data["os_family"], env.current_os_family())
        self.assertIn("capabilities", data)
        self.assertTrue(info.capabilities.tcp_connect)
        for target in info.scan_targets:
            self.assertIn(target.local_ip, target.network)
            self.assertTrue(info.is_local(target.local_ip))


if __name__ == "__main__":
    unittest.main()
