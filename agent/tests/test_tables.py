"""Las tablas ARP y MAC leídas por SSH (`agent.tables`): un lector por
familia contra la salida tal cual la imprime cada CLI, y el colector SSH
mandándolas con la forma del hallazgo SNMP."""

from __future__ import annotations

import unittest
from unittest import mock

from agent import ssh, tables
from agent.collectors.ssh import SshCollector, with_tables
from agent.credentials import Credential
from agent.tests.test_ssh import _FakeSsh

LINUX_NEIGH = """\
10.0.0.1 dev eth0 lladdr 00:11:22:33:44:01 REACHABLE
10.0.0.7 dev eth0 lladdr 00:11:22:33:44:07 STALE
10.0.0.9 dev eth0  FAILED
fe80::1 dev eth0 lladdr 00:11:22:33:44:01 router STALE
10.0.0.3 dev eth0  INCOMPLETE
"""

IOS_ARP = """\
Protocol  Address          Age (min)  Hardware Addr   Type   Interface
Internet  192.168.1.1             -   aabb.cc00.0001  ARPA   Vlan1
Internet  192.168.1.20            3   0050.56aa.bb20  ARPA   Vlan1
Internet  192.168.1.33            0   Incomplete      ARPA
"""

IOS_MAC = """\
          Mac Address Table
-------------------------------------------

Vlan    Mac Address       Type        Ports
----    -----------       --------    -----
 All    0100.0ccc.cccc    STATIC      CPU
  10    0050.56aa.bb20    DYNAMIC     Gi1/0/3
  10    0050.56aa.bb21    DYNAMIC     Gi1/0/3
  20    aabb.cc00.0009    DYNAMIC     Po1
Total Mac Addresses for this criterion: 4
"""

DELL_MAC = """\
Aging time is 300 Sec

Vlan     Mac Address           Type        Port
-------- --------------------- ----------- ---------------------
1        0012.3456.789A        Dynamic     Gi1/0/1
1        0012.3456.789B        Management  Vlan1
"""

PROCURVE_MAC = """\
 Status and Counters - Port Address Table

  MAC Address   Port   VLAN
  ------------- ------ ----
  001b3f-aabbcc 1      10
  001b3f-aabbcd 24     10
  0050c2-112233 A1     20
"""

PROCURVE_ARP = """\
 IP ARP table

  IP Address      MAC Address       Type    Port
  --------------- ----------------- ------- ----
  10.1.1.1        001b3f-aabbcc     dynamic 1
  10.1.1.254      0050c2-112233     dynamic A1
"""

VRP_MAC = """\
MAC Address    VLAN/VSI/BD   Learned-From        Type
-------------------------------------------------------------------------------
aabb-cc00-0001 10/-/-        GE0/0/1             dynamic
aabb-cc00-0002 10/-/-        Eth-Trunk1          dynamic
-------------------------------------------------------------------------------
Total items displayed = 2
"""

VRP_ARP = """\
IP ADDRESS      MAC ADDRESS     EXPIRE(M) TYPE        INTERFACE   VPN-INSTANCE
------------------------------------------------------------------------------
10.2.0.1        aabb-cc00-0001            I -         Vlanif10
10.2.0.50       0050-56aa-bb50  18        D-0         GE0/0/1
------------------------------------------------------------------------------
"""

COMWARE_MAC = """\
MAC Address      VLAN ID    State            Port/Nickname            Aging
aabb-cc00-0001   10         Learned          GE1/0/1                  Y
aabb-cc00-0002   20         Learned          BAGG1                    Y
"""

JUNOS_MAC_OLD = """\
Ethernet-switching table: 3 entries, 2 learned
  VLAN              MAC address       Type         Age Interfaces
  default           *                 Flood          - All-members
  default           aa:bb:cc:00:00:01 Learn          0 ge-0/0/1.0
  default           aa:bb:cc:00:00:02 Static         - Router
"""

JUNOS_MAC_ELS = """\
MAC flags (S - static MAC, D - dynamic MAC, L - locally learned, P - Persistent static)

Ethernet switching table : 1 entries, 1 learned
Routing instance : default-switch
    Vlan                MAC                 MAC         Age    Logical                NH        RTR
    name                address             flags              interface              Index     ID
    default             aa:bb:cc:00:00:03   D             -   ae0.0                  0         0
"""

JUNOS_ARP = """\
MAC Address       Address         Interface     Flags
aa:bb:cc:00:00:01 10.3.0.10       vlan.0        none
aa:bb:cc:00:00:03 10.3.0.11       ae0.0         none
Total entries: 2
"""

MIKROTIK_HOSTS = """\
Flags: X - disabled, I - invalid, D - dynamic, L - local, E - external
 #   MAC-ADDRESS       VID ON-INTERFACE    BRIDGE
 0 D AA:BB:CC:00:00:01     ether2          bridge1
 1 D AA:BB:CC:00:00:02  10 ether3          bridge1
 2 L AA:BB:CC:00:00:FF     bridge1         bridge1
"""

MIKROTIK_ARP = """\
Flags: X - disabled, I - invalid, H - DHCP, D - dynamic, P - published, C - complete
 #    ADDRESS         MAC-ADDRESS       INTERFACE
 0 DC 192.168.88.10   AA:BB:CC:00:00:01 bridge1
 1 DC 192.168.88.11   AA:BB:CC:00:00:02 bridge1
 2 D  192.168.88.99                     bridge1
"""

FORTI_ARP = """\
Address           Age(min)   Hardware Addr      Interface
10.4.0.1          0          00:09:0f:aa:bb:01  port1
10.4.0.20         3          0050:56aa:bb20     port2
"""


class ArpParsingTests(unittest.TestCase):
    def test_linux_neigh_keeps_what_has_a_mac_and_drops_failed_and_incomplete(self) -> None:
        rows = tables.parse_arp(LINUX_NEIGH)
        self.assertEqual(
            rows,
            [
                {"ip": "10.0.0.1", "mac": "00:11:22:33:44:01"},
                {"ip": "10.0.0.7", "mac": "00:11:22:33:44:07"},
                {"ip": "fe80::1", "mac": "00:11:22:33:44:01"},
            ],
        )

    def test_ios_dotted_macs_and_the_incomplete_row(self) -> None:
        rows = tables.parse_arp(IOS_ARP)
        self.assertEqual([r["ip"] for r in rows], ["192.168.1.1", "192.168.1.20"])
        self.assertEqual(rows[0]["mac"], "aa:bb:cc:00:00:01")

    def test_every_vendor_spelling_of_a_mac(self) -> None:
        self.assertEqual(tables.parse_arp(PROCURVE_ARP)[0], {"ip": "10.1.1.1", "mac": "00:1b:3f:aa:bb:cc"})
        self.assertEqual(tables.parse_arp(VRP_ARP)[1], {"ip": "10.2.0.50", "mac": "00:50:56:aa:bb:50"})
        self.assertEqual(tables.parse_arp(JUNOS_ARP)[0], {"ip": "10.3.0.10", "mac": "aa:bb:cc:00:00:01"})
        self.assertEqual(len(tables.parse_arp(MIKROTIK_ARP)), 2)
        self.assertEqual(tables.parse_arp(FORTI_ARP)[0]["mac"], "00:09:0f:aa:bb:01")

    def test_header_lines_and_counters_are_not_rows(self) -> None:
        self.assertEqual(tables.parse_arp("Total entries: 2\nProtocol Address Age\n"), [])
        self.assertEqual(tables.parse_arp(""), [])

    def test_a_multicast_mac_is_not_a_neighbour(self) -> None:
        self.assertEqual(tables.parse_arp("224.0.0.251 01:00:5e:00:00:fb\n"), [])


class MacTableParsingTests(unittest.TestCase):
    def test_ios_rows_carry_vlan_and_port_and_the_cpu_row_is_dropped(self) -> None:
        rows = tables.parse_mac_table("cisco", IOS_MAC)
        self.assertEqual(
            rows,
            [
                {"mac": "00:50:56:aa:bb:20", "ifindex": "Gi1/0/3", "vlan": "10"},
                {"mac": "00:50:56:aa:bb:21", "ifindex": "Gi1/0/3", "vlan": "10"},
                {"mac": "aa:bb:cc:00:00:09", "ifindex": "Po1", "vlan": "20"},
            ],
        )

    def test_dell_os6_reads_like_ios_without_its_management_row(self) -> None:
        rows = tables.parse_mac_table("dell", DELL_MAC)
        self.assertEqual(rows, [{"mac": "00:12:34:56:78:9a", "ifindex": "Gi1/0/1", "vlan": "1"}])

    def test_procurve_rows(self) -> None:
        rows = tables.parse_mac_table("aruba", PROCURVE_MAC)
        self.assertEqual([(r["ifindex"], r["vlan"]) for r in rows], [("1", "10"), ("24", "10"), ("A1", "20")])
        self.assertEqual(rows[0]["mac"], "00:1b:3f:aa:bb:cc")

    def test_vrp_and_comware_rows(self) -> None:
        vrp = tables.parse_mac_table("huawei", VRP_MAC)
        self.assertEqual([(r["ifindex"], r["vlan"]) for r in vrp], [("GE0/0/1", "10"), ("Eth-Trunk1", "10")])
        comware = tables.parse_mac_table("comware", COMWARE_MAC)
        self.assertEqual([(r["ifindex"], r["vlan"]) for r in comware], [("GE1/0/1", "10"), ("BAGG1", "20")])

    def test_junos_old_and_els_layouts(self) -> None:
        old = tables.parse_mac_table("junos", JUNOS_MAC_OLD)
        self.assertEqual(old, [{"mac": "aa:bb:cc:00:00:01", "ifindex": "ge-0/0/1", "vlan": ""}])
        els = tables.parse_mac_table("junos", JUNOS_MAC_ELS)
        self.assertEqual(els, [{"mac": "aa:bb:cc:00:00:03", "ifindex": "ae0", "vlan": ""}])

    def test_mikrotik_bridge_hosts_skip_the_local_ones(self) -> None:
        rows = tables.parse_mac_table("mikrotik", MIKROTIK_HOSTS)
        self.assertEqual(
            rows,
            [
                {"mac": "aa:bb:cc:00:00:01", "ifindex": "ether2", "vlan": ""},
                {"mac": "aa:bb:cc:00:00:02", "ifindex": "ether3", "vlan": "10"},
            ],
        )

    def test_a_family_without_a_reader_has_no_table(self) -> None:
        self.assertEqual(tables.parse_mac_table("fortinet", IOS_MAC), [])
        self.assertEqual(tables.parse_mac_table("linux", ""), [])

    def test_read_tables_asks_only_what_the_family_has(self) -> None:
        asked: list[str] = []

        def ask(command: str) -> str:
            asked.append(command)
            return FORTI_ARP if "arp" in command else ""

        found = tables.read_tables("fortinet", ask)
        self.assertEqual(asked, ["get system arp"])
        self.assertEqual(len(found["arp"]), 2)
        self.assertNotIn("fdb", found)
        self.assertEqual(tables.read_tables("esxi", ask), {})


class SshCollectorTablesTests(unittest.TestCase):
    ROOT = Credential(kind="ssh", username="admin", secret="x")

    def test_with_tables_uses_the_credential_that_got_in(self) -> None:
        fake = _FakeSsh({"show ip arp": ssh.Answer(connected=True, output=IOS_ARP),
                         "show mac address-table": ssh.Answer(connected=True, output=IOS_MAC)})
        with mock.patch("agent.collectors.ssh.ssh.run", fake):
            data = with_tables("192.168.1.1", self.ROOT, {"family": "cisco", "hostname": "sw"})
        self.assertEqual([c for _u, c in fake.calls], ["show ip arp", "show mac address-table"])
        self.assertEqual(len(data["arp"]), 2)
        self.assertEqual(len(data["fdb"]), 3)

    def test_a_family_without_orders_is_not_asked(self) -> None:
        fake = _FakeSsh({})
        with mock.patch("agent.collectors.ssh.ssh.run", fake):
            data = with_tables("192.168.1.1", self.ROOT, {"family": "esxi"})
        self.assertEqual(fake.calls, [])
        self.assertNotIn("arp", data)

    def test_the_finding_carries_the_tables_and_proposes_links_for_known_macs(self) -> None:
        """A switch read by SSH: its MAC table places the VM host it knows
        behind Gi1/0/3, in the same shape the SNMP collector produces."""
        switch = {
            "family": "cisco",
            "hostname": "sw-planta",
            "description": "IOS",
            "os": "IOS",
            "interfaces": [{"name": "Vlan1", "mac": "aa:bb:cc:00:00:01", "status": "up", "ip": "192.168.1.1"}],
            "arp": tables.parse_arp(IOS_ARP),
            "fdb": tables.parse_mac_table("cisco", IOS_MAC),
        }
        ctx = {
            "config": {"credentials": [{"kind": "ssh", "username": "admin", "secret": "x"}]},
            "env": None,
            "hosts": [{"ip": "192.168.1.1", "mac": "aa:bb:cc:00:00:01"}, {"ip": "192.168.1.20", "mac": "00:50:56:aa:bb:20"}],
        }
        with mock.patch("agent.collectors.ssh.ssh.AVAILABLE", True), \
             mock.patch("agent.collectors.ssh.ssh.PASSWORD_AUTH_AVAILABLE", True), \
             mock.patch("agent.collectors.ssh.net.hosts_listening", return_value=["192.168.1.1"]), \
             mock.patch("agent.collectors.ssh.interrogate", return_value=(switch, self.ROOT)), \
             mock.patch("agent.collectors.ssh.stack_members", side_effect=lambda ip, c, d, l: d), \
             mock.patch("agent.collectors.ssh.with_tables", side_effect=lambda ip, c, d, l: d):
            findings = SshCollector().collect(ctx)

        host = next(f for f in findings if f.kind == "host")
        self.assertEqual(host.payload["arp"][1], {"ip": "192.168.1.20", "mac": "00:50:56:aa:bb:20"})
        ports = {p["port"]: p for p in host.payload["fdb_ports"]}
        self.assertEqual(ports["Gi1/0/3"]["count"], 2)
        links = [f for f in findings if f.kind == "link"]
        # Only the MAC the sweep knows (the VM host) becomes a cable; the
        # stranger on Po1 does not.
        self.assertEqual(len(links), 1)
        self.assertEqual(links[0].payload["local"]["port"], "Gi1/0/3")
        self.assertEqual(links[0].payload["remote"]["device_ip"], "192.168.1.20")
        self.assertEqual(links[0].payload["vlan"], 10)

    def test_a_host_without_tables_has_the_same_finding_as_before(self) -> None:
        linux = {"family": "linux", "hostname": "srv", "description": "Ubuntu", "os": "Ubuntu", "interfaces": []}
        ctx = {
            "config": {"credentials": [{"kind": "ssh", "username": "admin", "secret": "x"}]},
            "env": None,
            "hosts": [{"ip": "192.168.1.5", "mac": ""}],
        }
        with mock.patch("agent.collectors.ssh.ssh.AVAILABLE", True), \
             mock.patch("agent.collectors.ssh.ssh.PASSWORD_AUTH_AVAILABLE", True), \
             mock.patch("agent.collectors.ssh.net.hosts_listening", return_value=["192.168.1.5"]), \
             mock.patch("agent.collectors.ssh.interrogate", return_value=(linux, self.ROOT)), \
             mock.patch("agent.collectors.ssh.stack_members", side_effect=lambda ip, c, d, l: d), \
             mock.patch("agent.collectors.ssh.with_tables", side_effect=lambda ip, c, d, l: d):
            findings = SshCollector().collect(ctx)

        self.assertEqual(len(findings), 1)
        self.assertNotIn("arp", findings[0].payload)
        self.assertNotIn("fdb_ports", findings[0].payload)


if __name__ == "__main__":
    unittest.main()
