"""Tarjetas y discos de una máquina virtual, plataforma por plataforma.

Lo que viaja al servidor tiene una sola forma (`agent/vmnet.py`): si un
cliente la rompe, la máquina entra sin direcciones o sin datastore y la traza
«¿De qué depende?» se queda a medias sin que nadie lo note.
"""

from __future__ import annotations

import unittest
from typing import Any

from agent import vmnet


class MacTests(unittest.TestCase):
    def test_every_spelling_ends_the_same(self) -> None:
        for raw in ("00:50:56:AA:BB:01", "00-50-56-aa-bb-01", "005056AABB01", "0050.56aa.bb01"):
            self.assertEqual(vmnet.mac(raw), "00:50:56:aa:bb:01")

    def test_what_is_not_a_mac_is_empty(self) -> None:
        for raw in (None, "", "vmbr0", "00:50:56", "zz:zz:zz:zz:zz:zz", 10):
            self.assertEqual(vmnet.mac(raw), "")


class InterfaceTests(unittest.TestCase):
    def test_a_vlan_out_of_range_or_zero_is_none(self) -> None:
        self.assertIsNone(vmnet.interface("a", "", [], 0)["vlan"])
        self.assertIsNone(vmnet.interface("a", "", [], 5000)["vlan"])
        self.assertIsNone(vmnet.interface("a", "", [], "diez")["vlan"])
        self.assertEqual(vmnet.interface("a", "", [], "10")["vlan"], 10)

    def test_addresses_that_are_not_a_list_are_dropped(self) -> None:
        self.assertEqual(vmnet.interface("a", "", "10.0.0.1")["ips"], [])


class DiskTests(unittest.TestCase):
    def test_two_disks_on_one_datastore_are_one_dependency(self) -> None:
        merged = vmnet.merge_disks([vmnet.disk("DS01", 10 * 1024**3), vmnet.disk("DS01", 5 * 1024**3), None])

        self.assertEqual(merged, [{"datastore": "DS01", "gb": 15}])

    def test_a_disk_without_datastore_is_not_a_disk(self) -> None:
        self.assertIsNone(vmnet.disk("", 100))


class VMwareTests(unittest.TestCase):
    DETAIL: dict[str, Any] = {
        "nics": {
            "4000": {"label": "Network adapter 1", "mac_address": "00:50:56:aa:bb:01"},
            "4001": {"label": "Network adapter 2", "mac_address": "00:50:56:aa:bb:02"},
        },
        "disks": {
            "2000": {"capacity": 100 * 1024**3, "backing": {"vmdk_file": "[DS01] srv/srv.vmdk"}},
            "2001": {"capacity": 20 * 1024**3, "backing": {"vmdk_file": "[DS-SSD] srv/srv_1.vmdk"}},
        },
    }
    GUEST = [
        {
            "mac_address": "00:50:56:AA:BB:01",
            "ip": {"ip_addresses": [{"ip_address": "10.0.0.25", "prefix_length": 24, "state": "PREFERRED"}]},
        }
    ]

    def test_the_datastore_is_the_name_between_brackets(self) -> None:
        self.assertEqual(vmnet.vmware_datastore("[datastore 1] a/b.vmdk"), "datastore 1")
        self.assertEqual(vmnet.vmware_datastore("sin corchetes"), "")

    def test_cards_come_with_the_addresses_the_tools_report(self) -> None:
        cards = vmnet.vmware_interfaces(self.DETAIL, self.GUEST)

        self.assertEqual(
            cards[0], {"name": "Network adapter 1", "mac": "00:50:56:aa:bb:01", "ips": ["10.0.0.25/24"], "vlan": None}
        )
        self.assertEqual(cards[1]["ips"], [])

    def test_disks_by_datastore(self) -> None:
        self.assertEqual(
            vmnet.vmware_disks(self.DETAIL),
            [{"datastore": "DS01", "gb": 100}, {"datastore": "DS-SSD", "gb": 20}],
        )

    def test_the_old_rest_shape_reads_the_same(self) -> None:
        """`/rest` en un vCenter 6.7 da las listas como `[{key, value}]`."""
        old = {
            "nics": [{"key": "4000", "value": self.DETAIL["nics"]["4000"]}],
            "disks": [{"key": "2000", "value": self.DETAIL["disks"]["2000"]}],
        }

        self.assertEqual(vmnet.vmware_interfaces(old)[0]["mac"], "00:50:56:aa:bb:01")
        self.assertEqual(vmnet.vmware_disks(old), [{"datastore": "DS01", "gb": 100}])

    def test_without_nics_or_disks_nothing_breaks(self) -> None:
        self.assertEqual(vmnet.vmware_interfaces({}), [])
        self.assertEqual(vmnet.vmware_disks({"disks": "raro"}), [])


class ProxmoxTests(unittest.TestCase):
    QEMU: dict[str, Any] = {
        "net0": "virtio=BC:24:11:AA:BB:CC,bridge=vmbr0,firewall=1,tag=10",
        "net1": "e1000=BC:24:11:AA:BB:DD,bridge=vmbr1",
        "scsi0": "local-lvm:vm-100-disk-0,iothread=1,size=32G",
        "scsi1": "ceph-ssd:vm-100-disk-1,size=512M",
        "ide2": "local:iso/debian.iso,media=cdrom,size=600M",
        "sata0": "none,media=cdrom",
        "agent": "1",
    }
    LXC: dict[str, Any] = {
        "net0": "name=eth0,bridge=vmbr0,hwaddr=BC:24:11:00:00:01,ip=192.168.1.5/24,ip6=dhcp,tag=20",
        "rootfs": "local-lvm:vm-101-disk-0,size=8G",
        "mp0": "nas-nfs:101/vm-101-disk-1.raw,mp=/datos,size=1T",
    }

    def test_a_kvm_reads_mac_vlan_and_disks(self) -> None:
        cards = vmnet.proxmox_interfaces(self.QEMU, container=False)

        self.assertEqual(cards[0], {"name": "net0", "mac": "bc:24:11:aa:bb:cc", "ips": [], "vlan": 10})
        self.assertEqual(cards[1]["vlan"], None)
        self.assertEqual(
            vmnet.proxmox_disks(self.QEMU, container=False),
            [{"datastore": "local-lvm", "gb": 32}, {"datastore": "ceph-ssd", "gb": 0}],
        )

    def test_the_qemu_agent_gives_the_addresses_by_mac(self) -> None:
        guest = {
            "result": [
                {
                    "name": "ens18",
                    "hardware-address": "bc:24:11:aa:bb:cc",
                    "ip-addresses": [{"ip-address": "10.0.0.30", "prefix": 24, "ip-address-type": "ipv4"}],
                }
            ]
        }

        cards = vmnet.proxmox_interfaces(self.QEMU, container=False, guest=guest)

        self.assertEqual(cards[0]["ips"], ["10.0.0.30/24"])

    def test_a_container_carries_its_address_in_the_config(self) -> None:
        cards = vmnet.proxmox_interfaces(self.LXC, container=True)

        self.assertEqual(cards, [{"name": "eth0", "mac": "bc:24:11:00:00:01", "ips": ["192.168.1.5/24"], "vlan": 20}])
        self.assertEqual(
            vmnet.proxmox_disks(self.LXC, container=True),
            [{"datastore": "local-lvm", "gb": 8}, {"datastore": "nas-nfs", "gb": 1024}],
        )


class WindowsDatastoreTests(unittest.TestCase):
    def test_each_kind_of_path(self) -> None:
        cases = {
            r"C:\ClusterStorage\Volume1\SRV\disk.vhdx": r"C:\ClusterStorage\Volume1",
            r"\\nas01\vms\SRV\disk.vhdx": r"\\nas01\vms",
            r"D:\Hyper-V\SRV\disk.vhdx": "D:",
            "": "",
            "relativo.vhdx": "",
        }
        for path, expected in cases.items():
            self.assertEqual(vmnet.windows_datastore(path), expected, path)


if __name__ == "__main__":
    unittest.main()
