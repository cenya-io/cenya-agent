# Cenya Agent

Open-source discovery agent for Cenya (Apache 2.0). It enrols with a one-time
code, sweeps the local network (ICMP/ARP, SNMP v2c/v3, SSH, WinRM, hypervisors)
and pushes what it finds over outbound HTTPS. No open ports, no local database.

See [`agent/README.md`](agent/README.md) for installation and usage. Installers
are published under [Releases](../../releases); `latest.json` in each release
carries the version, URL and SHA-256.
