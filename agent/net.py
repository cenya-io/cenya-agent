"""OS-level network probing, standard library only.

Everything here is built on what any Windows or Linux box already has: the
system ``ping``, the ``arp`` command and the resolver. No raw sockets (they
need root), no scapy (GPL -- not allowed in this project). The ARP output is
parsed with plain IP/MAC regexes so the language of the operating system does
not matter.
"""

from __future__ import annotations

import ipaddress
import itertools
import platform
import re
import socket
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Callable

PING_TIMEOUT_MS = 500
SWEEP_WORKERS = 50
# A /22 is 1022 addresses; anything bigger is a datacenter, not a small
# business LAN, and sweeping it by ICMP echo is the wrong tool anyway.
MAX_SWEEP_HOSTS = 1022

_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_MAC_RE = re.compile(r"\b(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}\b")


def primary_ip() -> str:
    """The address this host uses to reach the world, without sending a byte.

    The UDP "connect" trick only picks a route; nothing leaves the machine.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.connect(("192.0.2.1", 80))  # TEST-NET-1, never actually sent
            return str(probe.getsockname()[0])
    except OSError:
        return ""


def own_subnet() -> str:
    """The /24 this host sits in -- the sensible default sweep."""
    ip = primary_ip()
    if not ip:
        return ""
    return str(ipaddress.ip_network(f"{ip}/24", strict=False))


def expand_subnets(subnets: list[str]) -> list[str]:
    """Every address to probe, capped so a pasted /8 does not run for a week.

    **El recorte va dentro del recorrido, no después.** Materializar la red
    entera para quedarse con las primeras mil no era una ineficiencia: una /12
    son 1.048.574 direcciones y más de un giga de memoria en la máquina del
    cliente, y una /8 son dieciséis millones. `islice` sobre el generador
    resuelve el mismo caso sin construir nada.

    **IPv6 se descarta.** `ip_network("2001:db8::/64").hosts()` es un generador
    de 1,8·10¹⁹ elementos: cualquier intento de recorrerlo no termina. El
    barrido por ICMP no es la herramienta para IPv6 de todos modos -- ahí se
    descubre por vecindad, no probando direcciones una a una.
    """
    addresses: list[str] = []
    for subnet in subnets:
        try:
            network = ipaddress.ip_network(subnet.strip(), strict=False)
        except ValueError:
            continue
        if network.version != 4:
            continue
        addresses.extend(str(host) for host in itertools.islice(network.hosts(), MAX_SWEEP_HOSTS))
    return addresses


def ping_command(ip: str) -> list[str]:
    """The system's own ping. Windows counts milliseconds with ``-w`` and
    counts packets with ``-n``; Linux wants ``-W`` seconds and ``-c``."""
    if platform.system() == "Windows":
        return ["ping", "-n", "1", "-w", str(PING_TIMEOUT_MS), ip]
    return ["ping", "-c", "1", "-W", "1", ip]


def ping(ip: str) -> bool:
    try:
        result = subprocess.run(
            ping_command(ip),
            capture_output=True,
            text=True,
            errors="replace",
            timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    if result.returncode != 0:
        return False
    if platform.system() != "Windows":
        return True
    # ping.exe devuelve 0 también cuando un router contesta «Destination host
    # unreachable»: para él hubo respuesta, aunque el host esté muerto. En
    # subredes enrutadas eso era un falso vivo por dirección. Una respuesta de
    # verdad lleva «TTL=», y ese literal no cambia con el idioma del sistema.
    return "TTL=" in result.stdout.upper()


def sweep(
    addresses: list[str],
    workers: int = SWEEP_WORKERS,
    on_done: Callable[[], None] | None = None,
) -> list[str]:
    """The addresses that answered, in the order they were probed.

    ``workers`` is how many pings at once (the task's gentleness);
    ``on_done`` is called after each ping, for the progress bar, and whatever
    it raises is swallowed: reporting progress never breaks a sweep.
    """

    def probe(ip: str) -> bool:
        try:
            return ping(ip)
        finally:
            if on_done is not None:
                try:
                    on_done()
                except Exception:  # noqa: BLE001
                    pass

    alive: list[str] = []
    with ThreadPoolExecutor(max_workers=max(1, int(workers))) as pool:
        for ip, answered in zip(addresses, pool.map(probe, addresses)):
            if answered:
                alive.append(ip)
    return alive


def arp_table() -> dict[str, str]:
    """IP -> MAC from the system ARP cache, whatever language the OS speaks.

    A ping sweep fills the cache on the way, so running this right after the
    sweep is what turns "it answered" into "it is this physical machine".

    Two commands, in order: ``arp -a`` first (Windows and any Linux with
    net-tools), and ``ip neigh`` as the fallback -- a minimal Debian or Ubuntu
    server stopped shipping ``arp`` years ago, and without the fallback every
    host came back MAC-less there: identity degraded to the IP, a host that
    changed address opened a duplicate row, and confidence never left
    "endeble".
    """
    table = _neighbours(["arp", "-a"])
    if not table:
        # En Windows `ip` no existe y esto devuelve {} sin ruido; en un Linux
        # sin net-tools es el camino normal, no el excepcional.
        table = _neighbours(["ip", "neigh"])
    return table


def _neighbours(command: list[str]) -> dict[str, str]:
    """Whatever IP/MAC pairs that command prints, language-proof.

    `errors="replace"`: en un Windows en español la salida de `arp -a` llega
    en la página de códigos OEM y decodificarla en estricto lanza
    `UnicodeDecodeError`, que no es de los que se capturan abajo y se llevaba
    por delante el barrido entero, no solo las MAC.
    """
    try:
        output = subprocess.run(
            command, capture_output=True, text=True, errors="replace", timeout=30
        ).stdout
    except (OSError, subprocess.TimeoutExpired):
        return {}
    table: dict[str, str] = {}
    for line in output.splitlines():
        ip_match = _IP_RE.search(line)
        mac_match = _MAC_RE.search(line)
        if ip_match and mac_match:
            table[ip_match.group()] = mac_match.group().lower().replace("-", ":")
    return table


#: Cuánto se espera a una resolución inversa. Era la única operación del
#: barrido sin tope propio: un resolvedor colgado retenía su hilo sin límite.
REVERSE_DNS_TIMEOUT_SECONDS = 5.0


def reverse_dns(ip: str, timeout: float = REVERSE_DNS_TIMEOUT_SECONDS) -> str:
    """The PTR name, or "" -- and never more than ``timeout`` of waiting.

    ``gethostbyaddr`` has no timeout of its own and does not honour
    ``socket.setdefaulttimeout`` (it is a resolver call, not a socket op), so
    the bounded wait lives here: a daemon thread does the lookup and we stop
    waiting for it. A pathological resolver leaks that thread until the OS
    resolver gives up on it, which is bounded too -- the sweep's wall time is
    what this protects.
    """
    answer: dict[str, str] = {}

    def look_up() -> None:
        try:
            answer["name"] = socket.gethostbyaddr(ip)[0]
        except (OSError, socket.herror):
            pass

    worker = threading.Thread(target=look_up, daemon=True)
    worker.start()
    worker.join(timeout)
    return answer.get("name", "")


def resolve(name: str) -> str:
    """La dirección de ese nombre, o vacío. Un nombre que ya es una IP se
    devuelve tal cual.

    Hace falta para los hipervisores: el vCenter llama a sus servidores por el
    nombre con el que se dieron de alta, y sin traducirlo a una dirección el
    hallazgo no se fusiona con el que dejó el barrido para esa misma máquina.
    """
    name = (name or "").strip()
    if not name:
        return ""
    try:
        ipaddress.ip_address(name)
    except ValueError:
        pass
    else:
        return name
    try:
        return socket.gethostbyname(name)
    except (OSError, UnicodeError):
        return ""


#: Cuánto se espera a que un puerto conteste. Corto a propósito: esto se hace
#: contra todos los hosts vivos de la red, y un segundo por host son cuatro
#: minutos en una /24 llena.
PORT_TIMEOUT_SECONDS = 1.0
PORT_WORKERS = 50


def port_open(ip: str, port: int, timeout: float = PORT_TIMEOUT_SECONDS) -> bool:
    """¿Escucha algo ahí? Un TCP que abre y cierra, sin enviar nada.

    Existe para que SSH y WinRM no intenten autenticarse contra los ciento
    veinte equipos que contestaron al ping: sin esto, cada intento se come su
    tiempo de espera y el barrido pasa de segundos a media hora.
    """
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except (OSError, ValueError):
        return False


def hosts_listening(ips: list[str], port: int, workers: int = PORT_WORKERS) -> list[str]:
    """Los que tienen ese puerto abierto, en el orden en que se probaron."""
    if not ips:
        return []
    with ThreadPoolExecutor(max_workers=max(1, int(workers))) as pool:
        answers = pool.map(lambda ip: port_open(ip, port), ips)
        return [ip for ip, listening in zip(ips, answers) if listening]
