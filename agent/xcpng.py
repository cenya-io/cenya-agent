"""XCP-ng (y XenServer/Citrix Hypervisor) por XAPI, con la librería estándar.

XAPI habla JSON-RPC 2.0 sobre HTTPS en ``/jsonrpc``. El `RestClient` de
`agent.hypervisor` no sirve aquí a pesar de las ganas: urlencodea el cuerpo,
que es lo que quieren vCenter y Proxmox, y JSON-RPC exige el cuerpo en JSON.
Por eso este módulo lleva su propio `_call`, con la misma filosofía que el
resto del agente: timeout corto, **la verificación de TLS no se desactiva**
(ante el certificado autofirmado de un XCP-ng recién instalado, la salida es
dar la CA que lo firma, como con el vCenter) y un manejador que no sigue
redirecciones, para que la referencia de sesión no viaje a un destino que
nadie pidió.

El SDK oficial (`XenAPI.py`) está descartado a propósito, por lo mismo que
`pyvmomi`: son media docena de llamadas y el agente ya sabe hacerlas con
`urllib`, sin arrastrar una dependencia más cuya licencia habría que vigilar.

Una rareza de XAPI que explica varias decisiones de abajo: `get_all_records`
devuelve **todo el lote de una vez**, indexado por referencias opacas
(`OpaqueRef:...`), y los números llegan como cadenas. Eso permite que discos,
sistema operativo y host se resuelvan con una llamada por tabla y un cruce en
memoria, en vez de una petición por máquina como obliga el vCenter.
"""

from __future__ import annotations

import json
import ssl
import urllib.error
import urllib.request
from typing import Any

from agent.hypervisor import MAX_DETAILED_VMS, TIMEOUT_SECONDS, HypervisorError

XCPNG_PORT = 443

#: La referencia nula de XAPI: una VM apagada no reside en ningún host, y una
#: sin guest tools no tiene métricas. No es un error, es un campo vacío.
NULL_REF = "OpaqueRef:NULL"


class _NoRedirects(urllib.request.HTTPRedirectHandler):
    """Copia del de `agent.hypervisor`, por el mismo motivo: el manejador por
    defecto de `urllib` reenvía las cabeceras y el cuerpo al destino nuevo, y
    en el cuerpo de un `_call` va la referencia de sesión del XCP-ng."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D102, ANN001
        raise urllib.error.HTTPError(
            req.full_url, code, f"Redirección a {newurl}; no se sigue.", headers, fp
        )


class XcpNgClient:
    """Lo justo de XCP-ng: sus hosts y sus máquinas virtuales.

    Mismo contrato que `VMwareClient` y `ProxmoxClient`: `login()`, `hosts()`
    y `virtual_machines()`, para que el colector de hipervisores lo use sin
    cambiar su bucle.
    """

    def __init__(self, host: str, username: str, secret: str, *, port: int = 0, ca_file: str = "") -> None:
        self.url = f"https://{host}:{port or XCPNG_PORT}/jsonrpc"
        self.username = username
        self.secret = secret
        self.session = ""
        self._ca_file = ca_file
        self._request_id = 0
        #: Perezoso a propósito: `ssl.create_default_context` carga el almacén
        #: de certificados del sistema, y en Windows eso cuesta más de un
        #: segundo. Construir el cliente debe ser gratis; el coste se paga en
        #: la primera petición de verdad.
        self._opener: urllib.request.OpenerDirector | None = None

    def _call(self, method: str, params: list[Any]) -> Any:
        """Una llamada JSON-RPC 2.0 a la XAPI.

        Los errores nunca llevan los parámetros dentro: en el `login` viaja la
        contraseña, y el mensaje acaba en el informe de la ejecución, que se
        guarda.
        """
        if self._opener is None:
            self._opener = urllib.request.build_opener(
                _NoRedirects,
                urllib.request.HTTPSHandler(
                    context=ssl.create_default_context(cafile=self._ca_file or None)
                ),
            )
        self._request_id += 1
        payload = json.dumps(
            {"jsonrpc": "2.0", "method": method, "params": params, "id": self._request_id}
        ).encode()
        request = urllib.request.Request(
            self.url,
            data=payload,
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            method="POST",
        )
        try:
            with self._opener.open(request, timeout=TIMEOUT_SECONDS) as response:
                raw = response.read().decode(errors="replace")
        except urllib.error.HTTPError as exc:
            raise HypervisorError(f"{exc.code} en {method}") from exc
        except (urllib.error.URLError, TimeoutError, ssl.SSLError) as exc:
            raise HypervisorError(str(getattr(exc, "reason", exc))) from exc
        try:
            answer = json.loads(raw)
        except json.JSONDecodeError as exc:
            # Un portal cautivo, un proxy o el propio XCP-ng devolviendo su
            # página de error en HTML: se cuenta, no se intenta interpretar.
            raise HypervisorError("la respuesta no era JSON") from exc
        if not isinstance(answer, dict):
            raise HypervisorError("la respuesta no era JSON-RPC")
        if answer.get("error") is not None:
            raise HypervisorError(_error_text(answer["error"]))
        return answer.get("result")

    def login(self) -> None:
        """Abre la sesión y se queda con su referencia opaca."""
        answer = self._call("session.login_with_password", [self.username, self.secret])
        if not isinstance(answer, str) or not answer:
            raise HypervisorError("XCP-ng no devolvió sesión")
        self.session = answer

    def hosts(self) -> list[dict[str, Any]]:
        """Los servidores del pool de XCP-ng.

        XAPI no distingue «apagado» de «en mantenimiento»: un host con
        `enabled` a falso puede ser cualquiera de las dos cosas, así que se
        traduce a lo más honesto que admite el contrato: sin estado de
        alimentación y desconectado.
        """
        found: list[dict[str, Any]] = []
        for record in _records(self._call("host.get_all_records", [self.session])).values():
            name = str(record.get("hostname") or record.get("name_label") or "")
            if not name:
                continue
            enabled = bool(record.get("enabled"))
            found.append(
                {
                    "name": name,
                    "power_state": "POWERED_ON" if enabled else "",
                    "connection_state": "online" if enabled else "offline",
                }
            )
        return found

    def virtual_machines(self) -> list[dict[str, Any]]:
        """Las máquinas de verdad, con lo que hace falta para darlas de alta.

        `VM.get_all_records` devuelve **todo** lo que XAPI considera un `VM`:
        las plantillas de instalación y el dominio de control (dom0) de cada
        host también. Colarlos en la bandeja sería proponer dar de alta
        decenas de «máquinas» que nadie tiene, así que se filtran aquí.
        """
        machines = [
            (ref, vm)
            for ref, vm in _records(self._call("VM.get_all_records", [self.session])).items()
            if not (
                vm.get("is_a_template")
                or vm.get("is_default_template")
                or vm.get("is_control_domain")
            )
        ][:MAX_DETAILED_VMS]
        host_names = self._host_names()
        disk_gb = self._disk_gb_by_vm()
        os_names = self._os_by_guest_metrics()
        found: list[dict[str, Any]] = []
        for ref, vm in machines:
            memory = _number(vm.get("memory_static_max"))
            found.append(
                {
                    "id": str(vm.get("uuid") or "") or ref,
                    "name": str(vm.get("name_label") or vm.get("uuid") or ref),
                    "status": _status(str(vm.get("power_state") or "")),
                    "vcpus": int(_number(vm.get("VCPUs_max"))),
                    "ram_gb": round(memory / (1024**3)) if memory else 0,
                    "disk_gb": disk_gb.get(ref, 0),
                    # Una VM apagada no reside en ningún host: `resident_on`
                    # vale `OpaqueRef:NULL` y no está en el cruce, así que "".
                    "host": host_names.get(str(vm.get("resident_on") or ""), ""),
                    "operating_system": os_names.get(str(vm.get("guest_metrics") or ""), ""),
                }
            )
        return found

    def _host_names(self) -> dict[str, str]:
        """`{referencia del host: nombre}`, para colgar cada máquina del suyo.

        Si la llamada falla, las máquinas salen sin host y las demás columnas
        ni se enteran: un hallazgo incompleto vale más que ninguno.
        """
        try:
            records = _records(self._call("host.get_all_records", [self.session]))
        except HypervisorError:
            return {}
        return {
            ref: str(record.get("hostname") or record.get("name_label") or "")
            for ref, record in records.items()
        }

    def _disk_gb_by_vm(self) -> dict[str, int]:
        """`{referencia de la VM: GB de disco}`, cruzando VBD y VDI en memoria.

        Son **dos llamadas para el lote entero**, no una por máquina: XAPI da
        las tablas completas y el cruce sale gratis. Si cualquiera de las dos
        falla, todas las máquinas salen con 0 y no se lanza: un hallazgo
        incompleto vale más que ninguno, y el disco es el dato que menos
        decide al revisar la bandeja.
        """
        try:
            vbds = _records(self._call("VBD.get_all_records", [self.session]))
            vdis = _records(self._call("VDI.get_all_records", [self.session]))
        except HypervisorError:
            return {}
        bytes_by_vm: dict[str, float] = {}
        for vbd in vbds.values():
            # Los lectores de CD también son VBDs; solo cuentan los discos.
            if vbd.get("type") != "Disk":
                continue
            vm_ref = str(vbd.get("VM") or "")
            vdi = vdis.get(str(vbd.get("VDI") or ""))
            if not vm_ref or not isinstance(vdi, dict):
                continue
            bytes_by_vm[vm_ref] = bytes_by_vm.get(vm_ref, 0.0) + _number(vdi.get("virtual_size"))
        return {ref: round(total / (1024**3)) for ref, total in bytes_by_vm.items() if total}

    def _os_by_guest_metrics(self) -> dict[str, str]:
        """`{referencia de guest metrics: sistema operativo}`, una llamada.

        Solo las máquinas con las guest tools puestas tienen registro; las
        demás apuntan a `OpaqueRef:NULL` y salen con "". Si la llamada falla,
        todas salen sin sistema operativo, por lo mismo que los discos.
        """
        try:
            records = _records(self._call("VM_guest_metrics.get_all_records", [self.session]))
        except HypervisorError:
            return {}
        names: dict[str, str] = {}
        for ref, record in records.items():
            os_version = record.get("os_version")
            if isinstance(os_version, dict) and os_version.get("name"):
                names[ref] = str(os_version["name"])
        return names


def _error_text(error: Any) -> str:
    """El código XAPI, esté donde esté.

    En un error JSON-RPC de XAPI, `message` es un genérico que no dice nada
    («There was an error processing your request») y el código de verdad
    (`SESSION_AUTHENTICATION_FAILED`, `HOST_OFFLINE`...) viaja en `data` como
    lista. Se saca de donde esté para que el informe de la ejecución diga qué
    pasó, no solo que algo pasó.
    """
    if isinstance(error, dict):
        data = error.get("data")
        if isinstance(data, list):
            parts = [str(part) for part in data if isinstance(part, (str, int, float)) and str(part)]
            if parts:
                return " ".join(parts)
        if isinstance(data, str) and data:
            return data
        if error.get("message"):
            return str(error["message"])
    return "error de XAPI"


def _records(answer: Any) -> dict[str, dict[str, Any]]:
    """Los registros de un `get_all_records`, venga lo que venga.

    La respuesta la escribe otro proceso; una forma inesperada no puede acabar
    en un `AttributeError` a mitad del barrido.
    """
    if not isinstance(answer, dict):
        return {}
    return {str(ref): record for ref, record in answer.items() if isinstance(record, dict)}


def _status(power_state: str) -> str:
    """El estado, en el vocabulario del resto de hipervisores.

    `Paused` y `Suspended` acaban los dos en «suspended»: para la bandeja da
    igual si la pausa vive en RAM o en disco, la máquina no está sirviendo.
    """
    return {
        "running": "running",
        "halted": "stopped",
        "paused": "suspended",
        "suspended": "suspended",
    }.get(power_state.lower(), "running")


def _number(value: Any) -> float:
    """Copia de la de `agent.hypervisor`: XAPI da los números como cadenas."""
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0
