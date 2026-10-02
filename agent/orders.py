"""The orders of phase 3 (spec 3.3): test a credential, reseal for another agent, export a NetBox.

The control channel (`agent/control.py`) receives them and runs each in its
own worker; this module is what that worker does. Each function answers with
``(status, result, notes)`` -- the body of ``v2/orders/<id>/result/`` -- and
**never raises and never cites a secret**: not in the result, not in a note,
not in an exception text. Every secret opened here lives inside the function
that opened it and nowhere else.
"""

from __future__ import annotations

import ipaddress
import urllib.parse
from collections.abc import Callable, Mapping
from typing import Any

from agent import credentials as creds
from agent import net, probe, sealing
from agent.collectors import tasking
from agent.notes import Note, collector_note, probe_note

DONE = "done"
FAILED = "failed"

#: Cuántas credenciales caben en un `reseal`. Un perfil de pyme tiene una
#: docena; mil es un servidor roto, no un cliente grande.
MAX_RESEAL = 1000

Outcome = tuple[str, dict[str, Any], list[Note]]


def scrub(text: str, secrets: list[str]) -> str:
    """El texto sin ninguno de esos secretos dentro. La última red, no la primera."""
    return creds.scrub(text, None, *secrets)


def _line(note: Note) -> dict[str, Any]:
    """La línea de un informe de sondeo (spec 3.3): protocolo, código, parámetros y el texto de respaldo."""
    return {"protocol": note.collector, "code": note.code, "params": dict(note.params), "text": str(note)}


def _crashed(collector: str, exc: BaseException) -> Note:
    # Solo el tipo: el texto de una excepción que pasó cerca de un secreto
    # puede llevarlo dentro (una URL, un error de librería que repite lo que le dieron).
    name = type(exc).__name__
    return collector_note(collector, "crashed", f"error inesperado ({name})", error=name)


# --- test_credential -------------------------------------------------------------------

HYPERVISOR_KINDS = (creds.VMWARE, creds.PROXMOX, creds.HYPERV, creds.XCPNG)


def test_credential(params: Mapping[str, Any], ctx: dict) -> Outcome:
    """Prueba **esa** credencial contra esa IP; un hipervisor, contra su propio servidor.

    Lo pide una persona: no consulta ni altera el límite de rondas de la
    memoria, pero un acierto sí se apunta (`agent.probe.test_line`). Una
    dirección excluida en esta máquina, o fuera del alcance de la credencial,
    no se toca.
    """
    try:
        return _test_credential(params, ctx)
    except Exception as exc:  # noqa: BLE001
        return FAILED, {}, [_crashed("test_credential", exc)]


def _refused(code: str, text: str, **params: Any) -> Outcome:
    note = collector_note("test_credential", code, text, **params)
    return FAILED, {"ok": False, "line": _line(note)}, [note]


def _test_credential(params: Mapping[str, Any], ctx: dict) -> Outcome:
    ident = params.get("credential_id")
    ident = ident.strip() if isinstance(ident, str) else ""
    credential, present = creds.find(ctx, ident)
    if credential is None:
        if present:
            return _refused("sealed_unreadable", "la credencial sellada no se puede abrir en este agente", count=1)
        return _refused("unknown_credential", "esa credencial no está en la configuración de este agente")

    if credential.kind in HYPERVISOR_KINDS:
        return _test_hypervisor(credential, ctx)
    if credential.kind not in probe.TESTABLE:
        return _refused("unsupported", "esta clase de credencial no se puede probar", kind=credential.kind[:40])

    raw_ip = params.get("ip")
    try:
        ip = str(ipaddress.ip_address(str(raw_ip or "").strip()))
    except ValueError:
        note = collector_note("probe", "bad_address", "la dirección no es válida")
        return FAILED, {"ok": False, "line": _line(note)}, [note]
    if tasking.excluded(ctx, ip):
        # El mismo código que «Analizar»: quien excluyó la dirección está aquí, y manda.
        note = collector_note("probe", "excluded", "la dirección está excluida en este agente")
        return FAILED, {"ok": False, "line": _line(note)}, [note]
    if not credential.covers(ip):
        return _refused("out_of_scope", "la dirección está fuera del alcance de la credencial")
    ok, note = probe.test_line(ip, ctx, credential)
    return DONE, {"ok": ok, "line": _line(note)}, []


def _test_hypervisor(credential: creds.Credential, ctx: dict) -> Outcome:
    from agent.collectors.hypervisors import CLIENTS
    from agent import hypervisor

    if not credential.host:
        return _refused("credential_without_host", "la credencial no dice contra qué servidor va")
    address = net.resolve(credential.host)
    if tasking.excluded(ctx, credential.host) or (address and tasking.excluded(ctx, address)):
        note = collector_note("probe", "excluded", "la dirección está excluida en este agente")
        return FAILED, {"ok": False, "line": _line(note)}, [note]
    if not credential.covers(address or credential.host):
        return _refused("out_of_scope", "el servidor está fuera del alcance de la credencial")
    secrets = [credential.secret, credential.priv_secret]
    try:
        client = CLIENTS[credential.kind](
            credential.host,
            credential.username,
            credential.secret,
            port=credential.port,
            ca_file=creds.ca_file_for(ctx, credential),
        )
        client.login()
    except hypervisor.HypervisorError as exc:
        detail = scrub(str(exc), secrets)[:120]
        note = probe_note("hypervisor", "failed", f"{credential.host}: {detail}", host=credential.host, detail=detail)
        return DONE, {"ok": False, "line": _line(note)}, []
    except Exception as exc:  # noqa: BLE001
        name = type(exc).__name__
        note = probe_note("hypervisor", "check_failed", f"no se pudo comprobar ({name})", error=name)
        return DONE, {"ok": False, "line": _line(note)}, []
    mem = tasking.memory(ctx)
    if mem is not None:
        key = address if address and credential.covers(address) else credential.host
        try:
            mem.record_success(key, credential.kind, credential, tasking.now())
        except Exception:  # noqa: BLE001 - la memoria es prescindible
            pass
    note = probe_note(
        "hypervisor", "logged_in", f"{credential.host}: entró con «{credential.username}»",
        host=credential.host, username=credential.username,
    )
    return DONE, {"ok": True, "line": _line(note)}, []


# --- reseal ----------------------------------------------------------------------------


def reseal(params: Mapping[str, Any], ctx: dict, *, agent_uuid: str, environ: Mapping[str, str] | None = None) -> Outcome:
    """Abre los sobres de esas credenciales y los cierra para la clave de otro agente.

    Para cambiar de máquina sin volver a teclear nada: el servidor no puede
    abrir los sobres, pero este agente sí, y los cierra para el nuevo con su
    uuid en la AAD. La clave pública que llega se valida antes de usarla (RSA
    de 3072 bits o más, bien formada): re-sellar para una clave débil
    rebajaría la protección de todo lo que se mueve a ella.
    """
    try:
        return _reseal(params, ctx, agent_uuid=agent_uuid, environ=environ)
    except Exception as exc:  # noqa: BLE001
        return FAILED, {}, [_crashed("reseal", exc)]


def _reseal(params: Mapping[str, Any], ctx: dict, *, agent_uuid: str, environ: Mapping[str, str] | None) -> Outcome:
    if not sealing.available():
        return FAILED, {}, [collector_note("reseal", "unavailable", "este agente no puede abrir credenciales selladas")]
    try:
        target = sealing.canonical_uuid(params.get("agent"))  # type: ignore[arg-type]
    except sealing.SealError:
        return FAILED, {}, [collector_note("reseal", "bad_agent", "el uuid del agente nuevo no es válido")]
    public_key = params.get("public_key")
    try:
        sealing.load_public_key(public_key)  # type: ignore[arg-type]
    except sealing.SealError as exc:
        return FAILED, {}, [
            collector_note(
                "reseal", "bad_public_key", "la clave pública del agente nuevo no es válida o es demasiado corta",
                reason=exc.reason,
            )
        ]
    raw_ids = params.get("credential_ids")
    if not isinstance(raw_ids, list) or len(raw_ids) > MAX_RESEAL:
        return FAILED, {}, [collector_note("reseal", "bad_params", "la lista de credenciales no es válida")]
    wanted: list[str] = []
    for item in raw_ids:
        if isinstance(item, str) and item.strip() and item.strip() not in wanted:
            wanted.append(item.strip())

    by_id: dict[str, dict] = {}
    for item in creds.raw_list(ctx):
        if isinstance(item, dict) and isinstance(item.get(creds.SEALED), dict):
            ident = str(item.get("id") or "").strip()
            if ident:
                by_id.setdefault(ident, item)

    envelopes: dict[str, dict] = {}
    missing: list[str] = []
    key = sealing.own_private_key(environ)
    try:
        for ident in wanted:
            item = by_id.get(ident)
            if item is None or key is None:
                missing.append(ident)
                continue
            try:
                plaintext = sealing.open_envelope(
                    item[creds.SEALED], agent_uuid=agent_uuid, subject_id=ident, private_key=key
                )
                envelopes[ident] = sealing.seal_for(public_key, plaintext, agent_uuid=target, subject_id=ident)  # type: ignore[arg-type]
            except sealing.SealError:
                missing.append(ident)
            finally:
                plaintext = None  # noqa: F841 - que no sobreviva a la vuelta del bucle
    finally:
        key = None
    return DONE, {"envelopes": envelopes, "missing": missing}, []


# --- netbox_export ---------------------------------------------------------------------


def _same_url(a: str, b: str) -> bool:
    return a.strip().rstrip("/") == b.strip().rstrip("/")


def netbox_export(
    order_id: str,
    params: Mapping[str, Any],
    ctx: dict,
    *,
    agent_uuid: str,
    upload: Callable[[dict, str], dict],
    progress: Callable[[str, int, int], None] | None = None,
    environ: Mapping[str, str] | None = None,
) -> Outcome:
    """Lee ese NetBox con el token sellado y sube lo leído al servidor (spec 3.3, 3.4).

    El token llega cerrado para este agente y para **este encargo** (su `id`
    en la AAD), se abre aquí, se usa y se olvida. No aparece en ninguna nota,
    registro ni excepción: cualquier texto que salga de aquí pasa antes por
    `scrub`.
    """
    try:
        return _netbox_export(order_id, params, ctx, agent_uuid, upload, progress, environ)
    except Exception as exc:  # noqa: BLE001
        return FAILED, {}, [_crashed("netbox", exc)]


def _netbox_export(
    order_id: str,
    params: Mapping[str, Any],
    ctx: dict,
    agent_uuid: str,
    upload: Callable[[dict, str], dict],
    progress: Callable[[str, int, int], None] | None,
    environ: Mapping[str, str] | None,
) -> Outcome:
    from agent import netbox_export as exporter
    from agent.client import PushError

    url = params.get("url")
    if not isinstance(url, str) or not url.strip():
        return FAILED, {}, [collector_note("netbox", "bad_url", "falta la dirección de NetBox")]
    url = url.strip()
    verify_tls = params.get("verify_tls")
    verify_tls = verify_tls if isinstance(verify_tls, bool) else True
    envelope = params.get("sealed_token")
    try:
        plaintext = sealing.open_envelope(envelope, agent_uuid=agent_uuid, subject_id=order_id, environ=environ)  # type: ignore[arg-type]
    except sealing.SealError:
        return FAILED, {}, [
            collector_note("netbox", "sealed_unreadable", "el token sellado no se puede abrir en este agente", count=1)
        ]
    token = plaintext.get("secret")
    bound_url = plaintext.get("url")
    plaintext = None
    if not isinstance(token, str) or not token.strip():
        return FAILED, {}, [
            collector_note("netbox", "sealed_unreadable", "el token sellado no se puede abrir en este agente", count=1)
        ]
    token = token.strip()
    secrets = [token]
    if isinstance(bound_url, str) and not _same_url(bound_url, url):
        # El navegador puede cerrar la URL junto con el token: así un servidor
        # que cambiara la dirección del encargo no se llevaría el token a otro sitio.
        return FAILED, {}, [collector_note("netbox", "url_mismatch", "la dirección no es la que se selló con el token")]

    host = urllib.parse.urlsplit(url).hostname or ""
    if host and ctx.get("excluded") is not None and (
        tasking.excluded(ctx, host) or tasking.excluded(ctx, net.resolve(host) or "")
    ):
        return FAILED, {}, [collector_note("netbox", "excluded", "la dirección está excluida en este agente", host=host)]

    names = {path: name for name, path in exporter.ENDPOINTS.items()}
    total = len(exporter.ENDPOINTS)
    seen: list[str] = []

    def advance(path: str) -> None:
        name = names.get(path, "")
        if name and name not in seen:
            seen.append(name)
        if progress is not None:
            try:
                progress(name, len(seen) - 1, total)
            except Exception:  # noqa: BLE001 - avisar nunca rompe nada
                pass

    try:
        bundle = exporter.fetch_bundle(url, token, verify_tls=verify_tls, progress=advance)
    except exporter.ExportError as exc:
        detail = scrub(str(exc), secrets)[:300]
        return FAILED, {}, [collector_note("netbox", "export_failed", f"no se pudo leer NetBox: {detail}", detail=detail)]
    except Exception as exc:  # noqa: BLE001
        return FAILED, {}, [_crashed("netbox", exc)]
    finally:
        token = ""
        secrets = []
    summary = {name: len(rows) for name, rows in bundle.items() if isinstance(rows, list)}
    if progress is not None:
        try:
            progress("upload", total, total)
        except Exception:  # noqa: BLE001
            pass
    try:
        answer = upload(bundle, order_id)
    except PushError as exc:
        detail = str(exc)[:300]
        return FAILED, {"summary": summary}, [
            collector_note("netbox", "upload_failed", f"no se pudo subir lo leído: {detail}", status=exc.status, detail=detail)
        ]
    finally:
        bundle = None
    import_id = answer.get("import") if isinstance(answer, dict) else None
    return DONE, {"import": str(import_id or ""), "summary": summary}, []
