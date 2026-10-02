"""The agent's entry point, and the protocol-1 loop it falls back to.

Since 0.11 the agent speaks protocol 2 (``docs/agente-v2-nucleo.md``): a
control channel and tasks with their own cadence, run by `agent.runtime`.
Against a server that only knows protocol 1 -- its ``v2/checkin`` answers 404
-- it runs the loop of the 0.10.x agents, kept here unchanged (heartbeat,
sweep, push, sleep), and tries protocol 2 again every hour (spec 1.8).

``--once`` runs a single pass and exits, which is how the end-to-end path gets
exercised in tests and demos: a presence and an inventory with protocol 2, the
full sweep with protocol 1.
"""

from __future__ import annotations

import os
import socket
import sys
import time
from datetime import datetime, timezone
from typing import Protocol

from agent import __version__, enroll, localops, localpipe, logs, notes, probe, status, store
from agent import settings as local_settings
from agent.notes import collector_note
from agent.client import AgentClient, PushError
from agent.collectors import all_collectors
from agent.config import Config, from_env, setting
from agent.i18n import _t, _tn
from agent.memory import Excluded, Memory
from agent.runtime import FALLBACK, V1, V2, Runtime

# Lo que imprime el bucle se lee en una consola, en `docker logs` y, con el
# servicio de Windows, en el Visor de eventos (winservice redirige la salida
# allí): texto para una persona, así que va por el catálogo del agente.


def _sweep_line(created: int, refreshed: int, batches: int) -> str:
    """«Barrido enviado: 3 hallazgos nuevos, 10 ya conocidos.», en su idioma."""
    parts = {
        "created": _tn("%(n)d hallazgo nuevo", "%(n)d hallazgos nuevos", created) % {"n": created},
        "refreshed": _tn("%(n)d ya conocido.", "%(n)d ya conocidos.", refreshed) % {"n": refreshed},
    }
    if batches > 1:
        parts["batches"] = _tn("%(n)d envío", "%(n)d envíos", batches) % {"n": batches}
        return _t("[agente] Barrido enviado en %(batches)s: %(created)s, %(refreshed)s") % parts
    return _t("[agente] Barrido enviado: %(created)s, %(refreshed)s") % parts


def _say(text: str, *, error: bool = False) -> None:
    """Una línea para una persona: a la consola (o al Visor de eventos) y al registro.

    Tapada antes de salir por cualquiera de los dos: el Visor de eventos lo
    lee cualquier administrador, y un error de `urllib` puede traer dentro la
    URL de un proxy con su contraseña.
    """
    text = logs.scrub(str(text))
    if error:
        print(text, file=sys.stderr, flush=True)
        logs.error(text)
    else:
        print(text, flush=True)
        logs.info(text)


def unexpected_error(exc: BaseException) -> str:
    """Con el tipo de la excepción delante: un `KeyError` solo dice `'x'`."""
    return _t("Error inesperado: %(error)s") % {"error": f"{type(exc).__name__}: {exc}"}


class StopSignal(Protocol):
    """Lo que el bucle necesita para saber que tiene que parar.

    `threading.Event` lo cumple tal cual, y es lo que le pasa el servicio de
    Windows (`agent/winservice.py`). Un protocolo y no el tipo concreto para
    que este módulo no dependa de quién lo para: en la consola nadie pasa
    nada y el bucle se comporta exactamente como antes.
    """

    def is_set(self) -> bool: ...

    def wait(self, timeout: float | None = None) -> bool: ...


def _stopping(stop_event: StopSignal | None) -> bool:
    return stop_event is not None and stop_event.is_set()


def sweep(
    client: AgentClient,
    env: Config,
    *,
    report: bool = True,
    excluded: Excluded | None = None,
    memory: Memory | None = None,
    probes: bool = True,
) -> int:
    """One pass over every collector. Returns how many findings were pushed.

    A collector that blows up must not kill the sweep: it is reported as a
    partial run and the rest of the findings still go up.

    `report` escribe el fichero de estado que lee el icono de bandeja. `--once`
    lo apaga: es alguien probando a mano, y pisaría el estado del servicio que
    quizá corre a la vez en la misma máquina.

    `excluded` y `memory` son los mismos que usa el protocolo 2 (spec 2.3 y
    2.4): ningún camino toca una dirección excluida, tampoco este, y la
    memoria es la que evita repetir credenciales fallidas contra un dominio.
    `task` sigue sin ponerse: los colectores se comportan como en la 0.10.x.

    `probes` apagado (`--once`) deja los «Analizar» del latido para el
    servicio: son encargos suyos, y el servidor los da por hechos al recibir
    el informe.
    """
    if report:
        status.sweep_started()
    answer = client.heartbeat(version=__version__, hostname=socket.gethostname())
    started = datetime.now(timezone.utc)
    # The shared context: the server-sent config, the environment overrides,
    # and what one collector leaves for the next (the sweep's live hosts).
    ctx: dict = {"config": answer.get("config") or {}, "env": env, "excluded": excluded, "memory": memory}
    items = []
    collectors = all_collectors()
    for collector in collectors:
        if report:
            status.sweep_step(collector.name)
        try:
            items.extend(f.as_json() for f in collector.collect(ctx))
        except Exception as exc:  # noqa: BLE001 - one broken collector, not a dead agent
            ctx.setdefault("errors", []).append(
                collector_note(collector.name, "crashed", str(exc), detail=f"{type(exc).__name__}: {exc}")
            )
    # Los encargos de «Analizar» que trajo el latido: el sondeo dirigido de
    # cada IP, con su informe por protocolo. Van en el mismo empuje que el
    # barrido; el servidor los fusiona por IP con su fila de la bandeja.
    try:
        if probes:
            items.extend(probe.findings_for(ctx))
    except Exception as exc:  # noqa: BLE001 - un sondeo roto no tumba el barrido
        ctx.setdefault("errors", []).append(
            collector_note("probe", "crashed", str(exc), detail=f"{type(exc).__name__}: {exc}")
        )
    if memory is not None:
        try:
            memory.save()
        except Exception:  # noqa: BLE001 - la memoria es prescindible
            pass
    errors = ctx.get("errors") or []
    result = client.push_findings(
        run={
            "started_at": started.isoformat(),
            "finished_at": datetime.now(timezone.utc).isoformat(),
            "status": "partial" if errors else "ok",
            "stats": {"collectors": len(collectors)},
            # El texto en castellano, para un servidor que aún no conoce las
            # notas; y las notas, para que el servidor las escriba en el idioma
            # de quien las lee en la web (agent/notes.py).
            "error": "; ".join(errors),
            "notes": [notes.to_json(entry) for entry in errors],
            "agent_version": __version__,
        },
        items=items,
    )
    _say(
        _sweep_line(
            int(result.get("created", 0) or 0),
            int(result.get("refreshed", 0) or 0),
            int(result.get("batches") or 1),
        )
    )
    interval = _interval(answer.get("interval_seconds"))
    if report:
        status.sweep_finished(
            created=int(result.get("created", 0) or 0),
            refreshed=int(result.get("refreshed", 0) or 0),
            errors=list(ctx.get("errors") or []),
            next_in=interval or env.interval_seconds,
        )
    return interval


#: Suelo y techo del intervalo. Un cero martillea el servidor sin pausa y un
#: negativo lanza `ValueError` desde `time.sleep`; los dos matarían al agente por
#: un dato del servidor o del entorno, que es de quien menos debe fiarse.
MIN_INTERVAL_SECONDS = 30
MAX_INTERVAL_SECONDS = 24 * 60 * 60


def _interval(value: object, fallback: int = 0) -> int:
    """Los segundos que decir al bucle, acotados. Cero significa «deja el tuyo»."""
    try:
        seconds = int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return fallback
    if seconds <= 0:
        return fallback
    return max(MIN_INTERVAL_SECONDS, min(seconds, MAX_INTERVAL_SECONDS))


def main(argv: list[str] | None = None, stop_event: StopSignal | None = None) -> None:
    """Arranca el agente.

    `stop_event` lo usa quien necesita pararlo desde fuera --el servicio de
    Windows cuando alguien pulsa «Detener»-- sin matar el proceso. Un barrido
    en curso no se interrumpe (cortar a media consulta SNMP no ahorra nada y
    deja al colector en un estado raro): termina, y el bucle ya no empieza el
    siguiente. La siesta, en cambio, se corta en el acto.
    """
    args = argv if argv is not None else sys.argv[1:]
    from agent import localclient

    if args[:1] and args[0] in localclient.COMMANDS:
        # Clientes del canal local: hablan con el servicio que ya corre en
        # esta máquina, no arrancan otro agente.
        raise SystemExit(localclient.run(args))
    if args[:1] == ["enroll"]:
        raise SystemExit(enroll.run(args[1:]))
    if args[:1] == ["goodbye"]:
        # Se despide del servidor (spec 1.7) y borra el enrolamiento; aunque
        # el servidor no conteste. Lo llamará el desinstalador.
        from agent import goodbye

        raise SystemExit(goodbye.run(args[1:]))
    if args[:1] == ["settings"]:
        # Un ajuste local desde una consola o el instalador (/CA=): spec 2.6.
        from agent import settings_command

        raise SystemExit(settings_command.run(args[1:]))
    if args[:1] == ["update"]:
        # Linux, como root, desde la unidad cenya-agent-update.service: verifica
        # otra vez lo que pidió el agente y ejecuta install.sh --update. Antes de
        # proteger la carpeta de estado: root no debe hacerse su dueño.
        from agent import update

        raise SystemExit(update.run(args[1:]))
    if args[:1] == ["selftest"]:
        from agent import selftest

        raise SystemExit(selftest.run())
    if args[:1] == ["export-netbox"]:
        # No necesita estar enrolado: lee un NetBox y deja un fichero, sin
        # hablar con el servidor de Cenya.
        from agent import netbox_export

        raise SystemExit(netbox_export.run(args[1:]))
    # La carpeta de estado, protegida antes de leer nada de ella: lo que un
    # usuario cualquiera pudo dejar en una sin proteger (unos ajustes con su
    # proxy, una cola inventada) se aparta, y en una que no se puede proteger
    # el agente no arranca.
    try:
        securing = store.secure_state_dir()
    except store.StoreError as exc:
        _say(str(exc), error=True)
        raise SystemExit(str(exc)) from exc
    once = "--once" in args
    logs.setup()
    if securing.moved:
        _say(store.moved_line(securing), error=True)
    local = local_settings.load()
    language_locked = bool(os.environ.get("CENYA_LANGUAGE"))
    # El idioma de `settings.json`, si nadie lo fijó en el entorno: lo leen
    # `agent.i18n` (lo que se imprime) y `accept_language` (los errores del
    # servidor). Las variables mandan, como en el resto de ajustes.
    if local.language and not os.environ.get("CENYA_LANGUAGE"):
        os.environ["CENYA_LANGUAGE"] = local.language

    if once:
        # Un contenedor o un script que arranca el agente directamente puede
        # traer la cadena de conexión en el entorno: se canjea aquí, la primera vez.
        enroll.ensure_enrolled()
        config = from_env()
        client = _client_for(config, local)
        # Un servidor caído aquí es un mensaje, no un volcado de pila: `--once`
        # es lo que alguien ejecuta a mano para comprobar que el enrolado
        # funciona, y es justo cuando la URL o el token suelen estar mal.
        # Sin encargos, sin la cola del servicio y con una copia de su memoria
        # que no se guarda: `--once` puede correr con el servicio en marcha.
        runtime = Runtime(client, config, report=False, say=_say, once=True)
        try:
            if runtime.negotiate() == V2:
                runtime.once()
            else:
                sweep(client, config, report=False, excluded=runtime.excluded, memory=runtime.memory, probes=False)
        except PushError as exc:
            _say(_t("[agente] %(error)s") % {"error": exc}, error=True)
            raise SystemExit(1) from exc
        return

    # El canal local (spec 4): la aplicación de escritorio y los comandos
    # `status`, `pause`... hablan con este proceso por él. Vive lo que vive el
    # proceso, también sin enrolar: un equipo recién instalado se conecta
    # desde la aplicación (`connect`), y para eso el servicio tiene que estar
    # ahí escuchando, no salir al arrancar. Cada identidad es una sesión.
    channel = localops.LocalService(language_locked=language_locked)
    server = localpipe.serve(channel.dispatcher())
    try:
        config = _identity(channel, first=True)
        while True:
            if config is None:
                # Sin identidad: el canal contesta (`status` dice por qué) y se
                # espera a un `connect`. Para Windows el servicio está en marcha
                # y sano: nada de salir con error y reiniciarse en bucle.
                if not channel.wait_for_connect(stop_event):
                    break
                config = _identity(channel)
                continue
            client = _client_for(config, local_settings.load())
            runtime = Runtime(client, config, say=_say)
            channel.attach(runtime, client, config)
            _session(client, config, runtime, channel, channel.stop_signal(stop_event), stop_event)
            if _stopping(stop_event):
                break
            change = channel.take_change()
            if change is None:
                break
            channel.detach()
            # Lo que esperaba en la cola era de la identidad de antes.
            channel.discard_outbox()
            config = None if change == localops.DISCONNECTED else _identity(channel)
    finally:
        if server is not None:
            server.close()
    _say(_t("[agente] Detenido."))
    status.stopped()


def _identity(channel: localops.LocalService, *, first: bool = False) -> Config | None:
    """La identidad con la que trabajar, o `None` (y el canal sabe por qué) si no hay una usable.

    La primera vez también canjea ``CENYA_CONNECTION`` si la hay (un
    contenedor que arranca el agente directamente). Lo que antes hacía salir
    al agente --sin enrolar, un enrolamiento apartado por inseguro, una
    dirección http:// sin permiso-- ahora se dice y se espera.
    """
    try:
        if first:
            enroll.ensure_enrolled()
        return from_env()
    except SystemExit as exc:
        message = str(exc.code) if exc.code not in (None, 0) else ""
        if store.untrusted_enrollment():
            reason = localops.UNTRUSTED_STATE
        elif store.load() is None and not setting(os.environ, "AGENT_TOKEN"):
            reason = localops.NOT_ENROLLED_STATE
        else:
            reason = localops.INVALID_STATE
        channel.set_unenrolled(reason, message)
        _say(message or _t("[agente] Sin enrolar: esperando una conexión."), error=True)
        _say(_t("[agente] Esperando a que se conecte este equipo (cenya-agent connect <cadena>, o la aplicación Cenya Agent)."))
        status.stopped(reason=message)
        return None


def _client_for(config: Config, local: local_settings.Settings) -> AgentClient:
    return AgentClient(config.url, config.token, ca_bundle=config.ca_bundle or local.ca_bundle, proxy=local.proxy)


def _session(
    client: AgentClient,
    config: Config,
    runtime: Runtime,
    channel: localops.LocalService,
    stop: StopSignal,
    stop_event: StopSignal | None,
) -> None:
    """Una identidad: el protocolo 2, o el 1 si el servidor no sabe del 2, hasta que paren.

    `stop` es la parada del servicio o un cambio de identidad desde el canal
    local; `stop_event`, solo la del servicio (si ya estaba puesta, ni se
    pregunta al servidor).
    """
    mode = V1 if _stopping(stop_event) else runtime.negotiate()
    while True:
        channel.set_mode(mode)
        if mode == V1:
            if not _legacy_loop(client, config, runtime, stop):
                break
            mode = V2
            continue
        # Protocolo 2, o no se sabe todavía (la red caída al arrancar): se
        # arranca el 2, y si el servidor resulta ser del 1 su 404 lo dirá.
        _say(_t("[agente] Conectado a %(url)s con el protocolo 2.") % {"url": config.url})
        status.started(version=__version__, url=config.url, interval_seconds=0)
        if runtime.run(stop) != FALLBACK:
            break
        _say(_t("[agente] El servidor solo habla el protocolo 1: se sigue con el bucle de siempre."))
        mode = V1


#: Cada cuánto se vuelve a probar el protocolo 2 desde el bucle del 1 (spec 1.8).
V2_RETRY_SECONDS = 60 * 60


def _legacy_loop(client: AgentClient, config: Config, runtime: Runtime, stop_event: StopSignal | None) -> bool:
    """El bucle del protocolo 1, el de la 0.10.x. `True` si hay que pasar al 2.

    Sale con `False` cuando lo paran. Cada hora, entre barrido y barrido,
    pregunta otra vez por `v2/checkin`: el servidor puede haberse actualizado.
    """
    interval = _interval(config.interval_seconds, fallback=MIN_INTERVAL_SECONDS)
    _say(_t("[agente] Empujando a %(url)s cada ~%(seconds)d s.") % {"url": config.url, "seconds": interval})
    status.started(version=__version__, url=config.url, interval_seconds=interval)
    last_try = time.monotonic()
    while not _stopping(stop_event):
        try:
            interval = sweep(client, config, excluded=runtime.excluded, memory=runtime.memory) or interval
        except PushError as exc:
            # A network cut or a revoked token is not a reason to die: sleep
            # and try again. The server keeps the state; the agent just knocks.
            _say(_t("[agente] %(error)s") % {"error": exc}, error=True)
            status.failed(str(exc))
        except Exception as exc:  # noqa: BLE001
            # Ni un dato inesperado del servidor. El agente vive en la máquina
            # de un cliente sin nadie mirándola: morir en silencio es la peor
            # de las opciones, porque el inventario deja de actualizarse y no
            # hay ninguna señal de que haya pasado nada.
            _say(_t("[agente] %(error)s") % {"error": unexpected_error(exc)}, error=True)
            status.failed(unexpected_error(exc))
        interval = _nap(client, interval, stop_event)
        if not _stopping(stop_event) and time.monotonic() - last_try >= V2_RETRY_SECONDS:
            last_try = time.monotonic()
            if runtime.negotiate() == V2:
                return True
    return False


#: Cada cuánto pregunta el agente mientras duerme entre barridos. Es lo que
#: hace posibles «Barrer ahora» y «Analizar» sin abrir un solo puerto ni
#: mantener una conexión permanente: el servidor apunta el encargo, y el
#: agente pasa a recogerlo como muy tarde un minuto después. Un latido son
#: unos cientos de bytes: mil agentes preguntando cada minuto siguen siendo
#: ruido para el servidor.
POLL_SECONDS = 60


def _nap(client: AgentClient, interval: int, stop_event: StopSignal | None = None) -> int:
    """La siesta entre barridos, a sorbos, preguntando en cada sorbo.

    Devuelve el intervalo (quizá actualizado por el servidor a mitad de
    siesta). Sale antes de tiempo si el servidor dice `sweep_now`: alguien
    pulsó «Barrer ahora» o encargó un análisis y no quiere esperar al ciclo.
    Un latido fallido no despierta ni mata nada: se sigue durmiendo y el
    barrido normal llegará igual.

    Con `stop_event`, cada sorbo es una espera sobre él en vez de un
    `time.sleep`: quien para el servicio no espera al final del minuto. Se
    mira también antes de empezar, por si la orden llegó durante el barrido.
    """
    slept = 0
    while slept < interval:
        if _stopping(stop_event):
            break
        chunk = min(POLL_SECONDS, interval - slept)
        if stop_event is None:
            time.sleep(chunk)
        elif stop_event.wait(chunk):
            break
        slept += chunk
        if slept >= interval:
            break
        try:
            answer = client.heartbeat(version=__version__, hostname=socket.gethostname())
        except Exception as exc:  # noqa: BLE001 - la red va y viene; el sueño sigue
            # Pero el icono sí lo cuenta: un servidor que no contesta durante
            # la siesta es lo que tardaría quince minutos en notarse si no.
            status.nap_tick(next_in=interval - slept, error=str(exc))
            continue
        interval = _interval(answer.get("interval_seconds"), fallback=interval)
        status.nap_tick(next_in=max(0, interval - slept))
        if answer.get("sweep_now") or (answer.get("config") or {}).get("probe_ips"):
            break
    return interval


if __name__ == "__main__":
    main()
