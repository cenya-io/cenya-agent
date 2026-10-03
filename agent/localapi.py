"""The local channel's protocol, independent of how the bytes travel (spec 4).

Between the service and whoever sits at the same machine -- the desktop
application, the console commands -- there is a named pipe on Windows and a
Unix socket elsewhere (`agent.localpipe`). What travels on it is decided here,
and only here:

* **One JSON object per line**, UTF-8. A request is
  ``{"id": 1, "op": "status", "args": {}}``; the answer repeats the ``id`` and
  is ``{"id": 1, "ok": true, "data": {...}}`` or
  ``{"id": 1, "ok": false, "error": "<code>", "message": "<sentence>"}``.
* **Bounded.** A request line longer than `MAX_REQUEST_BYTES` is refused
  (``too_large``) and skipped up to its end; an answer longer than
  `MAX_RESPONSE_BYTES` becomes a ``too_large`` error. Nothing a client sends
  can make the service hold more than that in memory.
* **Never a crash.** Bad JSON, a list instead of an object, an unknown ``op``,
  a handler that blows up: each is an error *answer*, and the connection goes
  on.
* **Read or act.** Every operation is one or the other (`OPERATIONS`). Anyone
  on the machine may read; only an administrator may act. The decision is
  `may`, a pure function of the operation and of who is calling (`Caller`),
  which the transport establishes and this module never second-guesses.

Lo que los manejadores hacen está en `agent.localops`; aquí solo se decide qué
es una petición, quién puede hacerla y cómo se contesta.
"""

from __future__ import annotations

import json
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, Protocol

from agent import logs
from agent.i18n import _t

#: Una petición cabe de sobra en esto (la más larga es `settings.set` con unas
#: cuantas exclusiones); más es un cliente roto o alguien probando.
MAX_REQUEST_BYTES = 64 * 1024
#: La respuesta más grande es un `log` de 2.000 líneas o un informe de sondeo.
MAX_RESPONSE_BYTES = 8 * 1024 * 1024

READ = "read"
ACT = "act"

#: Las operaciones de la especificación (4) y su tipo. Lo que no está aquí no existe.
OPERATIONS: dict[str, str] = {
    "status": READ,
    "log": READ,
    "about": READ,
    "settings.get": READ,
    "run": ACT,
    "pause": ACT,
    "resume": ACT,
    "settings.set": ACT,
    "probe": ACT,
    "test_connection": ACT,
    "connect": ACT,
    "disconnect": ACT,
    "netbox.export": ACT,
    "support_bundle": ACT,
    "check_update": ACT,
}

# Los códigos de error: estables, para que el cliente decida qué decir sin
# depender del idioma de la frase.
BAD_REQUEST = "bad_request"
TOO_LARGE = "too_large"
UNKNOWN_OP = "unknown_op"
FORBIDDEN = "forbidden"
BUSY = "busy"
INVALID = "invalid"
NOT_ENROLLED = "not_enrolled"
UNAVAILABLE = "unavailable"
EXCLUDED = "excluded"
FAILED = "failed"
INTERNAL = "internal"


@dataclass(frozen=True)
class Caller:
    """Who is at the other end, as the transport established it.

    `admin` is the only thing that grants anything: on Windows, an elevated
    member of BUILTIN\\Administrators (the impersonated token says so); on
    Linux, uid 0 or the service's own uid. `who` is for the log (a SID, a uid),
    never for a decision.
    """

    admin: bool = False
    who: str = ""


#: Quien no se ha podido identificar: puede leer, y nada más.
ANONYMOUS = Caller(admin=False, who="?")


def kind_of(op: str) -> str | None:
    return OPERATIONS.get(op)


def may(op: str, caller: Caller) -> bool:
    """Whether `caller` may run `op`. Pure: the whole permission policy.

    Leer, cualquiera de la máquina; actuar, solo un administrador. Una
    operación que no existe no la puede nadie (el que pregunta recibe
    ``unknown_op``, no ``forbidden``: eso lo decide el despachador).
    """
    kind = OPERATIONS.get(op)
    if kind == READ:
        return True
    if kind == ACT:
        return bool(caller.admin)
    return False


def posix_may_act(peer_uid: int | None, service_uid: int) -> bool:
    """Linux (`SO_PEERCRED`): root or the account the service runs as. Pure."""
    return peer_uid is not None and peer_uid >= 0 and peer_uid in (0, service_uid)


# --- Errores y respuestas ------------------------------------------------------


class OpError(Exception):
    """A handler's coded refusal or failure. `message` is for a person; never a secret."""

    def __init__(self, code: str, message: str, **details: Any) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = details


def ok(request_id: Any, data: Any) -> dict[str, Any]:
    return {"id": request_id, "ok": True, "data": data}


def error(request_id: Any, code: str, message: str, **details: Any) -> dict[str, Any]:
    answer: dict[str, Any] = {"id": request_id, "ok": False, "error": code, "message": message}
    if details:
        answer["details"] = details
    return answer


def encode(message: Mapping[str, Any]) -> bytes:
    """Una línea de JSON en UTF-8, con su salto. Una respuesta enorme es un error, no un búfer de 1 GB."""
    data = json.dumps(message, ensure_ascii=False, separators=(",", ":"), default=str).encode("utf-8") + b"\n"
    if len(data) > MAX_RESPONSE_BYTES:
        return encode(error(message.get("id"), TOO_LARGE, _t("La respuesta es demasiado grande para el canal local.")))
    return data


def _valid_id(value: Any) -> bool:
    return value is None or (isinstance(value, (int, str)) and not isinstance(value, bool))


@dataclass(frozen=True)
class Request:
    id: Any
    op: str
    args: dict[str, Any]


def parse_request(line: bytes) -> Request | dict[str, Any]:
    """A `Request`, or the error answer for a line that is not one. Never raises."""
    try:
        data = json.loads(line.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        return error(None, BAD_REQUEST, _t("La petición no es JSON válido."))
    if not isinstance(data, dict):
        return error(None, BAD_REQUEST, _t("La petición tiene que ser un objeto JSON."))
    request_id = data.get("id")
    if not _valid_id(request_id):
        return error(None, BAD_REQUEST, _t("El campo «id» tiene que ser un número o un texto."))
    op = data.get("op")
    if not isinstance(op, str) or not op:
        return error(request_id, BAD_REQUEST, _t("Falta el campo «op»."))
    args = data.get("args", {})
    if args is None:
        args = {}
    if not isinstance(args, dict):
        return error(request_id, BAD_REQUEST, _t("El campo «args» tiene que ser un objeto."))
    return Request(request_id, op, args)


# --- El despachador ---------------------------------------------------------------

#: Un manejador recibe los `args` y quién llama, y devuelve los datos de la
#: respuesta (algo que se pueda pasar a JSON). Lanza `OpError` para decir que no.
Handler = Callable[[dict[str, Any], Caller], Any]


class Dispatcher:
    """Maps operations to handlers and turns whatever happens into an answer.

    Una operación de la tabla sin manejador (este agente aún no la sabe hacer)
    se contesta ``unavailable``; una que no está en la tabla, ``unknown_op``.
    """

    def __init__(self, handlers: Mapping[str, Handler]) -> None:
        unknown = set(handlers) - set(OPERATIONS)
        if unknown:
            raise ValueError(f"operaciones que no están en la tabla: {sorted(unknown)}")
        self._handlers = dict(handlers)

    def handle(self, request: Request, caller: Caller) -> dict[str, Any]:
        if request.op not in OPERATIONS:
            return error(request.id, UNKNOWN_OP, _t("Operación desconocida: %(op)s") % {"op": request.op[:60]})
        if not may(request.op, caller):
            return error(request.id, FORBIDDEN, _t("Esta operación solo la puede hacer un administrador."))
        handler = self._handlers.get(request.op)
        if handler is None:
            return error(request.id, UNAVAILABLE, _t("Este agente no sabe hacer todavía esa operación."))
        try:
            return ok(request.id, handler(request.args, caller))
        except OpError as exc:
            return error(request.id, exc.code, exc.message, **exc.details)
        except Exception as exc:  # noqa: BLE001 - un manejador roto es una respuesta, no un canal caído
            # Solo el tipo: el texto de una excepción puede llevar dentro lo
            # que llegó en `args` (el token de NetBox), y esto va al registro.
            logs.error(_t("[canal local] Fallo inesperado en %(op)s: %(type)s") % {"op": request.op, "type": type(exc).__name__})
            return error(request.id, INTERNAL, _t("Error inesperado en el agente (%(type)s).") % {"type": type(exc).__name__})

    def handle_line(self, line: bytes, caller: Caller) -> dict[str, Any]:
        parsed = parse_request(line)
        if isinstance(parsed, dict):
            return parsed
        return self.handle(parsed, caller)


# --- Las líneas -----------------------------------------------------------------


class TooLong:
    """A line that went over the limit: what is left of it is being skipped."""


TOO_LONG = TooLong()


class LineBuffer:
    """Cuts a byte stream into lines, never holding more than `limit` bytes.

    Una línea que pasa del tope se entrega como `TOO_LONG` una sola vez y lo
    que queda de ella se tira hasta su salto: el cliente recibe un error y la
    conversación sigue en la línea siguiente.
    """

    def __init__(self, limit: int = MAX_REQUEST_BYTES) -> None:
        self.limit = limit
        self._pending = bytearray()
        self._skipping = False

    @property
    def partial(self) -> bool:
        """Si hay media línea esperando (para el plazo de una petición a medias)."""
        return bool(self._pending) or self._skipping

    def feed(self, data: bytes) -> list[bytes | TooLong]:
        out: list[bytes | TooLong] = []
        while data:
            cut = data.find(b"\n")
            chunk, data = (data, b"") if cut < 0 else (data[:cut], data[cut + 1 :])
            if self._skipping:
                if cut >= 0:
                    self._skipping = False
                continue
            if len(self._pending) + len(chunk) > self.limit:
                self._pending.clear()
                out.append(TOO_LONG)
                self._skipping = cut < 0
                continue
            self._pending += chunk
            if cut >= 0:
                line = bytes(self._pending).rstrip(b"\r")
                self._pending.clear()
                if line.strip():
                    out.append(line)
        return out


# --- Una conexión, sin saber de qué es ----------------------------------------------


class Connection(Protocol):
    """Lo que un transporte da por cada cliente.

    `recv` devuelve lo que haya (b"" es que el cliente cerró) y lanza
    `TimeoutError` si en `timeout` segundos no llega nada; `send` manda todo o
    lanza (también `TimeoutError` si el cliente no lee).
    """

    def recv(self, timeout: float) -> bytes: ...

    def send(self, data: bytes, timeout: float) -> None: ...

    def close(self) -> None: ...


#: Un cliente callado tanto tiempo entre peticiones se despide.
IDLE_SECONDS = 300.0
#: Una petición empezada tiene que acabar de llegar en esto (contra quien
#: manda un byte cada minuto para quedarse con el hueco).
LINE_SECONDS = 30.0
#: La primera petición: quien conecta y no dice nada ocupa un hueco sin nombre.
FIRST_LINE_SECONDS = 10.0
#: Un cliente que no lee su respuesta en esto se cierra.
SEND_SECONDS = 30.0


def serve_connection(
    conn: Connection,
    dispatcher: Dispatcher,
    identify: Callable[[], Caller],
    *,
    admission: Admission | None = None,
    stop: threading.Event | None = None,
    idle_seconds: float = IDLE_SECONDS,
    line_seconds: float = LINE_SECONDS,
    first_line_seconds: float = FIRST_LINE_SECONDS,
    send_seconds: float = SEND_SECONDS,
) -> None:
    """Talk to one client until it leaves, goes quiet or misbehaves. Never raises.

    `identify` se llama después de la primera lectura (en Windows no se puede
    suplantar al cliente de un pipe antes de que haya escrito algo) y su
    resultado vale para toda la conexión. Con `admission`, quien ya tiene
    demasiadas conexiones abiertas recibe ``busy`` y se cierra.

    Tres plazos, para que nadie se quede con un hueco sin usarlo: la primera
    petición tiene que llegar pronto, una petición empezada tiene que acabar
    de llegar, y entre peticiones se espera más pero no siempre.
    """
    buffer = LineBuffer()
    caller: Caller | None = None
    claimed = False
    last_activity = time.monotonic()
    line_started = last_activity
    try:
        while stop is None or not stop.is_set():
            now = time.monotonic()
            if buffer.partial:
                deadline = line_started + line_seconds
            elif caller is None:
                deadline = last_activity + first_line_seconds
            else:
                deadline = last_activity + idle_seconds
            if now >= deadline:
                return
            # A sorbos de un segundo como mucho: así se ve `stop` enseguida.
            try:
                data = conn.recv(min(deadline - now, 1.0))
            except TimeoutError:
                continue
            if not data:
                return
            was_partial = buffer.partial
            lines = buffer.feed(data)
            if caller is None:
                try:
                    caller = identify()
                except Exception:  # noqa: BLE001 - quien no se identifica solo lee
                    caller = ANONYMOUS
                if admission is not None:
                    claimed = admission.claim(caller)
                    if not claimed:
                        busy = error(None, BUSY, _t("Hay demasiadas conexiones abiertas con el agente."))
                        conn.send(encode(busy), send_seconds)
                        return
            for line in lines:
                if isinstance(line, TooLong):
                    answer = error(None, TOO_LARGE, _t("La petición es demasiado grande."))
                else:
                    answer = dispatcher.handle_line(line, caller)
                conn.send(encode(answer), send_seconds)
            now = time.monotonic()
            if lines:
                last_activity = now
            if buffer.partial and (lines or not was_partial):
                line_started = now
    except Exception:  # noqa: BLE001 - un cliente que se va a medias, o que no lee
        return
    finally:
        if claimed and caller is not None and admission is not None:
            admission.release(caller)
        try:
            conn.close()
        except Exception:  # noqa: BLE001
            pass


class Admission:
    """How many connections at once, in total and per caller. Thread-safe.

    Un usuario cualquiera puede leer, pero no puede llenar todos los huecos y
    dejar fuera al administrador o a la aplicación: cada identidad tiene su
    propio tope, por debajo del total.
    """

    def __init__(self, total: int = 16, per_caller: int = 4) -> None:
        self.total = total
        self.per_caller = per_caller
        self._lock = threading.Lock()
        self._open = 0
        self._by_caller: dict[str, int] = {}

    def enter(self) -> bool:
        with self._lock:
            if self._open >= self.total:
                return False
            self._open += 1
            return True

    def leave(self) -> None:
        with self._lock:
            self._open = max(0, self._open - 1)

    def claim(self, caller: Caller) -> bool:
        with self._lock:
            count = self._by_caller.get(caller.who, 0)
            if count >= self.per_caller:
                return False
            self._by_caller[caller.who] = count + 1
            return True

    def release(self, caller: Caller) -> None:
        with self._lock:
            count = self._by_caller.get(caller.who, 0) - 1
            if count <= 0:
                self._by_caller.pop(caller.who, None)
            else:
                self._by_caller[caller.who] = count

    @property
    def open(self) -> int:
        with self._lock:
            return self._open
