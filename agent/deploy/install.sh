#!/bin/sh
# Instala, actualiza o desinstala el agente de Cenya en Linux
# (docs/agente-v2-instalacion.md, sección 5). POSIX sh: Debian, Ubuntu y la
# familia RHEL, con systemd y Python >= 3.10.
#
#   curl -fsSL https://github.com/cenya-io/cenya-agent/releases/latest/download/install.sh \
#     | sudo sh -s -- cenya://portal/CODIGO
#
#   sh install.sh [CADENA] [--ca FICHERO] [--version X.Y.Z]   instala, o actualiza si ya está
#   sh install.sh --update [--version X.Y.Z]                  actualiza (sin enrolar)
#   sh install.sh --uninstall                                 se despide del servidor y quita todo
#
# Y dos usos internos: `--update --archive F --version V` (lo llama, como root,
# `cenya-agent update apply-request` tras verificar F con su propio código) y
# `--watchdog ANTERIOR NUEVA SEGUNDOS` (la unidad del vigilante).
#
# Lo que deja:
#   /opt/cenya-agent/<versión>/   un entorno virtual por versión
#   /opt/cenya-agent/current      enlace a la que corre (cambiarlo es atómico)
#   /opt/cenya-agent/install.sh   esta misma lógica, para el vigilante y --uninstall
#   /usr/local/bin/cenya-agent    la orden; con sudo, corre como el usuario del agente
#   /var/lib/cenya-agent/         el estado (token, clave, ajustes, cola), 0700
#   cenya-agent.service           el agente, con su usuario sin privilegios
#   cenya-agent-update.path/.service  la actualización pedida por el agente
#
# Verificación. Lo que se descarga se comprueba contra el manifiesto firmado
# (latest.json + latest.json.sig, Ed25519) antes de instalar nada: la firma con
# las claves de RELEASE_KEYS (las pone el flujo de publicación al publicar este
# fichero), y el tamaño y la huella del archivo con lo que dice el manifiesto.
# Para verificar Ed25519 hace falta `cryptography`: se instala primero, sola, en
# un entorno temporal, y el verificador es el pequeño programa de más abajo (el
# agente aún no está instalado; es lo mismo que hace agent/release.py). openssl
# no sirve para esto en todas partes: `pkeyutl -rawin` con Ed25519 es de
# OpenSSL 3, y RHEL 8 trae 1.1.1. Sin claves en RELEASE_KEYS (una publicación
# sin firmar) se dice bien alto y solo se comprueba la huella.

set -eu

REPO_URL="${CENYA_REPO_URL:-https://github.com/cenya-io/cenya-agent}"
# Las claves públicas de publicación, en base64 y separadas por espacios. Vacío
# en el repositorio; el flujo de publicación las rellena (release_key.py embed-keys).
RELEASE_KEYS=''
PREFIX=/opt/cenya-agent
STATE=/var/lib/cenya-agent
AGENT_USER=cenya-agent
UNIT_DIR=/etc/systemd/system
BIN=/usr/local/bin/cenya-agent
WATCHDOG_UNIT=cenya-agent-watchdog

say() { printf '%s\n' "$*" >&2; }
die() { say "install.sh: $*"; exit 1; }

is_version() {
    case "$1" in
        '' | *[!0-9.]* | .* | *. | *..*) return 1 ;;
        *) return 0 ;;
    esac
}

need_root() {
    [ "$(id -u)" -eq 0 ] || die "hace falta root: sudo sh install.sh ..."
    command -v systemctl >/dev/null 2>&1 || die "hace falta systemd."
    command -v runuser >/dev/null 2>&1 || die "falta runuser (util-linux)."
}

find_python() {
    for candidate in python3.13 python3.12 python3.11 python3.10 python3; do
        if command -v "$candidate" >/dev/null 2>&1 &&
            "$candidate" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' 2>/dev/null; then
            if ! "$candidate" -c 'import ensurepip, venv' 2>/dev/null; then
                die "a $candidate le falta venv: apt install python3-venv (Debian/Ubuntu)."
            fi
            PYTHON=$(command -v "$candidate")
            return 0
        fi
    done
    die "hace falta Python 3.10 o posterior (python3)."
}

fetch() {
    # -L: GitHub redirige sus descargas. Todo lo que se baja se verifica después.
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL --retry 3 -o "$2" "$1"
    elif command -v wget >/dev/null 2>&1; then
        wget -q -O "$2" "$1"
    else
        die "hace falta curl o wget."
    fi
}

file_sha256() { sha256sum "$1" | cut -d ' ' -f 1; }
file_size() { wc -c <"$1" | tr -d ' '; }

# Comprueba la firma de latest.json y escribe en $WORK/release.env lo que hace
# falta de él (versión, URL, huella y tamaño del archivo de Linux).
verify_manifest() {
    if [ -n "$RELEASE_KEYS" ]; then
        "$PYTHON" -m venv "$WORK/verify"
        "$WORK/verify/bin/pip" install -q --disable-pip-version-check 'cryptography>=42' ||
            die "no se pudo instalar cryptography para verificar la firma."
        VERIFY_PY="$WORK/verify/bin/python"
    else
        say "AVISO: este install.sh no trae claves de publicación: no se puede verificar la firma"
        say "del manifiesto, solo la huella del archivo (que viaja por HTTPS desde GitHub)."
        VERIFY_PY="$PYTHON"
    fi
    "$VERIFY_PY" - "$WORK/latest.json" "$WORK/latest.json.sig" "$RELEASE_KEYS" >"$WORK/release.env" <<'PY'
import base64, json, re, sys
manifest, signature, keys = sys.argv[1], sys.argv[2], sys.argv[3].split()
data = open(manifest, "rb").read()
if keys:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    try:
        sig = base64.b64decode("".join(open(signature).read().split()), validate=True)
    except (OSError, ValueError):
        sys.exit("bad_signature: no hay firma válida")
    for key in keys:
        try:
            Ed25519PublicKey.from_public_bytes(base64.b64decode(key)).verify(sig, data)
            break
        except Exception:
            continue
    else:
        sys.exit("bad_signature: la firma no es de ninguna clave conocida")
info = json.loads(data)
linux = info["files"]["linux"]
version, url, sha, size = info["version"], linux["url"], linux["sha256"], int(linux["size"])
if not re.fullmatch(r"\d{1,6}(\.\d{1,6}){1,3}", version) or not re.fullmatch(r"[0-9a-f]{64}", sha):
    sys.exit("bad_manifest")
if not url.startswith("https://") or any(c in url for c in "'\"\\ $`"):
    sys.exit("bad_manifest: URL")
print(f"M_VERSION='{version}'\nM_URL='{url}'\nM_SHA='{sha}'\nM_SIZE='{size}'")
PY
    # shellcheck disable=SC1091
    . "$WORK/release.env"
}

# Descarga (o recibe con --archive) el archivo de la versión y lo deja en $ARCHIVE.
obtain_release() {
    if [ -n "$ARCHIVE" ]; then
        # Lo verificó quien llama (cenya-agent update apply-request).
        is_version "$VERSION" || die "--archive necesita --version."
        [ -f "$ARCHIVE" ] || die "no se encuentra $ARCHIVE"
        case "$ARCHIVE" in /*) ;; *) ARCHIVE="$(pwd)/$ARCHIVE" ;; esac
        return 0
    fi
    if [ -n "$VERSION" ]; then
        base="$REPO_URL/releases/download/agent-v$VERSION"
    else
        base="$REPO_URL/releases/latest/download"
    fi
    fetch "$base/latest.json" "$WORK/latest.json" || die "no se pudo descargar $base/latest.json"
    if [ -n "$RELEASE_KEYS" ]; then
        fetch "$base/latest.json.sig" "$WORK/latest.json.sig" || die "la versión no está firmada: no se instala."
    fi
    verify_manifest
    if [ -n "$VERSION" ] && [ "$VERSION" != "$M_VERSION" ]; then
        die "el manifiesto es de la $M_VERSION y se pidió la $VERSION."
    fi
    VERSION=$M_VERSION
    ARCHIVE="$WORK/cenya-agent-$VERSION.tar.gz"
    fetch "$M_URL" "$ARCHIVE" || die "no se pudo descargar $M_URL"
    [ "$(file_size "$ARCHIVE")" = "$M_SIZE" ] || die "bad_hash: el archivo no tiene el tamaño del manifiesto."
    [ "$(file_sha256 "$ARCHIVE")" = "$M_SHA" ] || die "bad_hash: el archivo no coincide con el manifiesto."
}

run_as_agent() {
    runuser -u "$AGENT_USER" -- env CENYA_STATE_DIR="$STATE" HOME="$STATE" "$PREFIX/current/bin/cenya-agent" "$@"
}

ensure_user() {
    if ! id -u "$AGENT_USER" >/dev/null 2>&1; then
        nologin=$(command -v nologin || echo /bin/false)
        useradd --system --user-group --home-dir "$STATE" --no-create-home --shell "$nologin" "$AGENT_USER"
    fi
    install -d -m 0700 -o "$AGENT_USER" -g "$AGENT_USER" "$STATE"
}

# Un entorno virtual nuevo al lado de los demás; el que está en marcha no se toca.
install_version() {
    dest="$PREFIX/$VERSION"
    mkdir -p "$PREFIX"
    chmod 0755 "$PREFIX"
    current_target=$(readlink "$PREFIX/current" 2>/dev/null || true)
    if [ "$current_target" = "$dest" ] && [ -x "$dest/bin/cenya-agent" ]; then
        say "La versión $VERSION ya está instalada."
    else
        rm -rf "$dest"
        "$PYTHON" -m venv "$dest"
        "$dest/bin/pip" install -q --disable-pip-version-check "cenya-agent[completo] @ file://$ARCHIVE" ||
            { rm -rf "$dest"; die "pip no pudo instalar la versión $VERSION."; }
    fi
    # Las unidades y esta misma lógica salen del archivo verificado.
    mkdir -p "$WORK/src"
    tar -xzf "$ARCHIVE" -C "$WORK/src"
    SRC=$(find "$WORK/src" -mindepth 1 -maxdepth 1 -type d | head -n 1)
    [ -f "$SRC/deploy/cenya-agent.service" ] || die "el archivo no trae deploy/cenya-agent.service."
}

switch_current() {
    ln -sfn "$1" "$PREFIX/current.new"
    mv -Tf "$PREFIX/current.new" "$PREFIX/current"
}

install_files() {
    install -m 0644 "$SRC/deploy/cenya-agent.service" "$UNIT_DIR/cenya-agent.service"
    install -m 0644 "$SRC/deploy/cenya-agent-update.path" "$UNIT_DIR/cenya-agent-update.path"
    install -m 0644 "$SRC/deploy/cenya-agent-update.service" "$UNIT_DIR/cenya-agent-update.service"
    install -m 0755 "$SRC/deploy/install.sh" "$PREFIX/install.sh"
    mkdir -p "$(dirname "$BIN")"
    cat >"$BIN.new" <<EOF
#!/bin/sh
# La orden del agente de Cenya (la deja install.sh). Con sudo corre como el
# usuario del agente: root no debe quedarse con la carpeta de estado.
export CENYA_STATE_DIR="\${CENYA_STATE_DIR:-$STATE}"
if [ "\$(id -u)" -eq 0 ]; then
    exec runuser -u $AGENT_USER -- env CENYA_STATE_DIR="\$CENYA_STATE_DIR" HOME="$STATE" $PREFIX/current/bin/cenya-agent "\$@"
fi
exec $PREFIX/current/bin/cenya-agent "\$@"
EOF
    chmod 0755 "$BIN.new"
    mv -f "$BIN.new" "$BIN"
    systemctl daemon-reload
    systemctl enable --now cenya-agent-update.path >/dev/null 2>&1 || true
}

# El vigilante de una actualización: una unidad que espera la marca de «sana» de
# la versión nueva y, si no llega, vuelve a la anterior. Con un temporizador
# persistente: si el equipo se reinicia en mitad, se ejecuta otra vez al arrancar.
install_watchdog() {
    previous=$1 next=$2 seconds=$3
    cat >"$UNIT_DIR/$WATCHDOG_UNIT.service" <<EOF
[Unit]
Description=Cenya agent: watch over the update from $previous to $next

[Service]
Type=oneshot
ExecStart=/bin/sh $PREFIX/install.sh --watchdog $previous $next $seconds
TimeoutStartSec=infinity
EOF
    cat >"$UNIT_DIR/$WATCHDOG_UNIT.timer" <<EOF
[Unit]
Description=Cenya agent: watch over the update from $previous to $next

[Timer]
OnActiveSec=30s

[Install]
WantedBy=timers.target
EOF
    systemctl daemon-reload
    systemctl enable --now "$WATCHDOG_UNIT.timer" >/dev/null 2>&1
}

remove_watchdog() {
    systemctl disable --now "$WATCHDOG_UNIT.timer" >/dev/null 2>&1 || true
    rm -f "$UNIT_DIR/$WATCHDOG_UNIT.timer" "$UNIT_DIR/$WATCHDOG_UNIT.service"
    systemctl daemon-reload || true
}

watchdog() {
    previous=$1 next=$2 seconds=$3
    if ! is_version "$previous" || ! is_version "$next"; then
        die "--watchdog ANTERIOR NUEVA SEGUNDOS"
    fi
    case "$seconds" in '' | *[!0-9]*) seconds=600 ;; esac
    [ "$seconds" -ge 60 ] || seconds=60
    waited=0
    while [ "$waited" -lt "$seconds" ]; do
        if [ -f "$STATE/updates/healthy-$next" ]; then
            say "La versión $next ha conectado: se queda."
            # Se guarda la anterior (vuelta atrás a mano) y se borran las demás.
            for old in "$PREFIX"/*; do
                name=$(basename "$old")
                is_version "$name" || continue
                [ "$name" = "$next" ] || [ "$name" = "$previous" ] || rm -rf "$old"
            done
            remove_watchdog
            return 0
        fi
        sleep 10
        waited=$((waited + 10))
    done
    if [ -x "$PREFIX/$previous/bin/cenya-agent" ]; then
        say "La versión $next no ha conectado en $seconds s: se vuelve a la $previous."
        switch_current "$PREFIX/$previous"
        mkdir -p "$STATE/updates"
        : >"$STATE/updates/failed-$next"
        chown "$AGENT_USER:$AGENT_USER" "$STATE/updates" "$STATE/updates/failed-$next" 2>/dev/null || true
        systemctl restart cenya-agent || true
    else
        say "No queda la versión $previous: no hay a qué volver."
    fi
    remove_watchdog
}

uninstall() {
    if [ -x "$PREFIX/current/bin/cenya-agent" ] && id -u "$AGENT_USER" >/dev/null 2>&1; then
        systemctl stop cenya-agent >/dev/null 2>&1 || true
        # Se despide del servidor (spec 1.7). Sin red, borra igual y sale con 0.
        run_as_agent goodbye || true
    fi
    remove_watchdog
    for unit in cenya-agent.service cenya-agent-update.path cenya-agent-update.service; do
        systemctl disable --now "$unit" >/dev/null 2>&1 || true
        rm -f "$UNIT_DIR/$unit"
    done
    systemctl daemon-reload || true
    rm -rf "$PREFIX" "$STATE"
    rm -f "$BIN"
    if id -u "$AGENT_USER" >/dev/null 2>&1; then
        userdel "$AGENT_USER" >/dev/null 2>&1 || true
    fi
    say "El agente de Cenya se ha desinstalado."
}

main() {
    MODE=install
    CONNECTION=''
    CA=''
    VERSION=''
    ARCHIVE=''
    while [ $# -gt 0 ]; do
        case "$1" in
            --update) MODE=update ;;
            --uninstall) MODE=uninstall ;;
            --watchdog)
                [ $# -ge 4 ] || die "--watchdog ANTERIOR NUEVA SEGUNDOS"
                need_root
                watchdog "$2" "$3" "$4"
                exit 0
                ;;
            --version) [ $# -ge 2 ] || die "falta la versión"; VERSION=$2; shift ;;
            --archive) [ $# -ge 2 ] || die "falta el archivo"; ARCHIVE=$2; shift ;;
            --ca) [ $# -ge 2 ] || die "falta el fichero de la CA"; CA=$2; shift ;;
            cenya://* | cenya+http://*) CONNECTION=$1 ;;
            *) die "no entiendo «$1»." ;;
        esac
        shift
    done
    need_root
    if [ "$MODE" = uninstall ]; then
        uninstall
        exit 0
    fi
    [ -z "$VERSION" ] || is_version "$VERSION" || die "versión no válida: $VERSION"
    find_python
    WORK=$(mktemp -d)
    trap 'rm -rf "$WORK"' EXIT
    obtain_release
    previous=''
    if [ -L "$PREFIX/current" ]; then
        previous=$(basename "$(readlink "$PREFIX/current")")
    fi
    ensure_user
    install_version
    if [ -n "$previous" ] && [ "$previous" != "$VERSION" ] && is_version "$previous"; then
        # Una actualización: la marca de «sana» de un intento anterior no vale,
        # y el vigilante queda puesto ANTES de cambiar de versión.
        rm -f "$STATE/updates/healthy-$VERSION"
        install -m 0755 "$SRC/deploy/install.sh" "$PREFIX/install.sh"
        seconds="${CENYA_UPDATE_WATCHDOG_SECONDS:-600}"
        case "$seconds" in '' | *[!0-9]*) seconds=600 ;; esac
        install_watchdog "$previous" "$VERSION" "$seconds"
    fi
    switch_current "$PREFIX/$VERSION"
    install_files
    if [ -n "$CA" ]; then
        [ -f "$CA" ] || die "no se encuentra $CA"
        # Lo copia y lo anota el propio agente, como su usuario: él lo valida.
        install -m 0600 -o "$AGENT_USER" -g "$AGENT_USER" "$CA" "$STATE/ca-import.pem"
        run_as_agent settings set ca_bundle "$STATE/ca-import.pem" || { rm -f "$STATE/ca-import.pem"; die "el certificado de la CA no se pudo aplicar."; }
        rm -f "$STATE/ca-import.pem"
    fi
    if [ -n "$CONNECTION" ] && [ "$MODE" = install ]; then
        if [ -f "$STATE/enrollment.json" ]; then
            say "Este equipo ya está enrolado: se ignora la cadena (cenya-agent enroll <cadena> --force para cambiarlo)."
        else
            run_as_agent enroll "$CONNECTION" || die "el agente se instaló, pero no se pudo enrolar."
        fi
    fi
    systemctl enable cenya-agent >/dev/null 2>&1
    if [ -f "$STATE/enrollment.json" ]; then
        systemctl restart cenya-agent
        say "Cenya Agent $VERSION instalado y en marcha (journalctl -u cenya-agent)."
    else
        say "Cenya Agent $VERSION instalado. Para conectarlo: sudo cenya-agent enroll <cadena>"
        say "y después: sudo systemctl start cenya-agent"
    fi
}

main "$@"
