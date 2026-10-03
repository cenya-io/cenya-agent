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
        # Todavía no está el archivo (ni su requirements-linux.txt): estas líneas
        # son las de cryptography en ese lock, copiadas por packaging/lock_linux.py.
        cat >"$WORK/verify-requirements.txt" <<'REQ'
# BEGIN verify-requirements
cffi==2.1.1 ; platform_python_implementation != 'PyPy' or sys_platform == 'win32' \
    --hash=sha256:046bfc24911b37851ee1b51aab8bffe713d89c68c6a057b09484ce9fd5f69b4e \
    --hash=sha256:06c72bb76605a4b0cd0aad6930b69d4baf7dd5d806cfc409b824191099700e66 \
    --hash=sha256:0beceaabe56af686895136a2de78db54ecd8e4046b236b8fd6d6cb61389e9bf2 \
    --hash=sha256:154852545011f779917b11c78db2358d095da62a9a172b78ad0a583ee5adc0d0 \
    --hash=sha256:194cffa889098ced9976c3fc6340305e43f6303657d298da55366907c05c22d6 \
    --hash=sha256:19ee6127ee34de7d83ce3d371ebc5ed91addbdcc39f9ab15ce4eb35a4e534971 \
    --hash=sha256:1a18a57b58cfb21fc28d72e876acf10eaed67a1ed96226f92af4df681d571c4c \
    --hash=sha256:1aa5645c30469b09530c4ebca77ebf8f17618293c58f8549cb1a543a50236e7d \
    --hash=sha256:1dea0e4d7d4f11f619fe8c1d76caf49e24405b4b5743c0e3be16a500ecd930c9 \
    --hash=sha256:208f941bb9d18e768138677f0a6d2ce01f590df56043dda1df1535ac57c88517 \
    --hash=sha256:210019b6c7cf07f081b4c54635c8cf744377001350e29cc0f81c4377b4797735 \
    --hash=sha256:246fa40ce8645a614ff682e0b70f37134e460eaf93a775e0cbe3cca585a67a80 \
    --hash=sha256:25792eac27877609e7bb06d42ff88278a6624fff2ba9bbb523c09616b117e80f \
    --hash=sha256:27350daa11d4f10c540e6e89dada4c54feb7256ad03e9a4dc075ebad7ba360d1 \
    --hash=sha256:28907ab9bfb6aa13184cfc17c6b8e1023c5ab6fd7076d8c20a35e59fe04f8f29 \
    --hash=sha256:2ae64be792b8966f2c69538199728b290e34726562896df1e5dc8ffd8d8188e8 \
    --hash=sha256:31348097ff5bbe827ccc41795d4dd099d9f0625e7def00ee653c137a490c2a6c \
    --hash=sha256:3143d81e29e1e20a9ce10901ec369012947876596f75a222235965f2b7ae832e \
    --hash=sha256:3222ba5d678f80a030e6afbcc33dc1ae5cb45facabb61cee2c7016b8432fde48 \
    --hash=sha256:3311ed60d36f83378794e1009ac6258bafbf81f7888b4caa7b35a521e3f95813 \
    --hash=sha256:334644fbac4eff73d985a17a91226df55d0f394160c4cfb880e084c8f7161cac \
    --hash=sha256:34e261f78cb6ceaaa36f42f2613f4380d94d9c759a9c73c769ee6e0247364632 \
    --hash=sha256:363e05fa78e15116c3c32c210ee36884fd6b9afa6d440e47112c3bd511d64cb6 \
    --hash=sha256:398aff33cee2767e3e781d2554c54bd0dff386bb437581e0d8011fde1a942ec1 \
    --hash=sha256:3d22a20b1fb1632cc72c22f95f7b0d2961c3e1c235f245ba4c606c4771035659 \
    --hash=sha256:42a494cee34437f05546455144f2b5d9ac09b1face62bcfce597d2e521066688 \
    --hash=sha256:42e2f76b9455f5a9a844f770bf3e200ed3da0e15f5df3db9c31fe80b04b3d004 \
    --hash=sha256:42f6930c31dc7f50732c9ae793c2786c7b6b044195967bbdde40bb9be81c4cc0 \
    --hash=sha256:456a61fa52d579ebf9df2e9552ead5129855dbaff6c1e5a9b1bc408809bdc062 \
    --hash=sha256:471cee653ae88de62096552e6d24ccb4a5adb8c8c9f10b5054d0122c15bf2779 \
    --hash=sha256:49cbc70e6542d4ccccb936558d1064a8012541e78f821f955cff24e357776c94 \
    --hash=sha256:4a7c934f7360e8cd64fe9efadcbd10c7c6364f531e432b9a4bf5ccbc9e0e8b50 \
    --hash=sha256:4be96343e422f2dfcd12ab5c9f5aebe03f82f737c6bffeca6830b3875cb44aab \
    --hash=sha256:4f42141fc14250de6dde5ee7ea4432be017252d91f19c5ad043c084cea629cac \
    --hash=sha256:507a24c282e0f42f8ed737cf048572cbf580468da5555764a8331735e9c736b6 \
    --hash=sha256:51b31d1c98274844cfd7838ce00bfc27c7423a4dc00fc0772fc3331c2cc90676 \
    --hash=sha256:58acb8ab8e295e6c5ea12f888cbb13cf21511ef2a3303a23f4325c29d17fe5c1 \
    --hash=sha256:5a59cc1c4442bc3d5c703bf720b51138d0bfc173618807c9ee2490a7541dd3d9 \
    --hash=sha256:5bb4e7ea95dcd6a014a6fef62e62467d67d8e582326443f3d68e71d6320a9fcf \
    --hash=sha256:5c58fe613dc5e5336357eff555824a314d8e43282600435c8d1cb6a7a2fedd13 \
    --hash=sha256:5e7cecbaadb83884793e05828cee59b210b24583b9c7425d0ba6a754fe22eb4e \
    --hash=sha256:616f097f2fe415bc92a247f02e11f634e1f9e9a83d327e3c915c15089c87869e \
    --hash=sha256:63bbfd5ded17c4840ac07cd8f1c21ba9d9708141f840b324f422f41b207e3973 \
    --hash=sha256:64faea20f4e2613363a1a9b9c7dd73058f3ecd00133a511e72ad7c511658f527 \
    --hash=sha256:661c298b4821edebead0c91edd2b00374d67ad7c5a1f7a91d4442633b79d6a72 \
    --hash=sha256:68e62fe11f30d5ca8289242866f0a5291402d8529ca2178ab8afc5c9694ae890 \
    --hash=sha256:6a8dddef476fab96d066d578fc88526767b836ab5ab21754e1d5bf3879c31c7c \
    --hash=sha256:6e192623c49c94421616a5778fba35cf0d5a8d000650c1967ef4448ee5cdd990 \
    --hash=sha256:7225e4514edb64eb6740324353e0da0711954fd8d7da4576755b1c6e09b697cd \
    --hash=sha256:75f80557d1389eddbd0de2681f6a390a0c5338c31ddaa821381c203fc3fd50d9 \
    --hash=sha256:770de9db11e84213beec501cfcaa013b019820ca881e03344dea5844f7876d94 \
    --hash=sha256:7750c6449dff7864bb9bb27ddfb0267756189201a3afc911d82b3caacd70dfc3 \
    --hash=sha256:7bde5e4cc5c10140859842b9d383af292b22639a4dffb725314baf45968cef80 \
    --hash=sha256:7ce713ace7c0e4520535b42b77eaa742c16dab813978064913e5a3cf82973b41 \
    --hash=sha256:7da0c5eff80f0197f3b3d1232ec5a682a9325f4ae9016a78f5f5ca35f9ced1f5 \
    --hash=sha256:7dbb61fe3a7699468030f71bbe5f8a0e326a151daa91beb11a6fc1f980c55e1c \
    --hash=sha256:811bd1e21d32de12efca32393a0ab3f5133b54fce9bd44b8bd77ab07da14bf6a \
    --hash=sha256:8ef53b2de9bcb9197d31854256575d59dbac0cba72ac627bb291ef5eceb74be4 \
    --hash=sha256:937c0052c05a31ca1daf18de3158eed4dbfcb9cc107adbea227728d647be701e \
    --hash=sha256:9d2055050ea716bd38b7f7f1579c275386646b4894c155a3e2f3cd62ed41b7c6 \
    --hash=sha256:9f8d177621de5cb38ee3e731eda45d421db093ec0739f46a5594babda7987a98 \
    --hash=sha256:a2d7755bef5a12ed488f4ef1f1b69ee9191d7396083b755a5d2295f6edb4768b \
    --hash=sha256:a48d62ab9d6f4f98c983223a547af44be6ca3691074c31cecced6facd3ba2dc1 \
    --hash=sha256:a4f00aa42f75d6e4595e8866e748cc1705adc0cddfeb2ca86d0d03993d63ba03 \
    --hash=sha256:a6e721d4b0e45d5b65e87534470e67b18dcd092c83f68fba09f152b9cbc061af \
    --hash=sha256:a730a083190634c65cca36ba5f489531576ebd79bcd5c8e172130f6453127231 \
    --hash=sha256:a931079504ecc49efed7744c476a5c343a92fabf66dec2db95edb1b2fdc770e2 \
    --hash=sha256:aa9511c62d14da7aacc9b4bf51f3f697a621e83b2d6919008243c3aad168eea3 \
    --hash=sha256:ab36d55f9ed2d067327667c2fea18dda018eb628dd6347aa01dda6cf1f5d3836 \
    --hash=sha256:ad2c86c495b899d862ea0f4b42891b8713a3bd45dd4105c7fd51c2a72f39f3a5 \
    --hash=sha256:aeae0e330c9f6acd681f647d46cefd30c29f93e3392882e792e82080c9691399 \
    --hash=sha256:b0431303acaea1089ad4b3e9ce4e6518193def1118d4073ca848635ee4ea2e96 \
    --hash=sha256:b5bdfd1c873d4e093aabc0ca84c4ca6dbc4f752afb5c86f146d9742580c9da2e \
    --hash=sha256:baed1e86cc735622097354b9d1281406caf42ff42a886d29faa8e8d1630333be \
    --hash=sha256:c1453022f490d2459a11819d83ad1d586e9ff65a12ac3e705ffebd46d3685dcf \
    --hash=sha256:c26608d2222fb1e94487e4a387d85f13eb55d5ed725cb25a0c589ac4ee60e7bc \
    --hash=sha256:c7659f22557c5a0bc4855cd635f55edec690cc008a40768527762cb9fb263455 \
    --hash=sha256:c8c69575568085ba0b1b10c0249d779a214aea6f6522e949a0fc9fb0fcb449d0 \
    --hash=sha256:c8d2c9fd1f2d16f780d15127abb050d13d1a76c03a4bd87d7e4980e45e511e12 \
    --hash=sha256:ca82be1a1d406ecfe1d25dc16cb33488e5a16bf4438c9fb590484ea29d92478b \
    --hash=sha256:cc572dace3f60ef98d7b12ff411d20f5362feb31a0439eab0085bbfd349982d7 \
    --hash=sha256:d18e5ac0f2f03f4f518d3e23db0f0cad7faa1da8620e9c09461d443bbf6e6692 \
    --hash=sha256:d28630f5854ab07ab1fd4aba756de52326c82e6be15d414b12793f1975048b54 \
    --hash=sha256:d9c275eaacd24aa73f94ffd6de08fc3f932424d8b6c376f4bed7cde376fe7bc3 \
    --hash=sha256:da0e573f9f97159390c89d9f1a9e41908b66d408cc5b58d08cf3847d844c531b \
    --hash=sha256:dd31f52ea1086513bb9df30f8fcee9b8918323ae067a3d5b78bc826a000712be \
    --hash=sha256:dddad92b554513a31f272570678ba307fb9f618f05e3d4a5eacafff9eae03e1d \
    --hash=sha256:df423d40ee8654634421812bc3b196da3f9bd7d32929da813f8394c4348a5358 \
    --hash=sha256:df913725b79db7bcf03448f36b7bf8815363417d5b58deecf9305e3e30f0f21a \
    --hash=sha256:e0bcb7e0f677f543555d2adff3bf19c05f66cdb4796e5ff602442ab2fe3c4ef7 \
    --hash=sha256:e2d65b31f36619cda3999b78b2aa9632e76b78448e7a56fc4240824200e7c4fc \
    --hash=sha256:e6e8cff14d6fb0be70a09c0bdc58096f501952d04624ebf867e0e56da2df8960 \
    --hash=sha256:f16c709686a78c727bbbf059f92b0bf41c6fc60deec706d2dc19f529175a6125 \
    --hash=sha256:f24fb43132a4c6b4cb4eb029492919b2db645be6808d738f244fd146c03c32cb \
    --hash=sha256:f53e442b08449d42821fa4a4fba000095af9f62742a500f978a9f557ec44339a \
    --hash=sha256:f5cfbc5fe74540d335175b656c725d74d90e3730c626d92575eea35029d9afaa \
    --hash=sha256:f81b3b8f3d4e343550fa4baa0e479bba9f2d29ce9c2e9b51d1ce1718d7442fcf \
    --hash=sha256:f8ec5e643a9a937f64e1999eb9f75d072263751912dc5cd06d3c85f8f44be7c3 \
    --hash=sha256:fb92203a88b3d3053034db775110081c49d28be6551923805e039924093761e4 \
    --hash=sha256:fcd22650c908d7b7da162bbfaab594a1227a15d1643a98c68b122ac642fa2264
cryptography==50.0.2 \
    --hash=sha256:0ddc924c04591c2811ca024d62ecad4f7f6f08af8939c211438f48a16bd23602 \
    --hash=sha256:0ec5f09541743261e66e291b4a0cbf0fb2997aeaab6d9e9c740b9dba1b58d1c2 \
    --hash=sha256:0ecbc5652bdb6fc9eaf89a7d196e20941adfe812f43bc4ca05d9150496821047 \
    --hash=sha256:1981f1db4630889b9ef7803fadef12b056f428cb6b85c27ba57b774793b6093c \
    --hash=sha256:1ba34f04897fcdaa73f74145c25f3ec146fbd56593853e88adc2e811303c5f42 \
    --hash=sha256:241449bf940a5d27309bd317e6f9a2af6932113818bb2b8f5c59ddc7ef16da18 \
    --hash=sha256:25784ce8b9621c90c643efb9e1e2162ab3b0224cae446ad5e70e7fcb1ce18b51 \
    --hash=sha256:3dc4fd8058cea1644971207d530e1a03a184a805ffc8ebdddf0599d78a331b81 \
    --hash=sha256:4061c0079120205fb760c58acab6443e217307dcf05e3702cf970e0689972856 \
    --hash=sha256:4a20ce1e5cb4284a86692fdcba7cb8754185c6b2e5c56fcef3751cf451d3cdc2 \
    --hash=sha256:4e81d95e5bafc2d6e34e4bed780e53e4d5b9a2f928573428aa4d35fbec1eb0de \
    --hash=sha256:58a0c478eeca76fe5e07993c5a0703def34a6dc6a0cda4f5564639b33112ffe7 \
    --hash=sha256:58ddb5a8e3179d12f19e4ea34d2d32e9d63a4baa142c875c1eb59f41b7243acd \
    --hash=sha256:630ebfea3bf689d075f82316324ff7433dc447fe6bc1bfc76524b74b4a9567d2 \
    --hash=sha256:6f8700550aa1474a91e5dc07049c46f98b423b5b1ddd0483e0b51362eeeaf5be \
    --hash=sha256:78198641e5be9521beea5aa782bb551a58068d10e6eb04c9c680c1b69f2e7d45 \
    --hash=sha256:79def8d059362e7831389ed3be0ecdf58a89386e1271e35dd9f5af84e81bffd0 \
    --hash=sha256:7a8701d6b584d76e909e3d305b7d126b41439876a5aaf76cddc67fc230eafa2e \
    --hash=sha256:7afa5a6602a9f29af1f3a2965f831bae7c9d5d597b7cbb716d41ab3b7d89879c \
    --hash=sha256:7b46165bb56eb4704e2eaaf86f3c940d19154535d9b0ca7d6d590b04060e00d5 \
    --hash=sha256:7b75de3c8b3be1cdb1052747c929440c3eea46c1bc2cb8a6e3a48388e9b7b452 \
    --hash=sha256:7c6d0330c472d96f6a6afe24d80dfdf15176c33096f0a4397ae4c60f3dd3be48 \
    --hash=sha256:828d49b0ff5a0e3975865571c5d91dbbdd0d38d8289b249a163e9425413a5e05 \
    --hash=sha256:84f964e537f916e2cc85199e5a88742e964939b575ac8598b3f9d6cc416cdaf1 \
    --hash=sha256:85d0d9a31b9098e98534226d5686b47264b95e62ce459dc2e62fdfc809f9fe93 \
    --hash=sha256:87e9ce85beb6b328ba370cc6e6aea483c92617b4c95b1d33a49297eb662bfb04 \
    --hash=sha256:8c71ba2cd31fc93748c38e1b613200ff1c2665cbfd5341fe3a61cfde35a1430e \
    --hash=sha256:92e665960f25fcdc73725b9cec7a3824f279ba97a98653afe9ffac2e43668f67 \
    --hash=sha256:94e5e9f108ee10471288214d3d233fbfbb492840a8457eb85178d643ddeb32c7 \
    --hash=sha256:9c8402a82ea0dc4ceeab793db05f0fafa8ca139ca34fcde5df0f596103c74107 \
    --hash=sha256:9dab55f57c74c3cad24c323bacbbd04be4705ba6eb0d92e920b1fc4837ed5079 \
    --hash=sha256:a582ab2ae1d34f67112cadc86702774c9ea4374df6bca6afe672817203c99134 \
    --hash=sha256:a6557e5f38e065ca9fbdaf7cfc7435ecb1d113aa81a022d1b51921ee7432e227 \
    --hash=sha256:a9f7355e6fab51f6c369b86fb7571cffa05edee2c2121e0380a37fb9ac1cd5c1 \
    --hash=sha256:ab50ee449bf968271e820086f10a33d101dd060370abc10bcd22279be2656539 \
    --hash=sha256:ac9ed99d81760c62fe89d5f0815cdfa1ba9a35141cf30f1c2d044f04b4803d2e \
    --hash=sha256:b13478603dcd0a2479ff8e87e2c19a7d525734686fe3c49542472293a204212d \
    --hash=sha256:c423ab384a46c4dff7217b2ea5ba2e11cffdeab6441acd04cf65a369caf0366c \
    --hash=sha256:c5e67125c7dca78d199ec4e116aa93dbb83494808ecbb8211a2cb09b1bf41dbd \
    --hash=sha256:c71be1cbfa5cd9a41ee452acf1eccd82b2c05950358b106ec8ceb83411d1a020 \
    --hash=sha256:cbc8738fd8526d80f35cb3a40d41f41a2e7030bb3b18b09a6778ef63d291c2fd \
    --hash=sha256:ce47f66801c20ec6c6632453bb5960fe38939e9306970b48b3a5a26de7745d94 \
    --hash=sha256:d370b8d1dfcdf7130178137f6fbee6140774a1acc6cacefc4b42643ec11d0a3a \
    --hash=sha256:d38cdff612d06fa6a32840d5e1b1f7a27cee4a349aa9085d94a67789d6bfd408 \
    --hash=sha256:d8947001be83df1394050758ce0e745dd74fb134eef0a4b5124208dfc3a68c37 \
    --hash=sha256:deb9fde5c60e437ee4821bc9bc39ff31b42135c27e1dc61ef0a629389c1de62e \
    --hash=sha256:dfe9763530994147d9af1def057a5b9658b00e8f8fe8743d144d1e0911c2e454 \
    --hash=sha256:e105ab60406787da31fccc883fc0f733af1efd78f0136a4599692c4083a73d0c \
    --hash=sha256:e275096ea1e60cc595cda2836fd4a6c725d1125108b868be17f53684d164e2cc \
    --hash=sha256:edc3342adf8f697fc5f59c887a304356f147b397809440ed64e2fa6af2f50f37 \
    --hash=sha256:ee247f5c245c9a2fe7c8e2214e295918838e44e00a45a6718451e4004219e767 \
    --hash=sha256:eef4c2f3423810b3070ab391f85436d2f8bbfcb286ac15cbc73190b3563b1f1a \
    --hash=sha256:f21e8a22c8605750c7af886bab299a363721264061b4ac0a30efb73cfd58efc5 \
    --hash=sha256:f265528741e048bce55c3463ed721fb0aa45a5888d8add8cfeccb3035451bbdc \
    --hash=sha256:f2f9bd7f90c64fe89253f0a2c05e3c4856072660429ce8831b4235bf29403a67 \
    --hash=sha256:f785f6161f202ab04d8ca194158968798e480ca058943907972da5f12e2881e8 \
    --hash=sha256:f9f6143a8c75945eb960d9eb98905a441394abfa24afaae239d514ffb2586480 \
    --hash=sha256:fa8f5efb344d6908a1ce62f4a24e2e5780f825d6f53f5f50ec5ffacac72936cb \
    --hash=sha256:fdd28f912fccfec1846a94e2e1e8f9b0012f557f0c46fe4f3eb0d7a87afcf90b
pycparser==3.0 ; (implementation_name != 'PyPy' and platform_python_implementation != 'PyPy') or (implementation_name != 'PyPy' and sys_platform == 'win32') \
    --hash=sha256:600f49d217304a5902ac3c37e1281c9fe94e4d0489de643a9504c5cdfdfc6b29 \
    --hash=sha256:b727414169a36b7d524c1c3e31839a521725078d7b2ff038656844266160a992
typing-extensions==4.16.0 ; python_full_version < '3.11' or sys_platform == 'win32' \
    --hash=sha256:481caa481374e813c1b176ada14e97f1f67a4539ce9cfeb3f350d78d6370c2e8 \
    --hash=sha256:dc983d19a509c94dba722ee6abd33940f7c05a89e243c47e907eb4db6f1a43e5
# END verify-requirements
REQ
        "$WORK/verify/bin/pip" install -q --disable-pip-version-check \
            --require-hashes --no-deps --only-binary :all: -r "$WORK/verify-requirements.txt" ||
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

# Las marcas de la actualización (`updates/healthy-X`, `updates/failed-X`) viven
# en la carpeta del usuario del agente: root no las toca por ruta.
# shellcheck disable=SC2016 # $1 y $2 son de la sh hija, a propósito
mark_as_agent() {
    runuser -u "$AGENT_USER" -- sh -c 'mkdir -p "$1/updates" && : >"$1/updates/failed-$2"' sh "$STATE" "$1" || true
}

# shellcheck disable=SC2016
unmark_as_agent() {
    runuser -u "$AGENT_USER" -- sh -c 'rm -f "$1/updates/healthy-$2"' sh "$STATE" "$1" || true
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
    # Las dependencias fijadas, las unidades y esta misma lógica salen del
    # archivo verificado.
    mkdir -p "$WORK/src"
    tar -xzf "$ARCHIVE" -C "$WORK/src"
    SRC=$(find "$WORK/src" -mindepth 1 -maxdepth 1 -type d | head -n 1)
    [ -f "$SRC/deploy/cenya-agent.service" ] || die "el archivo no trae deploy/cenya-agent.service."
    [ -f "$SRC/deploy/requirements-linux.txt" ] ||
        die "el archivo no trae deploy/requirements-linux.txt: sin dependencias fijadas no se instala."
    # Va dentro de una línea de requisitos de pip: solo caracteres que no se
    # puedan leer como otra cosa (ni espacios, ni «#», ni «;»).
    case "$ARCHIVE" in *[!A-Za-z0-9._/-]*) die "la ruta del archivo solo puede tener letras, números y . _ - /: $ARCHIVE" ;; esac
    current_target=$(readlink "$PREFIX/current" 2>/dev/null || true)
    if [ "$current_target" = "$dest" ] && [ -x "$dest/bin/cenya-agent" ]; then
        say "La versión $VERSION ya está instalada."
    else
        rm -rf "$dest"
        "$PYTHON" -m venv "$dest"
        # Como root, nada sin huella: primero exactamente lo del lock (solo
        # ruedas, ningún setup.py ajeno se ejecuta), después el agente sin
        # dependencias, sin índice y con el setuptools que acaba de entrar.
        printf 'cenya-agent @ file://%s --hash=sha256:%s\n' "$ARCHIVE" "$(file_sha256 "$ARCHIVE")" >"$WORK/agent-requirement.txt"
        { "$dest/bin/pip" install -q --disable-pip-version-check \
            --require-hashes --no-deps --only-binary :all: -r "$SRC/deploy/requirements-linux.txt" &&
            "$dest/bin/pip" install -q --disable-pip-version-check \
                --require-hashes --no-deps --no-build-isolation --no-index -r "$WORK/agent-requirement.txt"; } ||
            { rm -rf "$dest"; die "pip no pudo instalar la versión $VERSION."; }
    fi
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
        # Como el usuario del agente, nunca como root: la carpeta es suya y un
        # enlace puesto ahí llevaría a root a crear o truncar otro fichero.
        mark_as_agent "$next"
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
        unmark_as_agent "$VERSION"
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
