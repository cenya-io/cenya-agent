"""The tray icon, drawn in plain Python at whatever size Windows asks for.

The Cenya app icon (the navy rounded square with the three stacked layers, as
in the brand pack's ``cenya-icono-app.svg``) with a status dot in the corner. Drawn
here instead of shipped as ``.ico`` files so that it is sharp at every display
scale -- 16 px at 100 %, 24 at 150 %, 32 at 200 % -- without an image library
(Pillow would be a dependency for three polygons and two circles) and without files to package.

The output is what ``win32gui.CreateIconFromResource`` takes: a 32-bit DIB with
its alpha channel. Pure Python on purpose, so it is tested without Windows.
"""

from __future__ import annotations

import math
import struct
from collections.abc import Callable

#: Los colores del icono de app del paquete de marca: fondo marino y las tres
#: capas en los celestes de la versión «sobre oscuro», de arriba abajo. Los
#: tonos de estado son los de la aplicación (assets/css/app.css). El gris es el
#: de «no lo sé», no el de «apagado».
BACKGROUND = (0x0F, 0x17, 0x2A)
LAYERS = ((0x38, 0xBD, 0xF8), (0x0E, 0xA5, 0xE9), (0x03, 0x69, 0xA1))
TONE_COLORS = {
    "ok": (0x22, 0xC5, 0x5E),
    "warning": (0xF5, 0x9E, 0x0B),
    "unknown": (0x9C, 0xA3, 0xAF),
}

#: Submuestras por lado de píxel: 4×4 da bordes suaves sin que dibujar un
#: icono de 32 px cueste nada que se note.
SUBSAMPLES = 4

Shape = Callable[[float, float], float]  # distancia con signo: negativa dentro


def _rounded_square(size: float, radius: float) -> Shape:
    half = size / 2

    def distance(x: float, y: float) -> float:
        qx = abs(x - half) - (half - radius)
        qy = abs(y - half) - (half - radius)
        outside = math.hypot(max(qx, 0.0), max(qy, 0.0))
        return outside + min(max(qx, qy), 0.0) - radius

    return distance


def _circle(cx: float, cy: float, r: float) -> Shape:
    return lambda x, y: math.hypot(x - cx, y - cy) - r


def _polygon(points: list[tuple[float, float]]) -> Shape:
    """Dentro o fuera de un polígono (par-impar). Solo el signo cuenta: el
    suavizado lo dan las submuestras, no la distancia."""

    def distance(x: float, y: float) -> float:
        inside = False
        j = len(points) - 1
        for i, (xi, yi) in enumerate(points):
            xj, yj = points[j]
            if (yi > y) != (yj > y) and x < (xj - xi) * (y - yi) / (yj - yi) + xi:
                inside = not inside
            j = i
        return -1.0 if inside else 1.0

    return distance


#: Las tres capas del símbolo, de arriba abajo, en las coordenadas de 0 a 100
#: de ``cenya-simbolo-*.svg``.
LAYER_POINTS = (
    ((50, 10), (88, 27), (50, 44), (12, 27)),
    ((12, 39), (50, 56), (88, 39), (88, 48), (50, 65), (12, 48)),
    ((12, 60), (50, 77), (88, 60), (88, 69), (50, 86), (12, 69)),
)


#: Escala y desplazamiento del símbolo dentro del cuadro de 100. El icono de
#: app del paquete lo pone al 65 %; aquí va al 82 %, porque a 16 px de bandeja
#: al 65 % las tres capas se funden en una mancha.
LAYER_SCALE = 0.82
LAYER_OFFSET = (50 - LAYER_SCALE * 50, 50 - LAYER_SCALE * 48)


def _layers(size: float) -> list[Shape]:
    unit = size / 100
    dx, dy = LAYER_OFFSET
    return [
        _polygon([((dx + LAYER_SCALE * x) * unit, (dy + LAYER_SCALE * y) * unit) for x, y in layer])
        for layer in LAYER_POINTS
    ]


def render_rgba(size: int, tone: str) -> list[tuple[int, int, int, int]]:
    """Los píxeles del icono, fila a fila desde arriba, en RGBA sin premultiplicar."""
    color = TONE_COLORS[tone]
    s = float(size)

    square = _rounded_square(s, radius=s * 0.22)
    layers = _layers(s)

    # El punto de estado en la esquina, con un anillo recortado para que se lea
    # sobre el marino y sobre cualquier barra de tareas, clara u oscura.
    dot_center = s * 0.78
    dot = _circle(dot_center, dot_center, s * 0.19)
    cutout = _circle(dot_center, dot_center, s * 0.27)

    pixels: list[tuple[int, int, int, int]] = []
    step = 1.0 / SUBSAMPLES
    for row in range(size):
        for col in range(size):
            totals = [0.0, 0.0, 0.0, 0.0]  # rojo, verde y azul ya multiplicados por alfa, y alfa
            for sy in range(SUBSAMPLES):
                for sx in range(SUBSAMPLES):
                    x = col + (sx + 0.5) * step
                    y = row + (sy + 0.5) * step
                    if dot(x, y) <= 0:
                        sample = color
                    elif cutout(x, y) <= 0:
                        continue
                    elif square(x, y) <= 0:
                        sample = BACKGROUND
                        for layer, layer_color in zip(layers, LAYERS):
                            if layer(x, y) <= 0:
                                sample = layer_color
                                break
                    else:
                        continue
                    totals[0] += sample[0]
                    totals[1] += sample[1]
                    totals[2] += sample[2]
                    totals[3] += 1
            count = SUBSAMPLES * SUBSAMPLES
            covered = totals[3]
            if covered == 0:
                pixels.append((0, 0, 0, 0))
                continue
            pixels.append(
                (
                    round(totals[0] / covered),
                    round(totals[1] / covered),
                    round(totals[2] / covered),
                    round(255 * covered / count),
                )
            )
    return pixels


def icon_resource(size: int, tone: str) -> bytes:
    """El icono como recurso DIB de 32 bits, lo que pide `CreateIconFromResource`.

    Cabecera `BITMAPINFOHEADER` con el doble de alto (la mitad de abajo es la
    máscara AND de los iconos), píxeles BGRA de abajo arriba, y una máscara
    AND a cero: con alfa, Windows usa el canal alfa y la máscara no cuenta.
    """
    header = struct.pack("<IiiHHIIiiII", 40, size, size * 2, 1, 32, 0, 0, 0, 0, 0, 0)
    rgba = render_rgba(size, tone)
    rows = [rgba[row * size : (row + 1) * size] for row in range(size)]
    color = b"".join(
        bytes((b, g, r, a)) for row in reversed(rows) for (r, g, b, a) in row
    )
    mask_row = ((size + 31) // 32) * 4
    return header + color + bytes(mask_row * size)
