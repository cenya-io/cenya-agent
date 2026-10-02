"""Punto de entrada de `cenya-agent-app.exe`: la ventana de Cenya Agent (sin consola)."""

from agent.app.main import main

if __name__ == "__main__":
    raise SystemExit(main())
