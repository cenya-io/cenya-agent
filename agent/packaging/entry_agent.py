"""Punto de entrada de `cenya-agent.exe` (PyInstaller necesita un script, no un entry point)."""

from agent.__main__ import main

if __name__ == "__main__":
    main()
