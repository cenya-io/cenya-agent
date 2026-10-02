"""Punto de entrada de `cenya-agent-askpass.exe`: el programa que OpenSSH ejecuta (SSH_ASKPASS) cuando pide una contraseña."""

import sys

from agent.askpass import main

if __name__ == "__main__":
    sys.exit(main())
