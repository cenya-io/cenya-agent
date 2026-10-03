"""Cenya Agent, the desktop application: the agent's face on the machine.

A window (``agent.app.main``) that talks to the service only through the local
channel of spec section 4 (``agent.localclient``, the one client every local
program uses): a named pipe on Windows, a
Unix socket elsewhere -- never a network port. It opens no socket of any kind
itself: the page is handed to WebView2 as a string and speaks to Python
through pywebview's JS bridge, not over HTTP.

Layout:

* ``view``        every decision about what to show, as pure functions with tests.
* ``strings``     every text the page shows, marked for translation.
* ``bridge``      the object the page calls (``window.pywebview.api``).
* ``winsys``      the few things that are Windows' and not the service's: elevation,
                  the service control manager, the sign-in entry of the tray icon.
* ``fake_server`` a scripted service for development, reviews and tests.
* ``main``        the entry point (``cenya-agent-app``).

Importing this package imports nothing heavy: pywebview is only loaded by
``main``, so the tray icon and the tests can use ``view`` on a
machine without it.
"""
