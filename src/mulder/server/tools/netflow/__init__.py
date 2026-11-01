"""NetFlow (nfdump ``nfcapd.*``) tool package.

Importing this package registers the six ``run_netflow_*`` MCP tools
(``tools.py``); ``core.py`` holds the pure helpers they share.
"""

from mulder.server.tools.netflow import tools  # noqa: F401
