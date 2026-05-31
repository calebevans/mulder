"""Canonical source name constants for MCP tool modules.

All source names used across the Mulder tool layer are defined here
to avoid drift between modules that reference the same underlying data.
Import from this module rather than defining local constants.
"""

# Volatility sources
SRC_PSLIST = "volatility.pslist"
SRC_PSTREE = "volatility.pstree"
SRC_PSSCAN = "volatility.psscan"
SRC_ENVARS = "volatility.envars"
SRC_PRIVS = "volatility.privs"
SRC_MODULES = "volatility.modules"
SRC_MODSCAN = "volatility.modscan"
SRC_USERASSIST = "volatility.userassist"
SRC_FILESCAN = "volatility.filescan"
SRC_NETSCAN = "volatility.netscan"
SRC_CMDLINE = "volatility.cmdline"
SRC_DLLLIST = "volatility.dlllist"

# TSK sources
SRC_TSK_PARTITIONS = "tsk.partitions"
SRC_TSK_FILELIST = "tsk.filelist"
SRC_TSK_TIMELINE = "tsk.timeline"
SRC_TSK_FSSTAT = "tsk.fsstat"
SRC_TSK_ICAT = "tsk.icat"
SRC_TSK_ISTAT = "tsk.istat"

# Plaso sources
SRC_PLASO_TIMELINE = "plaso.timeline"

# EVTX sources
SRC_EVTX_SECURITY = "evtx.security"
SRC_EVTX_SYSTEM = "evtx.system"

# EZ Tools sources
SRC_EZ_SHIMCACHE = "ez.shimcache"
SRC_EZ_AMCACHE = "ez.amcache"
SRC_EZ_PREFETCH = "ez.prefetch"
SRC_EZ_EVTX_SECURITY = "ez.evtx.security"
SRC_EZ_SRUM = "ez.srum"
SRC_EZ_USNJRNL = "ez.usnjrnl"
SRC_EZ_MFT = "ez.mft"
SRC_EZ_JUMPLISTS = "ez.jumplists"
SRC_EZ_LNKFILES = "ez.lnkfiles"

# Bulk extractor sources
SRC_BULK_URL = "bulk.url"
SRC_BULK_EMAIL = "bulk.email"
SRC_BULK_DOMAIN = "bulk.domain"

# PCAP sources
SRC_PCAP_CONVERSATIONS = "pcap.conversations"
SRC_PCAP_DNS = "pcap.dns"
SRC_PCAP_HTTP = "pcap.http"
