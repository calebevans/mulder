"""Targeted registry value query tool using python-registry.

Provides direct access to specific Windows registry key/value pairs
from hive files extracted via TSK, with automatic decoding of
FILETIME timestamps, REG_BINARY, and REG_MULTI_SZ values.
"""

from __future__ import annotations

import logging
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Literal

from Registry import Registry

from mulder.server.app import get_ctx, mcp
from mulder.server.extract_helpers import extract_and_index
from mulder.server.helpers import (
    error_response,
    make_tool_call_id,
    tool_response,
)
from mulder.server.tool_access import Role, tool_access
from mulder.server.tools.extract.tsk import _cleanup_tsk_extract_dir, _tsk_extract_files

__all__ = ["query_registry_value"]

logger = logging.getLogger(__name__)

_FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)

_HIVE_PATHS: dict[str, list[str]] = {
    "system": ["config/SYSTEM"],
    "software": ["config/SOFTWARE"],
    "sam": ["config/SAM"],
    "security": ["config/SECURITY"],
    "ntuser": [
        "Documents and Settings/{username}/NTUSER.DAT",
        "Users/{username}/NTUSER.DAT",
    ],
    "usrclass": [
        "Documents and Settings/{username}/Local Settings/Application Data/"
        "Microsoft/Windows/UsrClass.dat",
        "Users/{username}/AppData/Local/Microsoft/Windows/UsrClass.dat",
    ],
}

_REGISTRY_VALUE_TYPE_NAMES: dict[int, str] = {
    Registry.RegSZ: "REG_SZ",
    Registry.RegExpandSZ: "REG_EXPAND_SZ",
    Registry.RegBin: "REG_BINARY",
    Registry.RegDWord: "REG_DWORD",
    Registry.RegMultiSZ: "REG_MULTI_SZ",
    Registry.RegQWord: "REG_QWORD",
    Registry.RegNone: "REG_NONE",
}


def _try_decode_filetime(raw: bytes) -> str | None:
    """Attempt to decode an 8-byte value as a Windows FILETIME.

    FILETIME is a 64-bit value representing 100-nanosecond intervals
    since January 1, 1601 UTC. Returns an ISO timestamp if the decoded
    value falls within a plausible range, otherwise None.

    Args:
        raw: 8 bytes of raw binary data.

    Returns:
        ISO 8601 timestamp string or None if not a valid FILETIME.
    """
    ticks = int.from_bytes(raw, "little")
    if ticks == 0:
        return None
    try:
        dt = _FILETIME_EPOCH + timedelta(microseconds=ticks // 10)
        if (
            datetime(1980, 1, 1, tzinfo=timezone.utc)
            < dt
            < datetime(2100, 1, 1, tzinfo=timezone.utc)
        ):
            return dt.isoformat()
    except (OverflowError, OSError):
        pass
    return None


def _decode_registry_value(
    value: Registry.RegistryValue,
) -> dict[str, Any]:
    """Decode a registry value into a typed Python representation.

    Handles REG_SZ, REG_EXPAND_SZ, REG_DWORD, REG_QWORD, REG_BINARY,
    REG_MULTI_SZ, and REG_NONE types. Binary values that match known
    FILETIME patterns are automatically converted to ISO timestamps.

    Args:
        value: A python-registry RegistryValue object.

    Returns:
        Dict with keys: name, type, data, decoded (optional).
    """
    vtype = value.value_type()
    raw = value.value()
    result: dict[str, Any] = {
        "name": value.name(),
        "type": _REGISTRY_VALUE_TYPE_NAMES.get(vtype, f"UNKNOWN({vtype})"),
    }

    if (
        vtype in (Registry.RegSZ, Registry.RegExpandSZ)
        or vtype == Registry.RegDWord
        or vtype == Registry.RegQWord
        or vtype == Registry.RegMultiSZ
    ):
        result["data"] = raw
    elif vtype == Registry.RegBin:
        result["data"] = raw.hex()
        if len(raw) == 8:
            decoded = _try_decode_filetime(raw)
            if decoded:
                result["decoded"] = decoded
    elif vtype == Registry.RegNone:
        result["data"] = raw.hex() if isinstance(raw, bytes) else raw
    else:
        result["data"] = str(raw)

    return result


def _extract_hive(
    image_path: str,
    hive: str,
    username: str | None,
) -> tuple[Path | None, str | None]:
    """Locate and extract a hive file from a disk image via TSK.

    Args:
        image_path: Path to the disk image.
        hive: Hive identifier (system, software, sam, security, ntuser, usrclass).
        username: Username for per-user hives (ntuser, usrclass).

    Returns:
        Tuple of (extracted hive path, temp directory for cleanup) or
        (None, None) if the hive could not be located.
    """
    patterns = _HIVE_PATHS[hive]
    if username:
        patterns = [p.format(username=username) for p in patterns]

    extracted = _tsk_extract_files(image_path, patterns)
    if not extracted:
        return None, None

    _rel, fpath = extracted[0]
    return fpath, str(fpath.parent)


@mcp.tool()
@tool_access(Role.EXTRACT_ANALYST)
def query_registry_value(
    case_id: str,
    image_path: str,
    hive: Literal["system", "software", "sam", "security", "ntuser", "usrclass"],
    key_path: str,
    value_name: str | None = None,
    username: str | None = None,
) -> dict[str, Any]:
    """Query a specific registry key or value from a Windows hive file.

    Extracts the target hive from a disk image using TSK and reads the
    requested key or value using python-registry. Returns decoded,
    typed values including automatic conversion of FILETIME timestamps,
    Unix epochs, REG_BINARY, and REG_MULTI_SZ data.

    When value_name is omitted, returns all values under the key plus
    a list of subkeys.

    Common forensic registry paths:

    SYSTEM hive:
        ControlSet001\\Control\\TimeZoneInformation - system timezone
        ControlSet001\\Control\\Windows - ShutdownTime (FILETIME)
        ControlSet001\\Enum\\USBSTOR - USB device history
        ControlSet001\\Services\\Tcpip\\Parameters\\Interfaces - network config

    SOFTWARE hive:
        Microsoft\\Windows NT\\CurrentVersion - InstallDate, ProductName,
            RegisteredOwner, RegisteredOrganization
        Microsoft\\Windows\\CurrentVersion\\Uninstall - installed programs

    NTUSER.DAT hive (requires username):
        Software\\Microsoft\\Internet Explorer\\TypedURLs - typed URLs
        Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs - MRU
        Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist - execution counts
        Control Panel\\Desktop - wallpaper, screensaver settings

    Args:
        case_id: Active case identifier.
        image_path: Path to the disk image containing the registry hive.
        hive: Target hive name.
        key_path: Registry key path relative to the hive root
            (e.g., "ControlSet001\\Control\\TimeZoneInformation").
        value_name: Specific value to retrieve. If omitted, returns
            all values and subkeys under the key.
        username: Required when hive is "ntuser" or "usrclass" to
            locate the per-user hive file.

    Returns:
        Dict containing decoded value(s), value type, key metadata,
        and last-written timestamp for the key.
    """
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    params: dict[str, Any] = {
        "case_id": case_id,
        "image_path": image_path,
        "hive": hive,
        "key_path": key_path,
        "value_name": value_name,
        "username": username,
    }

    if hive in ("ntuser", "usrclass") and not username:
        return error_response(
            tc_id,
            "query_registry_value",
            params,
            f"username is required when querying the '{hive}' hive",
            error_type="missing_parameter",
        )

    ctx = get_ctx()
    _ = ctx.case_id  # Validate case is loaded

    extract_dir: str | None = None
    try:
        hive_path, extract_dir = _extract_hive(image_path, hive, username)
        if hive_path is None:
            return error_response(
                tc_id,
                "query_registry_value",
                params,
                f"Could not locate {hive} hive in image {image_path}. "
                f"Ensure run_fls has been executed on this image.",
                error_type="hive_not_found",
            )

        reg = Registry.Registry(str(hive_path))

        try:
            key = reg.open(key_path)
        except Registry.RegistryKeyNotFoundException:
            return error_response(
                tc_id,
                "query_registry_value",
                params,
                f"Key not found: {key_path}",
                error_type="key_not_found",
                suggestion=(
                    "Verify the key path is relative to the hive root. "
                    "For SYSTEM hive, paths start with ControlSet001\\..."
                ),
            )

        last_written = key.timestamp().isoformat() if key.timestamp() else None

        if value_name is not None:
            try:
                val = key.value(value_name)
            except Registry.RegistryValueNotFoundException:
                available = [v.name() for v in key.values()]
                return error_response(
                    tc_id,
                    "query_registry_value",
                    params,
                    f"Value '{value_name}' not found under key '{key_path}'. "
                    f"Available values: {available}",
                    error_type="value_not_found",
                )

            decoded = _decode_registry_value(val)
            results: dict[str, Any] = {
                "key_path": key_path,
                "last_written": last_written,
                "value": decoded,
            }
        else:
            values = [_decode_registry_value(v) for v in key.values()]
            subkeys = [sk.name() for sk in key.subkeys()]
            results = {
                "key_path": key_path,
                "last_written": last_written,
                "values": values,
                "subkeys": subkeys,
            }

        source = f"registry.query.{hive}"
        if username:
            source = f"registry.query.{hive}.{username}"

        results_text = f"Registry query: {hive}\\{key_path}"
        if value_name:
            val_data = results.get("value", {}).get("data", "")
            results_text += f"\\{value_name} = {val_data}"
        else:
            results_text += f" ({len(results.get('values', []))} values, "
            results_text += f"{len(results.get('subkeys', []))} subkeys)"

        extract_and_index(results_text, source, image_path, "python-registry")

        elapsed = (time.monotonic() - t0) * 1000
        return tool_response(
            tc_id,
            "query_registry_value",
            params,
            results,
            source=None,
            elapsed_ms=elapsed,
        )
    finally:
        if extract_dir:
            _cleanup_tsk_extract_dir(extract_dir)
