#!/usr/bin/env bash
#
# mulder — reverse a native install created by install.sh
#
# Driven entirely by $PREFIX/MANIFEST. Nothing outside that file is touched,
# and SIFT-owned paths are refused even if they somehow appear in it.
#
#   sudo mulder-uninstall            # or: sudo ./uninstall.sh
#   sudo ./uninstall.sh --dry-run
#   sudo ./uninstall.sh --purge      # also removes case data and the workspace

set -euo pipefail

if [[ -t 1 ]]; then
    C_RESET=$'\033[0m'; C_RED=$'\033[31m'; C_GREEN=$'\033[32m'
    C_YELLOW=$'\033[33m'; C_BLUE=$'\033[36m'; C_BOLD=$'\033[1m'
else
    C_RESET=''; C_RED=''; C_GREEN=''; C_YELLOW=''; C_BLUE=''; C_BOLD=''
fi

STEP_NUM=0
step() {
    STEP_NUM=$((STEP_NUM + 1))
    printf '\n%s==> [%d] %s%s\n' "${C_BOLD}${C_BLUE}" "$STEP_NUM" "$*" "$C_RESET"
}
ok()   { printf '    %s[ ok ]%s %s\n' "$C_GREEN" "$C_RESET" "$*"; }
info() { printf '    %s[info]%s %s\n' "$C_BLUE" "$C_RESET" "$*"; }
warn() { printf '    %s[warn]%s %s\n' "$C_YELLOW" "$C_RESET" "$*"; }
fail() { printf '\n%s[fail]%s %s\n' "$C_RED" "$C_RESET" "$*" >&2; exit 1; }

ASSUME_YES=0
DRY_RUN=0
PURGE=0
PREFIX_OPT=""

usage() {
    cat <<'USAGE'
mulder uninstaller

Usage:
  sudo ./uninstall.sh [OPTIONS]

Options:
  --prefix DIR   install prefix to remove (default: /opt/mulder)
  --dry-run      print what would be removed and exit
  --purge        also remove the investigation workspace, the case databases
                 and the Volatility symbol cache
  --yes          never prompt
  --help         this text

apt packages installed by install.sh are deliberately left in place: they are
ordinary system tools and other software may now depend on them.
USAGE
}

ORIG_ARGS=("$@")
while [[ $# -gt 0 ]]; do
    case "$1" in
        --prefix)   PREFIX_OPT="${2:-}"; shift ;;
        --prefix=*) PREFIX_OPT="${1#*=}" ;;
        --dry-run)  DRY_RUN=1 ;;
        --purge)    PURGE=1 ;;
        --yes|-y)   ASSUME_YES=1 ;;
        --help|-h)  usage; exit 0 ;;
        *)          printf 'unknown option: %s\n\n' "$1" >&2; usage >&2; exit 2 ;;
    esac
    shift
done

PREFIX="${PREFIX_OPT:-${PREFIX:-/opt/mulder}}"
[[ -d "$PREFIX" ]] || fail "no install found at $PREFIX (pass --prefix DIR)"

# --------------------------------------------------------------------------
# Self-relocation (M4). This script is installed at $PREFIX/uninstall.sh and
# has to delete that directory. Bash reads a script incrementally from the open
# fd, so removing $PREFIX mid-run can truncate the remainder and silently
# half-uninstall. Re-exec from a copy outside the prefix first.
# --------------------------------------------------------------------------
SELF=""
if [[ -n "${BASH_SOURCE[0]:-}" && -f "${BASH_SOURCE[0]}" ]]; then
    SELF="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"
fi
if [[ -n "$SELF" && "$SELF" == "$PREFIX/"* && -z "${MULDER_UNINSTALL_RELOCATED:-}" ]]; then
    RELOC_DIR="$(mktemp -d)"
    cp "$SELF" "$RELOC_DIR/uninstall.sh"
    chmod +x "$RELOC_DIR/uninstall.sh"
    export MULDER_UNINSTALL_RELOCATED=1
    exec "$RELOC_DIR/uninstall.sh" --prefix "$PREFIX" ${ORIG_ARGS[@]+"${ORIG_ARGS[@]}"}
fi

if [[ $DRY_RUN -eq 0 && "$(id -u)" -ne 0 && "$PREFIX" == /opt/* ]]; then
    fail "removing $PREFIX needs root: sudo $0 ${ORIG_ARGS[*]}"
fi

version_field() {
    [[ -f "$PREFIX/VERSION" ]] || return 1
    sed -n "s/^$1=//p" "$PREFIX/VERSION" | head -n1
}

TARGET_USER="$(version_field TARGET_USER || true)"
TARGET_HOME="$(version_field TARGET_HOME || true)"
WORKSPACE="$(version_field WORKSPACE || true)"
BINDIR="$(version_field BINDIR || true)"
MCP_REGISTERED="$(version_field MCP_REGISTERED || true)"
# Same rule as install.sh: $SUDO_USER only names the runtime user when we are
# actually elevated.
if [[ -z "$TARGET_USER" ]]; then
    if [[ "$(id -u)" -eq 0 ]]; then TARGET_USER="${SUDO_USER:-root}"; else TARGET_USER="$(id -un)"; fi
fi
# `|| true`: under `pipefail` a failing getent would abort the script.
[[ -n "$TARGET_HOME" ]] || TARGET_HOME="$(getent passwd "$TARGET_USER" | cut -d: -f6 || true)"
[[ -n "$TARGET_HOME" ]] || TARGET_HOME="${HOME:-/root}"
[[ -n "$WORKSPACE" ]]   || WORKSPACE="/mulder-investigation"
[[ -n "$BINDIR" ]]      || BINDIR="/usr/local/bin"

# --------------------------------------------------------------------------
# Read the MANIFEST fully into an array BEFORE removing anything: the file
# itself lives under $PREFIX and would disappear mid-iteration otherwise.
# --------------------------------------------------------------------------
step "Reading the manifest"
PATHS=()
if [[ -f "$PREFIX/MANIFEST" ]]; then
    while IFS= read -r line; do
        [[ -n "$line" ]] && PATHS+=("$line")
    done < "$PREFIX/MANIFEST"
    ok "$PREFIX/MANIFEST lists ${#PATHS[@]} path(s)"
else
    warn "no MANIFEST at $PREFIX; only $PREFIX itself will be removed"
fi

# Paths that belong to SIFT (or to the system) and must never be removed, even
# if a manifest edit or a future bug lists them.
PROTECTED=(
    / /bin /boot /dev /etc /home /lib /opt /proc /root /run /sbin /srv /sys
    /tmp /usr /usr/bin /usr/lib /usr/local /usr/local/bin /usr/local/lib
    /usr/sbin /usr/share /var
    /opt/volatility3 /opt/mvt /opt/pyhindsight /opt/zimmermantools
    /opt/plaso /opt/sift /usr/share/sift
)

is_protected() {
    local candidate="$1" p
    for p in "${PROTECTED[@]}"; do
        [[ "$candidate" == "$p" ]] && return 0
    done
    return 1
}

# Roots we are willing to delete anything beneath. A manifest entry that does
# not resolve under one of these is refused outright. This is the containment
# check: the PROTECTED list alone is an exact-string denylist and is trivially
# defeated by a trailing slash or a `..` segment, which would let a corrupt or
# edited MANIFEST make us `rm -rf` an arbitrary path as root.
ALLOWED_ROOTS=(
    "$PREFIX"
    "$BINDIR"
    /opt/chainsaw /opt/hayabusa /opt/zircolite /opt/sigma-rules /opt/attack
    /opt/signature-base /opt/aleapp /opt/ileapp /opt/didier-stevens /opt/litellm
    /opt/zimmermantools/mulder-extra
    /usr/local/bin
    "$WORKSPACE"
    "$TARGET_HOME/.mulder"
    "$TARGET_HOME/.cache/volatility3"
)

is_contained() {
    local candidate="$1" r
    for r in "${ALLOWED_ROOTS[@]}"; do
        [[ -n "$r" ]] || continue
        [[ "$candidate" == "$r" || "$candidate" == "$r"/* ]] && return 0
    done
    return 1
}

remove_path() {
    local raw="$1" target

    # Reject anything that is not an absolute path before it can be resolved
    # relative to $PWD.
    if [[ "$raw" != /* ]]; then
        warn "refusing to remove '$raw' (not an absolute path)"
        return 0
    fi

    # Canonicalise: collapses `..`, strips a trailing slash, and does not
    # require the path to exist. --no-symlinks keeps us from following a
    # symlink out of an allowed root.
    target="$(realpath -m --no-symlinks -- "$raw" 2>/dev/null || true)"
    if [[ -z "$target" || "$target" != /* ]]; then
        warn "refusing to remove '$raw' (could not be resolved)"
        return 0
    fi

    # Re-check protection AFTER canonicalisation, so `/opt/zimmermantools/` and
    # `/opt/mulder/../../etc` are both caught.
    if is_protected "$target"; then
        warn "refusing to remove $target (system or SIFT-owned)"
        return 0
    fi
    if ! is_contained "$target"; then
        warn "refusing to remove $target (outside every mulder-owned root)"
        return 0
    fi

    if [[ ! -e "$target" && ! -L "$target" ]]; then
        return 0
    fi
    if [[ $DRY_RUN -eq 1 ]]; then
        printf '    would remove  %s\n' "$target"
    else
        # Never let one busy or immutable path abort the run under `set -e` and
        # leave a half-removed install behind.
        if rm -rf -- "$target"; then
            ok "removed $target"
        else
            warn "could not fully remove $target; remove it by hand"
        fi
    fi
}

step "Plan"
printf '    prefix      %s\n' "$PREFIX"
printf '    bindir      %s\n' "$BINDIR"
printf '    workspace   %s (%s)\n' "$WORKSPACE" "$([[ $PURGE -eq 1 ]] && echo "will be removed" || echo "kept; pass --purge")"
printf '    case data   %s/.mulder (%s)\n' "$TARGET_HOME" "$([[ $PURGE -eq 1 ]] && echo "will be removed" || echo "kept; pass --purge")"
printf '    apt pkgs    left installed\n'

if [[ $DRY_RUN -eq 0 && $ASSUME_YES -eq 0 && -t 0 ]]; then
    read -r -p "    Proceed? [y/N] " reply
    [[ "$reply" =~ ^[Yy] ]] || fail "aborted"
fi

# --------------------------------------------------------------------------
step "Deregistering the MCP server"
if [[ "${MCP_REGISTERED:-0}" == "1" ]]; then
    CLAUDE_BIN="$(command -v claude || true)"
    [[ -z "$CLAUDE_BIN" && -x "$TARGET_HOME/.local/bin/claude" ]] && CLAUDE_BIN="$TARGET_HOME/.local/bin/claude"
    if [[ -n "$CLAUDE_BIN" && $DRY_RUN -eq 0 ]]; then
        if [[ "$(id -un)" == "$TARGET_USER" ]]; then
            "$CLAUDE_BIN" mcp remove mulder --scope user >/dev/null 2>&1 || true
        else
            sudo -u "$TARGET_USER" -H "$CLAUDE_BIN" mcp remove mulder --scope user >/dev/null 2>&1 || true
        fi
        ok "removed the mulder MCP registration"
    else
        info "claude CLI not found; nothing to deregister"
    fi
else
    info "mulder was never registered with the claude CLI"
fi

# --------------------------------------------------------------------------
step "Removing installed paths"
# $PREFIX goes last: it holds the MANIFEST and (before relocation) this script.
for target in ${PATHS[@]+"${PATHS[@]}"}; do
    [[ "$target" == "$PREFIX" ]] && continue
    remove_path "$target"
done

# Dangling symlinks the manifest may predate.
for link in "$BINDIR/mulder" "$BINDIR/mulder-uninstall" /usr/local/bin/chainsaw; do
    if [[ -L "$link" && ! -e "$link" ]]; then
        remove_path "$link"
    fi
done

# --------------------------------------------------------------------------
step "User data"
if [[ $PURGE -eq 1 ]]; then
    remove_path "$WORKSPACE"
    remove_path "$TARGET_HOME/.mulder"
    remove_path "$TARGET_HOME/.cache/volatility3/symbols/windows.zip"
    remove_path "$TARGET_HOME/.cache/volatility3/symbols/linux.zip"
else
    info "keeping $WORKSPACE"
    info "keeping $TARGET_HOME/.mulder (case databases, audit logs, reports)"
    info "keeping the Volatility symbol cache under $TARGET_HOME/.cache/volatility3"
    info "pass --purge to remove all three"
fi

# --------------------------------------------------------------------------
step "Removing $PREFIX"
remove_path "$PREFIX"

if [[ $DRY_RUN -eq 1 ]]; then
    printf '\n%sDry run: nothing was removed.%s\n' "$C_YELLOW" "$C_RESET"
else
    printf '\n%smulder has been uninstalled.%s\n' "$C_GREEN" "$C_RESET"
    printf 'apt packages were left installed; remove them yourself if you want them gone.\n'
fi
