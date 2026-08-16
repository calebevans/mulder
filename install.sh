#!/usr/bin/env bash
#
# mulder — native installer for the SANS SIFT Workstation
#
# Installs mulder into an isolated virtualenv at /opt/mulder and fills in the
# forensic tools SIFT does not already ship, reproducing the layout of the
# container image (ghcr.io/calebevans/mulder) exactly. Every absolute path and
# version pin below is taken from the Dockerfile; mulder's Python source
# hardcodes these paths, so nothing under src/ has to change.
#
#   git clone https://github.com/calebevans/mulder.git
#   cd mulder && sudo ./install.sh
#
#   curl -fsSL https://raw.githubusercontent.com/calebevans/mulder/main/install.sh | sudo bash
#
# See docs/sift-install.md for the tier matrix and troubleshooting.

set -euo pipefail

# NOTE: deliberately no `IFS=$'\n\t'`. The apt step computes a missing-package
# set and that IFS silently breaks space word-splitting. Arrays are used
# throughout instead.

# --------------------------------------------------------------------------
# Version pins — every one of these matches the Dockerfile line noted beside it
# --------------------------------------------------------------------------
readonly CHAINSAW_VERSION="2.16.0"   # Dockerfile:267
readonly HAYABUSA_VERSION="3.8.1"    # Dockerfile:126
readonly ZIRCOLITE_VERSION="2.20.0"  # Dockerfile:488
readonly SIGMA_VERSION="r2024-09-02" # Dockerfile:285
readonly CAPA_VERSION="9.4.0"        # Dockerfile:209
readonly FLOSS_VERSION="3.1.0"       # Dockerfile:230
readonly DIE_VERSION="3.09"          # Dockerfile:250

# SHA-256 digests. Only immutable GitHub *release assets* are pinned: those are
# write-once blobs. Deliberately NOT pinned, because there is no stable digest
# to pin and a hardcoded one would break the installer on the next upstream
# push (see docs/sift-install.md#supply-chain):
#   - the SigmaHQ tag tarball (a GitHub auto-generated source archive; GitHub
#     has changed its gzip settings before, which changes the digest without
#     the content changing)
#   - the EZ Tools zips (download.ericzimmermanstools.com rebuilds them)
#   - MITRE ATT&CK master, the Volatility symbol packs, and every git clone.
# Git sources are pinned by tag instead and their resolved commit is printed.
readonly SHA256_CHAINSAW_AMD64="5d46cd140838413aeb5711451a282b3922443d9ec6afaea3e6b6b220454fd807"
readonly SHA256_CHAINSAW_ARM64="e7aa1c9ef6a7ca34f285ed46faf95ba1f499612ef2d044fbd8ee4852f42dc4f9"
readonly SHA256_HAYABUSA_AMD64="93c7fc5820151d1b8308987a47f0231a7f286d726478bea226adf2bc6d05bcee"
readonly SHA256_CAPA_AMD64="07800a1d20a21eb18fc98716e2ae81b668e0c9a04defd588c8aa17ea3d3281e4"
readonly SHA256_CAPA_ARM64="165df126f05e86736afee0f4c28b19c6037315a99afc3a92a426432cdd30d2c5"
readonly SHA256_FLOSS_AMD64="8cdd05d78e3ffa59360425c6b846a2f22933fd1923bdd326fceff82f7549d40a"
readonly SHA256_DIE_AMD64="4cb162f95222ded211f1ae24f3cf84c56021a67862ae405d6bbd7f1ae291387f"

readonly REPO_URL="https://github.com/calebevans/mulder.git"

# --------------------------------------------------------------------------
# Output helpers
# --------------------------------------------------------------------------
if [[ -t 1 ]]; then
    C_RESET=$'\033[0m'; C_RED=$'\033[31m'; C_GREEN=$'\033[32m'
    C_YELLOW=$'\033[33m'; C_BLUE=$'\033[36m'; C_BOLD=$'\033[1m'
else
    C_RESET=''; C_RED=''; C_GREEN=''; C_YELLOW=''; C_BLUE=''; C_BOLD=''
fi

STEP_NUM=0
WARN_COUNT=0

step() {
    STEP_NUM=$((STEP_NUM + 1))
    printf '\n%s==> [%d] %s%s\n' "${C_BOLD}${C_BLUE}" "$STEP_NUM" "$*" "$C_RESET"
}
ok()   { printf '    %s[ ok ]%s %s\n' "$C_GREEN" "$C_RESET" "$*"; }
info() { printf '    %s[info]%s %s\n' "$C_BLUE" "$C_RESET" "$*"; }
warn() { WARN_COUNT=$((WARN_COUNT + 1)); printf '    %s[warn]%s %s\n' "$C_YELLOW" "$C_RESET" "$*"; }
fail() { printf '\n%s[fail]%s %s\n' "$C_RED" "$C_RESET" "$*" >&2; exit 1; }

# --------------------------------------------------------------------------
# Options
# --------------------------------------------------------------------------
TIER="default"
USER_MODE=0
FORCE=0
ASSUME_YES=0
REGISTER_MCP=0
DO_VOL_SYMBOLS=1
DO_SIGNATURE_BASE=1
DO_MOBILE=1
DO_LITELLM=1
VERIFY_ONLY=0
VERIFY_STRICT=0
REF="main"   # the advertised one-liner fetches install.sh from main, and main
             # is routinely ahead of the last tag: defaulting to v$VERSION would
             # make the clone fail outright.
PREFIX_OPT=""

usage() {
    cat <<'USAGE'
mulder installer for the SANS SIFT Workstation

Usage:
  sudo ./install.sh [OPTIONS]
  curl -fsSL https://raw.githubusercontent.com/calebevans/mulder/main/install.sh | sudo bash

Tiers:
  --minimal            venv + wrapper + apt gaps + workspace. Reuses everything
                       SIFT already provides. No gap forensic tools.
  (default)            minimal + chainsaw, hayabusa, zircolite, Sigma rules,
                       MITRE ATT&CK, PECmd, CAPA.
  --full               default + signature-base, Volatility symbols,
                       ALEAPP/iLEAPP, DidierStevensSuite, FLOSS, Detect-It-Easy,
                       LiteLLM, libguestfs-tools, the [pdf] and [stix] extras.

Options:
  --prefix DIR         install prefix (default: /opt/mulder)
  --user               sudo-free install under $HOME/.local. /opt assets are
                       skipped: mulder's hardcoded paths cannot be relocated,
                       so this is a partial install. Requires --cwd on every
                       `mulder investigate` run.
  --force              reinstall components even when already present
  --ref REF            git ref to clone when piped to bash (default: main)
  --register-mcp       register mulder with the local Claude Code CLI
  --no-vol-symbols     skip the Volatility 3 symbol packs (--full)
  --no-signature-base  skip the YARA signature-base clone (--full)
  --no-mobile          skip ALEAPP/iLEAPP and pysqlcipher3
  --no-litellm         skip the isolated LiteLLM venv (--full)
  --verify             probe an existing install and exit
  --strict             with --verify, also fail on missing SIFT-provided tools
  --yes                never prompt
  --help               this text

Environment:
  PREFIX, BINDIR       override the install prefix / bin directory

Exit status of --verify depends on REQUIRED probes only; SIFT-provided (REUSED)
and OPTIONAL probes are reported but never fatal unless --strict is given.
USAGE
}

ORIG_ARGS=("$@")
while [[ $# -gt 0 ]]; do
    case "$1" in
        --minimal)           TIER="minimal" ;;
        --full)              TIER="full" ;;
        --prefix)            PREFIX_OPT="${2:-}"; shift ;;
        --prefix=*)          PREFIX_OPT="${1#*=}" ;;
        --user)              USER_MODE=1 ;;
        --force)             FORCE=1 ;;
        --ref)               REF="${2:-}"; shift ;;
        --ref=*)             REF="${1#*=}" ;;
        --register-mcp)      REGISTER_MCP=1 ;;
        --no-vol-symbols)    DO_VOL_SYMBOLS=0 ;;
        --no-signature-base) DO_SIGNATURE_BASE=0 ;;
        --no-mobile)         DO_MOBILE=0 ;;
        --no-litellm)        DO_LITELLM=0 ;;
        --verify)            VERIFY_ONLY=1 ;;
        --strict)            VERIFY_STRICT=1 ;;
        --yes|-y)            ASSUME_YES=1 ;;
        --help|-h)           usage; exit 0 ;;
        *)                   printf 'unknown option: %s\n\n' "$1" >&2; usage >&2; exit 2 ;;
    esac
    shift
done

# --------------------------------------------------------------------------
# Identity — resolved once. The installer runs under sudo, so $HOME is /root
# and every user-owned artifact must use the *invoking* user instead.
# --------------------------------------------------------------------------
# $SUDO_USER names whoever *invoked* sudo, which is only the runtime user when
# we are actually elevated. `sudo -u someone ./install.sh --user` also sets it,
# and would otherwise hand us the wrong home directory.
if [[ "$(id -u)" -eq 0 ]]; then
    TARGET_USER="${SUDO_USER:-root}"
else
    TARGET_USER="$(id -un)"
fi
# `|| true` is required: under `pipefail` a failing getent fails the whole
# substitution and aborts before the fallback below can run.
TARGET_HOME="$(getent passwd "$TARGET_USER" | cut -d: -f6 || true)"
[[ -n "$TARGET_HOME" ]] || TARGET_HOME="${HOME:-/root}"
TARGET_GROUP="$(id -gn "$TARGET_USER" 2>/dev/null || echo "$TARGET_USER")"

if [[ $USER_MODE -eq 1 ]]; then
    PREFIX="${PREFIX_OPT:-${PREFIX:-$TARGET_HOME/.local/share/mulder}}"
    BINDIR="${BINDIR:-$TARGET_HOME/.local/bin}"
    WORKSPACE="$TARGET_HOME/mulder-investigation"
else
    PREFIX="${PREFIX_OPT:-${PREFIX:-/opt/mulder}}"
    BINDIR="${BINDIR:-/usr/local/bin}"
    # cli.py:247 defaults --cwd to /mulder-investigation and cli.py:298-302
    # raises if .mcp.json is absent there. Using the literal path costs no
    # source change.
    WORKSPACE="/mulder-investigation"
fi

# Absolutise before anything is recorded in MANIFEST. A relative --prefix would
# otherwise produce a wrapper containing `. relprefix/mulder/env.sh` (broken
# from any other cwd) and a manifest of relative paths that uninstall.sh would
# resolve against *its* cwd.
absolutise() {
    local p="$1"
    [[ "$p" == /* ]] || p="$PWD/$p"
    realpath -m --no-symlinks -- "$p" 2>/dev/null || printf '%s' "$p"
}
PREFIX="$(absolutise "$PREFIX")"
BINDIR="$(absolutise "$BINDIR")"
WORKSPACE="$(absolutise "$WORKSPACE")"

VENV="$PREFIX/venv"
ENV_FILE="$PREFIX/env.sh"

# --------------------------------------------------------------------------
# Small utilities
# --------------------------------------------------------------------------
CLEANUP_DIRS=()
cleanup() {
    local d
    for d in ${CLEANUP_DIRS[@]+"${CLEANUP_DIRS[@]}"}; do
        [[ -n "$d" && -d "$d" ]] && rm -rf "$d"
    done
    return 0
}
trap cleanup EXIT

MANIFEST_PATHS=()
record() { MANIFEST_PATHS+=("$@"); }

# Every network fetch goes through here and every caller wraps it in an `if`,
# so a failed download can never abort the run under `set -e`.
fetch() {
    curl -fsSL --proto '=https' --tlsv1.2 --retry 3 --retry-delay 2 \
        --connect-timeout 20 -o "$2" "$1"
}

verify_sha256() {
    local file="$1" expected="$2" label="$3" actual
    if [[ -z "$expected" ]]; then
        info "$label: unpinned upstream, fetched over TLS only"
        return 0
    fi
    actual="$(sha256sum "$file" | awk '{print $1}')"
    if [[ "$actual" != "$expected" ]]; then
        warn "$label: SHA-256 mismatch (expected $expected, got $actual)"
        return 1
    fi
    return 0
}

as_target() {
    if [[ "$(id -un)" == "$TARGET_USER" ]]; then
        "$@"
    else
        sudo -u "$TARGET_USER" -H "$@"
    fi
}

own_by_target() { chown -R "$TARGET_USER:$TARGET_GROUP" "$@" 2>/dev/null || true; }

confirm() {
    [[ $ASSUME_YES -eq 1 ]] && return 0
    [[ -t 0 ]] || return 0   # non-interactive: never block
    local reply
    read -r -p "    $1 [Y/n] " reply
    [[ -z "$reply" || "$reply" =~ ^[Yy] ]]
}

arch_deb() {
    if command -v dpkg >/dev/null 2>&1; then
        dpkg --print-architecture
    else
        case "$(uname -m)" in
            x86_64)  echo amd64 ;;
            aarch64) echo arm64 ;;
            *)       uname -m ;;
        esac
    fi
}
ARCH="$(arch_deb)"

# --------------------------------------------------------------------------
# --verify
# --------------------------------------------------------------------------
REQ_FAIL=0
REUSED_FAIL=0

probe() {
    # probe CLASS LABEL COMMAND...
    local class="$1" label="$2"
    shift 2
    if "$@" >/dev/null 2>&1; then
        printf '    %s[ ok ]%s %-9s %s\n' "$C_GREEN" "$C_RESET" "$class" "$label"
        return 0
    fi
    case "$class" in
        REQUIRED) REQ_FAIL=$((REQ_FAIL + 1));    printf '    %s[fail]%s %-9s %s\n' "$C_RED" "$C_RESET" "$class" "$label" ;;
        REUSED)   REUSED_FAIL=$((REUSED_FAIL + 1)); printf '    %s[miss]%s %-9s %s\n' "$C_YELLOW" "$C_RESET" "$class" "$label" ;;
        *)        printf '    %s[miss]%s %-9s %s\n' "$C_YELLOW" "$C_RESET" "$class" "$label" ;;
    esac
    return 0
}

EZ_DIR="/opt/zimmermantools"
EZ_DLLS=(AmcacheParser.dll AppCompatCacheParser.dll EvtxECmd.dll MFTECmd.dll PECmd.dll RECmd.dll)

ez_find() {
    # extract/misc.py:90-93 does Path("/opt/zimmermantools").rglob(dll) and
    # takes candidates[0]; rglob order is os.scandir order, i.e. unsorted, so
    # printing the resolved path is the only way to see a duplicate.
    local dll="$1" hit
    [[ -d "$EZ_DIR" ]] || return 1
    hit="$(find "$EZ_DIR" -type f -name "$dll" -print -quit 2>/dev/null || true)"
    [[ -n "$hit" ]] || return 1
    printf '%s\n' "$hit"
}

version_field() {
    [[ -f "$PREFIX/VERSION" ]] || return 1
    sed -n "s/^$1=//p" "$PREFIX/VERSION" | head -n1
}

do_verify() {
    printf '%smulder installation check%s  (prefix: %s)\n' "$C_BOLD" "$C_RESET" "$PREFIX"

    [[ -f "$ENV_FILE" ]] || fail "no $ENV_FILE — mulder is not installed at $PREFIX"
    # D7: sourcing the generated env.sh is what makes these probes see exactly
    # what the wrapper gives mulder at runtime. One definition, two consumers.
    # shellcheck disable=SC1090
    . "$ENV_FILE"

    local ws
    ws="$(version_field WORKSPACE || true)"
    [[ -n "$ws" ]] || ws="$WORKSPACE"

    printf '\n  %sREQUIRED%s — mulder itself\n' "$C_BOLD" "$C_RESET"
    probe REQUIRED "mulder wrapper ($BINDIR/mulder)"  test -x "$BINDIR/mulder"
    probe REQUIRED "venv mulder"                      test -x "$VENV/bin/mulder"
    probe REQUIRED "venv python3"                     test -x "$VENV/bin/python3"
    probe REQUIRED "import mulder"                    "$VENV/bin/python3" -c 'import mulder'
    probe REQUIRED "import volatility3"               "$VENV/bin/python3" -c 'import volatility3'
    probe REQUIRED "import Registry"                  "$VENV/bin/python3" -c 'from Registry import Registry'
    probe REQUIRED "import Evtx"                      "$VENV/bin/python3" -c 'import Evtx'
    probe REQUIRED "workspace $ws/.mcp.json"          test -f "$ws/.mcp.json"
    if [[ -d /opt/chainsaw ]]; then
        # B1: probe the symlink itself, never `command -v chainsaw`.
        # chainsaw.py:33 hardcodes /usr/local/bin/chainsaw and execs it
        # directly, so PATH containing /opt/chainsaw makes the availability
        # gate pass while every exec fails with ENOENT — swallowed by the
        # `except OSError` at chainsaw.py:530.
        probe REQUIRED "/usr/local/bin/chainsaw symlink" test -x /usr/local/bin/chainsaw
    fi

    printf '\n  %sREUSED%s — provided by SIFT (reported, not fatal)\n' "$C_BOLD" "$C_RESET"
    probe REUSED "log2timeline.py"  command -v log2timeline.py
    # plaso.py:33 sets _PSORT_BIN = "psort.py" and gates on a bare
    # shutil.which with no module fallback: the literal name must be on PATH.
    probe REUSED "psort.py"         command -v psort.py
    probe REUSED "fls"              command -v fls
    probe REUSED "icat"             command -v icat
    probe REUSED "mactime"          command -v mactime
    probe REUSED "hindsight.py"     command -v hindsight.py
    probe REUSED "mvt-android"      command -v mvt-android
    probe REUSED "mvt-ios"          command -v mvt-ios
    probe REUSED "rip.pl"           command -v rip.pl
    probe REUSED "dotnet"           command -v dotnet
    # SIFT ships python3-yara (the module) but not the yara binary, and
    # tools/yara.py shells out to the binary.
    probe REUSED "yara"             command -v yara
    probe REUSED "clamscan"         command -v clamscan
    probe REUSED "strings"          command -v strings
    probe REUSED "ewfmount"         command -v ewfmount
    probe REUSED "capinfos"         command -v capinfos

    printf '\n  %sEZ Tools%s — resolved rglob path for the six DLLs mulder invokes\n' "$C_BOLD" "$C_RESET"
    local dll hit
    for dll in "${EZ_DLLS[@]}"; do
        if hit="$(ez_find "$dll")"; then
            printf '    %s[ ok ]%s %-9s %-26s %s\n' "$C_GREEN" "$C_RESET" "REUSED" "$dll" "$hit"
        else
            REUSED_FAIL=$((REUSED_FAIL + 1))
            printf '    %s[miss]%s %-9s %-26s %s\n' "$C_YELLOW" "$C_RESET" "REUSED" "$dll" "not found under $EZ_DIR"
        fi
    done

    printf '\n  %sOPTIONAL%s\n' "$C_BOLD" "$C_RESET"
    probe OPTIONAL "hayabusa"         test -x /opt/hayabusa/hayabusa
    probe OPTIONAL "zircolite"        test -f /opt/zircolite/zircolite.py
    probe OPTIONAL "sigma rules"      test -d /opt/sigma-rules/rules/windows
    probe OPTIONAL "MITRE ATT&CK"     test -f /opt/attack/enterprise-attack.json
    probe OPTIONAL "signature-base"   test -d /opt/signature-base
    probe OPTIONAL "capa"             command -v capa
    probe OPTIONAL "floss"            command -v floss
    probe OPTIONAL "diec"             command -v diec
    probe OPTIONAL "litellm"          command -v litellm
    probe OPTIONAL "ALEAPP"           test -f /opt/aleapp/aleapp.py
    probe OPTIONAL "iLEAPP"           test -f /opt/ileapp/ileapp.py
    probe OPTIONAL "pdfid.py"         test -f /opt/didier-stevens/pdfid.py
    probe OPTIONAL "zeek"             command -v zeek
    probe OPTIONAL "suricata"         command -v suricata
    probe OPTIONAL "vol symbols"      test -f "$TARGET_HOME/.cache/volatility3/symbols/windows.zip"

    printf '\n'
    if [[ $REQ_FAIL -gt 0 ]]; then
        printf '%s%d REQUIRED probe(s) failed.%s See docs/sift-install.md#troubleshooting.\n' \
            "$C_RED" "$REQ_FAIL" "$C_RESET"
        return 1
    fi
    if [[ $VERIFY_STRICT -eq 1 && $REUSED_FAIL -gt 0 ]]; then
        printf '%s%d REUSED probe(s) missing and --strict was given.%s\n' \
            "$C_YELLOW" "$REUSED_FAIL" "$C_RESET"
        return 1
    fi
    if [[ $REUSED_FAIL -gt 0 ]]; then
        printf '%sAll REQUIRED probes passed.%s %d SIFT-provided tool(s) missing — the\n' \
            "$C_GREEN" "$C_RESET" "$REUSED_FAIL"
        printf 'corresponding MCP tools will report themselves unavailable.\n'
    else
        printf '%sAll REQUIRED and REUSED probes passed.%s\n' "$C_GREEN" "$C_RESET"
    fi
    return 0
}

if [[ $VERIFY_ONLY -eq 1 ]]; then
    do_verify
    exit $?
fi

# --------------------------------------------------------------------------
# Privilege
# --------------------------------------------------------------------------
SCRIPT_PATH=""
if [[ -n "${BASH_SOURCE[0]:-}" && -f "${BASH_SOURCE[0]}" ]]; then
    SCRIPT_PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"
fi

if [[ $USER_MODE -eq 0 && "$(id -u)" -ne 0 ]]; then
    if [[ -n "$SCRIPT_PATH" ]] && command -v sudo >/dev/null 2>&1; then
        # sudo sets SUDO_USER for us, which is how TARGET_USER stays correct.
        printf 'Re-running under sudo (a system install writes to %s and %s)...\n' "$PREFIX" "$BINDIR"
        exec sudo -- "$SCRIPT_PATH" ${ORIG_ARGS[@]+"${ORIG_ARGS[@]}"}
    fi
    fail "a system install needs root.
    Run:  sudo ./install.sh ${ORIG_ARGS[*]}
    Or:   curl -fsSL https://raw.githubusercontent.com/calebevans/mulder/main/install.sh | sudo bash
    For a sudo-free partial install into \$HOME, pass --user."
fi

# --------------------------------------------------------------------------
# Locate the repo — one script serves both `git clone && ./install.sh` and
# `curl … | sudo bash`.
# --------------------------------------------------------------------------
SCRIPT_DIR=""
[[ -n "$SCRIPT_PATH" ]] && SCRIPT_DIR="$(dirname "$SCRIPT_PATH")"

if [[ -n "$SCRIPT_DIR" && -f "$SCRIPT_DIR/pyproject.toml" && -d "$SCRIPT_DIR/src/mulder" ]]; then
    REPO_DIR="$SCRIPT_DIR"
else
    command -v git >/dev/null 2>&1 || fail "git is required to fetch the mulder source"
    WORK_DIR="$(mktemp -d)"
    CLEANUP_DIRS+=("$WORK_DIR")
    printf 'Cloning %s (%s)...\n' "$REPO_URL" "$REF"
    git clone --depth=1 --branch "$REF" "$REPO_URL" "$WORK_DIR/repo" >/dev/null 2>&1 \
        || fail "clone of $REPO_URL@$REF failed"
    REPO_DIR="$WORK_DIR/repo"
fi

MULDER_VERSION="$(sed -n 's/^version = "\(.*\)"$/\1/p' "$REPO_DIR/pyproject.toml" | head -n1)"
[[ -n "$MULDER_VERSION" ]] || fail "could not read version from $REPO_DIR/pyproject.toml"

TMP_DIR="$(mktemp -d)"
CLEANUP_DIRS+=("$TMP_DIR")

# --------------------------------------------------------------------------
# Banner
# --------------------------------------------------------------------------
cat <<BANNER

${C_BOLD}mulder ${MULDER_VERSION} — SIFT installer${C_RESET}

  tier         ${TIER}
  prefix       ${PREFIX}
  bindir       ${BINDIR}
  workspace    ${WORKSPACE}
  target user  ${TARGET_USER} (${TARGET_HOME})
  arch         ${ARCH}
BANNER

if [[ $USER_MODE -eq 1 ]]; then
    printf '\n%s--user mode:%s /opt assets are skipped. mulder hardcodes absolute paths\n' "$C_YELLOW" "$C_RESET"
    printf 'under /opt, so chainsaw, hayabusa, zircolite, Sigma rules, ATT&CK,\n'
    printf 'signature-base and the mobile tools will report themselves unavailable.\n'
    printf 'Every run needs "mulder investigate --cwd %s ...".\n' "$WORKSPACE"
fi

if [[ $TIER != "minimal" && $USER_MODE -eq 0 ]]; then
    confirm "Continue?" || fail "aborted"
fi

# ==========================================================================
# 1. Preflight
# ==========================================================================
step "Preflight"

OS_ID=""; OS_VER=""
if [[ -r /etc/os-release ]]; then
    # shellcheck disable=SC1091
    OS_ID="$(. /etc/os-release && echo "${ID:-}")"
    OS_VER="$(. /etc/os-release && echo "${VERSION_ID:-}")"
fi
case "$OS_ID:$OS_VER" in
    ubuntu:22.04|ubuntu:24.04) ok "$OS_ID $OS_VER (a supported SIFT platform)" ;;
    ubuntu:*) warn "Ubuntu $OS_VER is outside SIFT's supported set (22.04, 24.04); continuing" ;;
    *)        warn "${OS_ID:-unknown} ${OS_VER:-} is not Ubuntu; continuing on a best-effort basis" ;;
esac

# SIFT has no version file (sift-server-version-file is a test.nop), so this is
# a heuristic used only to tune messages — never to gate behaviour.
ON_SIFT=0
if [[ -d /usr/share/sift || -d /opt/zimmermantools || -f /etc/apt/preferences.d/sift ]] \
   || id sansforensics >/dev/null 2>&1; then
    ON_SIFT=1
    ok "SIFT Workstation detected"
else
    info "no SIFT markers found — installing on a plain host"
fi

PYTHON_BIN="$(command -v python3 || true)"
# SIFT always has python3, but a minimised Ubuntu container (and the CI smoke
# job) does not. Try once to install it rather than failing preflight before
# the apt step that would have provided it.
if [[ -z "$PYTHON_BIN" ]] && command -v apt-get >/dev/null 2>&1 && [[ "$(id -u)" -eq 0 ]]; then
    warn "python3 not found; attempting to install it"
    DEBIAN_FRONTEND=noninteractive apt-get update -qq >/dev/null 2>&1 || true
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
        python3 python3-virtualenv >/dev/null 2>&1 || true
    PYTHON_BIN="$(command -v python3 || true)"
fi
[[ -n "$PYTHON_BIN" ]] || fail "python3 not found. Install it: sudo apt-get install python3"
PY_VER="$("$PYTHON_BIN" -c 'import sys; print("%d.%d" % sys.version_info[:2])')"
if ! "$PYTHON_BIN" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)'; then
    fail "python3 is $PY_VER; mulder requires >= 3.10 (pyproject.toml requires-python)"
fi
if [[ "$PY_VER" == "3.12" ]]; then
    ok "python3 $PY_VER ($PYTHON_BIN) — same minor as the container image"
else
    warn "python3 $PY_VER ($PYTHON_BIN) — the container image uses 3.12; $PY_VER is supported but less tested"
fi

for tool in curl git; do
    command -v "$tool" >/dev/null 2>&1 || warn "$tool is not installed; some steps will be skipped"
done

# Free space, roughly per tier.
case "$TIER" in
    minimal) NEED_MB=1200 ;;
    default) NEED_MB=2500 ;;
    full)    NEED_MB=6000 ;;
    *)       NEED_MB=2500 ;;
esac
# df needs a path that exists. Under --user the prefix's parent may not, and a
# failing command substitution in an assignment aborts the whole run under
# `set -e`, so walk up to the nearest existing ancestor first.
existing_ancestor() {
    local d="$1"
    while [[ -n "$d" && "$d" != "/" && ! -d "$d" ]]; do d="$(dirname "$d")"; done
    printf '%s\n' "${d:-/}"
}
DF_TARGET="$(existing_ancestor "$PREFIX")"
AVAIL_MB="$(df -Pm "$DF_TARGET" 2>/dev/null | awk 'NR==2 {print $4}' || true)"
if [[ -n "$AVAIL_MB" && "$AVAIL_MB" -lt "$NEED_MB" ]]; then
    warn "only ${AVAIL_MB} MB free on ${DF_TARGET}; the $TIER tier wants ~${NEED_MB} MB"
else
    ok "${AVAIL_MB:-?} MB free on ${DF_TARGET}"
fi

mkdir -p "$PREFIX" "$BINDIR"
record "$PREFIX" "$BINDIR/mulder"

# B3: stage .mcp.json into the prefix immediately. Under `curl | sudo bash` the
# repo lives in a mktemp dir behind an EXIT trap, so nothing in the installed
# product may keep a reference to $REPO_DIR.
if [[ -f "$REPO_DIR/.mcp.json" ]]; then
    install -m 0644 "$REPO_DIR/.mcp.json" "$PREFIX/.mcp.json"
    MCP_JSON="$PREFIX/.mcp.json"
    record "$PREFIX/.mcp.json"
    ok "staged .mcp.json into $PREFIX"
else
    MCP_JSON=""
    warn "no .mcp.json in the repo; the workspace will not be seeded"
fi

# ==========================================================================
# 2. apt packages
# ==========================================================================
step "System packages"

export DEBIAN_FRONTEND=noninteractive
APT_UPDATED=0

apt_refresh() {
    [[ $APT_UPDATED -eq 1 ]] && return 0
    if apt-get update -qq >/dev/null 2>&1; then
        APT_UPDATED=1
    else
        warn "apt-get update failed (offline?)"
        APT_UPDATED=1   # do not retry on every call
        return 1
    fi
}

# Installs only what dpkg reports as missing. SIFT pins its own PPA at 899 and
# GIFT at 801 (above the default 500), so an unnecessary `apt install` can pull
# a different build of a package that is already there and working.
apt_install_set() {
    local label="$1"; shift
    local pkg missing=()
    for pkg in "$@"; do
        dpkg -s "$pkg" >/dev/null 2>&1 || missing+=("$pkg")
    done
    if [[ ${#missing[@]} -eq 0 ]]; then
        ok "$label: all present"
        return 0
    fi
    info "$label: installing ${#missing[@]} missing package(s): ${missing[*]}"
    apt_refresh || true
    if apt-get install -y --no-install-recommends "${missing[@]}" >/dev/null 2>&1; then
        ok "$label: installed"
        return 0
    fi
    # A batch install fails wholesale if a single package does not resolve
    # (pasco/tcpxtract/outguess/chkrootkit are not in every Ubuntu release), so
    # fall back to one at a time and report precisely what is unavailable.
    warn "$label: batch install failed, retrying individually"
    for pkg in "${missing[@]}"; do
        apt-get install -y --no-install-recommends "$pkg" >/dev/null 2>&1 \
            || warn "$label: $pkg is unavailable on this release"
    done
    return 0
}

if [[ $USER_MODE -eq 1 ]]; then
    warn "--user: skipping all apt operations"
elif ! command -v apt-get >/dev/null 2>&1; then
    warn "apt-get not found; skipping system packages"
else
    if ! grep -Rqs '^deb .*universe' /etc/apt/sources.list /etc/apt/sources.list.d/ \
       && ! grep -Rqs 'Components:.*universe' /etc/apt/sources.list.d/; then
        if command -v add-apt-repository >/dev/null 2>&1; then
            add-apt-repository -y universe >/dev/null 2>&1 || warn "could not enable the universe component"
        fi
    fi

    # Needed by this installer itself.
    apt_install_set "installer prerequisites" ca-certificates curl git unzip

    # SIFT's own convention is virtualenv, not python3-venv: all 20 of its
    # pip.installed states pass venv_bin=/usr/bin/virtualenv, and it never
    # installs python3-venv, so `python3 -m venv` can fail with
    # "ensurepip is not available". Install a provider only when neither works.
    if [[ ! -x /usr/bin/virtualenv ]] && ! "$PYTHON_BIN" -c 'import ensurepip' >/dev/null 2>&1; then
        apt_install_set "virtualenv provider" python3-virtualenv
        if [[ ! -x /usr/bin/virtualenv ]]; then
            apt_install_set "venv provider" "python${PY_VER}-venv"
        fi
    fi

    # Dockerfile:342-379 minus container-only entries, plus ewf-tools.
    # Every binary here is invoked by mulder via subprocess.
    apt_install_set "forensic tools" \
        yara sleuthkit ewf-tools binutils clamav clamav-freshclam regripper \
        libvshadow-utils libbde-utils libfvde-utils pst-utils \
        libimage-exiftool-perl tshark wireshark-common tcpdump foremost \
        scalpel binwalk testdisk ssdeep hashdeep p7zip-full outguess tcpflow \
        tcpxtract libheif-examples dislocker dc3dd afflib-tools chkrootkit pasco

    if [[ "$TIER" == "full" ]]; then
        # Several hundred MB and it builds an appliance on first use.
        apt_install_set "libguestfs" libguestfs-tools
    else
        info "libguestfs-tools is --full only; extract_disk_guestmount will degrade"
    fi

    if [[ "$TIER" != "minimal" && $DO_MOBILE -eq 1 ]]; then
        # pysqlcipher3 (phone.py:659) has no wheels and must compile.
        apt_install_set "build dependencies" \
            build-essential pkg-config libsqlcipher-dev libffi-dev libssl-dev \
            zlib1g-dev "python${PY_VER}-dev"
    fi

    # Dockerfile:380. Without a signature database clamscan fails at runtime.
    # Skipped on --minimal because the download is ~300 MB and SIFT already
    # ships a populated database.
    if [[ "$TIER" != "minimal" ]] && command -v freshclam >/dev/null 2>&1; then
        if ! compgen -G '/var/lib/clamav/*.c[vl]d' >/dev/null 2>&1; then
            info "seeding the ClamAV signature database (this takes a while)"
            freshclam --quiet >/dev/null 2>&1 || warn "freshclam failed; run 'sudo freshclam' later"
        else
            ok "ClamAV signature database already present"
        fi
    fi

    # §4.1: verify the binaries, not the dpkg state — an apt failure swallowed
    # by a warn can leave dpkg reporting success.
    for bin in yara fls strings clamscan; do
        command -v "$bin" >/dev/null 2>&1 || warn "$bin is still not on PATH after the apt step"
    done
fi

# ==========================================================================
# 3. The mulder virtualenv
# ==========================================================================
step "Python environment"

# D3: /usr/bin/virtualenv first — that is SIFT's venv_bin in every one of its
# own states, and it does not depend on ensurepip. `python3 -m venv` is the
# fallback, never the first choice. uv is never used to provision an
# interpreter: under sudo it would drop a managed CPython into /root/.local
# (mode 0700) and produce a venv that sansforensics cannot execute.
VENV_TOOL=""
make_venv() {
    local dir="$1"
    if [[ -x /usr/bin/virtualenv ]]; then
        if /usr/bin/virtualenv -q -p "$PYTHON_BIN" "$dir" >/dev/null 2>&1; then
            VENV_TOOL="/usr/bin/virtualenv"
            return 0
        fi
        warn "/usr/bin/virtualenv failed for $dir; falling back to python3 -m venv"
    fi
    if "$PYTHON_BIN" -m venv "$dir" >/dev/null 2>&1; then
        VENV_TOOL="python3 -m venv"
        return 0
    fi
    return 1
}

# A broken venv must not brick the installer. Under `set -euo pipefail` a
# failing command inside a substitution fails the assignment and, with no `||`,
# aborts the whole run with no message — and before the --force rebuild below,
# so even --force could not recover. Both guards below are load-bearing.
VENV_VERSION=""
VENV_HEALTHY=0
if [[ -x "$VENV/bin/mulder" ]]; then
    VENV_VERSION="$("$VENV/bin/mulder" --version 2>/dev/null | awk '{print $NF}' || true)"
fi
if [[ -x "$VENV/bin/python3" ]] && "$VENV/bin/python3" -c 'import mulder' >/dev/null 2>&1; then
    VENV_HEALTHY=1
fi
# Scoped to the venv step only — reusing $FORCE here would also re-download
# every gap tool.
REBUILD_VENV=$FORCE
if [[ -d "$VENV" && $VENV_HEALTHY -eq 0 ]]; then
    warn "the venv at $VENV is present but cannot import mulder; rebuilding it"
    REBUILD_VENV=1
    VENV_VERSION=""
fi

if [[ ! -x "$VENV/bin/python3" || $REBUILD_VENV -eq 1 ]]; then
    [[ $REBUILD_VENV -eq 1 && -d "$VENV" ]] && rm -rf "$VENV"
    make_venv "$VENV" || fail "could not create a virtualenv at $VENV.
    Install one of the two providers SIFT/Ubuntu offer:
      sudo apt-get install python3-virtualenv   (preferred, SIFT's convention)
      sudo apt-get install python${PY_VER}-venv"
    ok "created $VENV with $VENV_TOOL"
    # SIFT seeds these up front in every one of its virtualenv.managed states.
    "$VENV/bin/pip" install -q -U pip setuptools wheel >/dev/null 2>&1 \
        || warn "could not upgrade pip/setuptools/wheel in $VENV"
else
    ok "reusing the existing venv at $VENV"
fi
record "$VENV"

# Always reconcile the venv against the repo: `git pull && ./install.sh` is the
# documented upgrade path and must not be a no-op.
if [[ "$VENV_VERSION" == "$MULDER_VERSION" && $FORCE -eq 0 ]]; then
    ok "mulder $MULDER_VERSION already installed in the venv"
else
    [[ -n "$VENV_VERSION" ]] && info "upgrading mulder $VENV_VERSION -> $MULDER_VERSION"
    PIP_TARGET="$REPO_DIR"
    if [[ "$TIER" == "full" ]]; then
        PIP_TARGET="${REPO_DIR}[pdf,stix]"
    fi
    # NEVER `pip install -e`. Under `curl | sudo bash` the repo is a mktemp dir
    # behind an EXIT trap and an editable install would point the finder at a
    # directory that is about to be deleted; from a persistent clone, editable
    # means a later `git checkout` silently mutates the installed product.
    if ! "$VENV/bin/pip" install -q --no-cache-dir "$PIP_TARGET" >/dev/null; then
        if [[ "$TIER" == "full" ]]; then
            warn "install with the [pdf,stix] extras failed; retrying without them"
            "$VENV/bin/pip" install -q --no-cache-dir "$REPO_DIR" >/dev/null \
                || fail "pip install of mulder failed"
        else
            fail "pip install of mulder failed"
        fi
    fi
    ok "installed mulder $MULDER_VERSION (non-editable)"
fi

# Extra runtime dependencies, mirroring Dockerfile:470 and :484. volatility3,
# oletools, python-evtx, python-registry and detect-secrets are already hard
# pyproject.toml dependencies and are deliberately not repeated here.
#
# `evtx` is the Rust package Zircolite needs — NOT a duplicate of python-evtx.
# It overwrites python-evtx's evtx_dump console script, which is harmless
# (mulder uses neither binary; it imports the Evtx module at
# extractors/disk.py:42). Dropping it breaks run_zircolite.
if ! "$VENV/bin/pip" install -q --no-cache-dir \
        stix2 evtx jsonpath-ng colorama tqdm aiohttp lark >/dev/null 2>&1; then
    warn "could not install the Zircolite/ATT&CK helper packages (offline?)"
else
    ok "installed stix2 evtx jsonpath-ng colorama tqdm aiohttp lark"
fi

if [[ "$TIER" != "minimal" && $DO_MOBILE -eq 1 ]]; then
    if "$VENV/bin/pip" install -q --no-cache-dir pysqlcipher3 >/dev/null 2>&1; then
        ok "installed pysqlcipher3 (phone.py:659)"
    else
        warn "pysqlcipher3 did not build; encrypted mobile databases will be unreadable"
    fi
fi

if [[ "$ARCH" == "arm64" && "$TIER" == "full" ]]; then
    # Dockerfile:472-473 — no prebuilt FLOSS binary for arm64.
    "$VENV/bin/pip" install -q --no-cache-dir flare-floss >/dev/null 2>&1 \
        && ok "installed flare-floss (arm64 substitute for the FLOSS binary)" \
        || warn "flare-floss did not install; run_floss will be unavailable on arm64"
fi

# B2: the venv is built as root but is executed by the invoking user.
chmod -R a+rX "$PREFIX" 2>/dev/null || true

# ==========================================================================
# 4. env.sh and the wrapper
# ==========================================================================
step "Launcher and environment"

# DOTNET_ROOT is detected, never copied from the container. SIFT apt-installs
# dotnet-sdk-9.0 at /usr/bin/dotnet; the container's /usr/local/share/dotnet
# does not exist here. The directory test is mandatory: if dotnet is a real
# file in /usr/bin, the naive dirname formula yields DOTNET_ROOT=/usr/bin and
# breaks an otherwise-working dotnet.
DOTNET_ROOT_DETECTED=""
if command -v dotnet >/dev/null 2>&1; then
    _d="$(dirname "$(readlink -f "$(command -v dotnet)")")"
    if [[ -d "$_d/shared/Microsoft.NETCore.App" ]]; then
        DOTNET_ROOT_DETECTED="$_d"
        ok "DOTNET_ROOT=$DOTNET_ROOT_DETECTED"
    else
        info "dotnet found but $_d has no shared/Microsoft.NETCore.App; leaving DOTNET_ROOT unset"
    fi
else
    warn "dotnet not found; EZ Tools operations will report themselves unavailable"
fi

{
    printf '# %s — generated by install.sh on %s; do not edit.\n' "$ENV_FILE" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf '# Re-run the installer to regenerate. Sourced by %s/mulder and by --verify.\n\n' "$BINDIR"
    printf '# The venv MUST come first: mulder shells out to a bare "python3" for\n'
    printf '# ALEAPP (phone.py:1086), iLEAPP (phone.py:1226), Zircolite, pdfid\n'
    printf '# (documents.py:301), pdf-parser (documents.py:365), plaso and volatility.\n'
    printf '# Nothing in src/ uses sys.executable, so python3 must resolve to ours.\n'
    printf 'export PATH="%s/bin:/opt/chainsaw:/opt/hayabusa:${PATH}"\n' "$VENV"
    printf '# Dockerfile:326 — parity; affects only mulder'"'"'s process tree.\n'
    printf 'export DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=true\n'
    printf '# Dockerfile:324 — the bundled claude binary lives in a root-owned venv;\n'
    printf '# an autoupdate attempt by a non-root run fails noisily.\n'
    printf 'export DISABLE_AUTOUPDATE=1\n'
    printf 'export PYTHONDONTWRITEBYTECODE=1\n'
    printf 'export PYTHONUNBUFFERED=1\n'
    if [[ -n "$DOTNET_ROOT_DETECTED" ]]; then
        printf 'export DOTNET_ROOT="%s"\n' "$DOTNET_ROOT_DETECTED"
        if ! command -v dotnet >/dev/null 2>&1; then
            printf 'export PATH="${DOTNET_ROOT}:${PATH}"\n'
        fi
    fi
} >| "$ENV_FILE"
chmod 0644 "$ENV_FILE"
record "$ENV_FILE"
ok "wrote $ENV_FILE"

{
    printf '#!/usr/bin/env bash\n'
    printf '# %s/mulder — generated by install.sh; re-run the installer to change.\n' "$BINDIR"
    printf '. %s\n' "$ENV_FILE"
    printf 'exec %s/bin/mulder "$@"\n' "$VENV"
} >| "$BINDIR/mulder"
chmod 0755 "$BINDIR/mulder"
ok "wrote $BINDIR/mulder"

# uninstall.sh is a repo deliverable but has to survive the repo going away.
if [[ -f "$REPO_DIR/uninstall.sh" ]]; then
    install -m 0755 "$REPO_DIR/uninstall.sh" "$PREFIX/uninstall.sh"
    ln -sfn "$PREFIX/uninstall.sh" "$BINDIR/mulder-uninstall"
    record "$PREFIX/uninstall.sh" "$BINDIR/mulder-uninstall"
    ok "installed $PREFIX/uninstall.sh (also on PATH as mulder-uninstall)"
else
    warn "uninstall.sh not found in the repo; skipping"
fi

# B2 again, now that the wrapper exists.
if as_target "$VENV/bin/python3" -c 'import mulder' >/dev/null 2>&1; then
    ok "$TARGET_USER can import mulder from $VENV"
else
    fail "venv is not usable by $TARGET_USER.
    $VENV/bin/python3 -c 'import mulder' failed as $TARGET_USER.
    Check the mode of every directory on the path to $VENV."
fi
if [[ "$TARGET_USER" == "root" ]] && id nobody >/dev/null 2>&1; then
    # Belt and braces: root can traverse anything, so a root-only run proves
    # nothing about a real non-root SIFT user.
    sudo -u nobody "$VENV/bin/python3" -c 'import mulder' >/dev/null 2>&1 \
        && ok "an unprivileged user (nobody) can import mulder too" \
        || warn "nobody cannot import mulder from $VENV; check directory modes"
fi

# ==========================================================================
# 5. Gap forensic tools
# ==========================================================================
if [[ "$TIER" == "minimal" || $USER_MODE -eq 1 ]]; then
    step "Gap forensic tools"
    info "skipped for the $([[ $USER_MODE -eq 1 ]] && echo '--user' || echo 'minimal') install"
else

step "chainsaw ${CHAINSAW_VERSION}"
if [[ -x /opt/chainsaw/chainsaw && $FORCE -eq 0 ]]; then
    ok "/opt/chainsaw already present"
    CHAINSAW_OK=1
else
    case "$ARCH" in
        arm64) CHAINSAW_ARCH="aarch64-unknown-linux-gnu"; CHAINSAW_SHA="$SHA256_CHAINSAW_ARM64" ;;
        *)     CHAINSAW_ARCH="x86_64-unknown-linux-gnu";  CHAINSAW_SHA="$SHA256_CHAINSAW_AMD64" ;;
    esac
    CHAINSAW_OK=0
    if fetch "https://github.com/WithSecureLabs/chainsaw/releases/download/v${CHAINSAW_VERSION}/chainsaw_${CHAINSAW_ARCH}.tar.gz" "$TMP_DIR/chainsaw.tar.gz"; then
        if verify_sha256 "$TMP_DIR/chainsaw.tar.gz" "$CHAINSAW_SHA" "chainsaw"; then
            mkdir -p /opt/chainsaw
            # Guarded: a truncated or corrupt archive must warn, not abort the
            # whole run under `set -e`.
            if tar xzf "$TMP_DIR/chainsaw.tar.gz" -C /opt/chainsaw --strip-components=1; then
                chmod +x /opt/chainsaw/chainsaw
                CHAINSAW_OK=1
                ok "installed /opt/chainsaw/chainsaw"
            else
                warn "chainsaw archive could not be extracted; skipping"
            fi
        fi
    else
        warn "could not download chainsaw (offline?)"
    fi
fi
if [[ ${CHAINSAW_OK:-0} -eq 1 ]]; then
    # Rules and mappings live in the git repo, not the release tarball.
    if [[ ! -d /opt/chainsaw/rules || $FORCE -eq 1 ]]; then
        if git clone --depth 1 --branch "v${CHAINSAW_VERSION}" \
                https://github.com/WithSecureLabs/chainsaw.git "$TMP_DIR/chainsaw-repo" >/dev/null 2>&1; then
            # `cp -rT`, not `cp -r`: onto an existing directory (the --force
            # path) plain `cp -r` would nest and produce /opt/chainsaw/rules/rules.
            rm -rf /opt/chainsaw/mappings /opt/chainsaw/rules
            mkdir -p /opt/chainsaw/mappings /opt/chainsaw/rules
            cp -rT "$TMP_DIR/chainsaw-repo/mappings" /opt/chainsaw/mappings
            cp -rT "$TMP_DIR/chainsaw-repo/rules" /opt/chainsaw/rules
            ok "installed chainsaw rules and mappings from tag v${CHAINSAW_VERSION}"
        else
            warn "could not clone the chainsaw repo for rules/mappings"
        fi
    else
        ok "chainsaw rules and mappings already present"
    fi
    # B1 — THE most important line in this installer.
    # chainsaw.py:33 sets _CHAINSAW_BINARY = "/usr/local/bin/chainsaw" and
    # execs that literal path at :110, :160, :201 and :243. Only the gate at
    # :448 is PATH-aware, so putting /opt/chainsaw on PATH makes the gate pass
    # while every exec fails with ENOENT, swallowed by the except OSError at
    # :530 — run_chainsaw would be silently, permanently dead. Dockerfile:408
    # creates exactly this symlink.
    ln -sfn /opt/chainsaw/chainsaw /usr/local/bin/chainsaw
    record /opt/chainsaw /usr/local/bin/chainsaw
    ok "linked /usr/local/bin/chainsaw -> /opt/chainsaw/chainsaw"
fi

step "hayabusa ${HAYABUSA_VERSION}"
if [[ -x /opt/hayabusa/hayabusa && $FORCE -eq 0 ]]; then
    ok "/opt/hayabusa already present"
    record /opt/hayabusa
elif [[ "$ARCH" != "amd64" ]]; then
    # Dockerfile:135-145 builds hayabusa from source via rustup on arm64
    # because the prebuilt aarch64-gnu binary needs GLIBC >= 2.38. A rustup
    # toolchain build is not something an installer should do unattended.
    warn "hayabusa ships a prebuilt binary for amd64 only; skipping on $ARCH (run_hayabusa unavailable).
      Build it yourself: https://github.com/Yamato-Security/hayabusa"
else
    if fetch "https://github.com/Yamato-Security/hayabusa/releases/download/v${HAYABUSA_VERSION}/hayabusa-${HAYABUSA_VERSION}-lin-x64-musl.zip" "$TMP_DIR/hayabusa.zip"; then
        if verify_sha256 "$TMP_DIR/hayabusa.zip" "$SHA256_HAYABUSA_AMD64" "hayabusa"; then
            mkdir -p /opt/hayabusa
            # Guarded: a corrupt archive must warn, not abort the run.
            if unzip -qo "$TMP_DIR/hayabusa.zip" -d /opt/hayabusa; then
                chmod +x "/opt/hayabusa/hayabusa-${HAYABUSA_VERSION}-lin-x64-musl"
                # hayabusa.py:35 looks for /opt/hayabusa/hayabusa specifically.
                ln -sfn "/opt/hayabusa/hayabusa-${HAYABUSA_VERSION}-lin-x64-musl" /opt/hayabusa/hayabusa
                record /opt/hayabusa
                ok "installed /opt/hayabusa/hayabusa"
            else
                warn "hayabusa archive could not be extracted; skipping"
            fi
        fi
    else
        warn "could not download hayabusa (offline?)"
    fi
fi

step "SigmaHQ rules ${SIGMA_VERSION}"
if [[ -d /opt/sigma-rules/rules && $FORCE -eq 0 ]]; then
    ok "/opt/sigma-rules already present"
    record /opt/sigma-rules
elif fetch "https://github.com/SigmaHQ/sigma/archive/refs/tags/${SIGMA_VERSION}.tar.gz" "$TMP_DIR/sigma.tar.gz"; then
    mkdir -p /opt/sigma-rules
    # The Sigma tarball is deliberately unpinned (a GitHub auto-generated
    # source archive has no stable digest), so a bad archive is a realistic
    # failure and must not abort the run.
    if tar xzf "$TMP_DIR/sigma.tar.gz" -C /opt/sigma-rules --strip-components=1; then
        record /opt/sigma-rules
        ok "installed /opt/sigma-rules (chainsaw.py:34 reads rules/windows/)"
    else
        warn "Sigma rules archive could not be extracted; skipping"
    fi
else
    warn "could not download the SigmaHQ ${SIGMA_VERSION} tarball (offline?)"
fi

step "Zircolite ${ZIRCOLITE_VERSION}"
if [[ -f /opt/zircolite/zircolite.py && $FORCE -eq 0 ]]; then
    ok "/opt/zircolite already present"
    record /opt/zircolite
elif git clone --depth 1 --branch "$ZIRCOLITE_VERSION" \
        https://github.com/wagga40/Zircolite.git /opt/zircolite >/dev/null 2>&1; then
    chmod +x /opt/zircolite/zircolite.py
    record /opt/zircolite
    ok "installed /opt/zircolite at $(git -C /opt/zircolite rev-parse --short HEAD)"
else
    warn "could not clone Zircolite ${ZIRCOLITE_VERSION} (offline?)"
fi
# Dockerfile:511-512 — zircolite.py:32 reads /opt/zircolite/rules/linux/.
if [[ -d /opt/zircolite && -d /opt/sigma-rules/rules/linux ]]; then
    mkdir -p /opt/zircolite/rules/linux
    cp -r /opt/sigma-rules/rules/linux/. /opt/zircolite/rules/linux/ 2>/dev/null || true
    ok "copied the Linux Sigma rules into /opt/zircolite/rules/linux"
fi

step "MITRE ATT&CK STIX data"
if [[ -f /opt/attack/enterprise-attack.json && $FORCE -eq 0 ]]; then
    ok "/opt/attack already present"
    record /opt/attack
else
    mkdir -p /opt/attack
    ATTACK_OK=1
    for feed in enterprise-attack ics-attack; do
        # Staged through $TMP_DIR: curl on 22.04 predates --remove-on-error and
        # would leave a truncated JSON behind, which attack.py would then try
        # to parse on every call.
        if fetch "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/${feed}/${feed}.json" "$TMP_DIR/${feed}.json"; then
            install -m 0644 "$TMP_DIR/${feed}.json" "/opt/attack/${feed}.json"
        else
            ATTACK_OK=0
            warn "could not download ${feed}.json (offline?)"
        fi
    done
    if [[ $ATTACK_OK -eq 1 ]]; then
        record /opt/attack
        ok "installed /opt/attack (attack.py:24-25); unpinned upstream master"
    fi
fi

step "CAPA ${CAPA_VERSION}"
if [[ -x /opt/capa/capa && $FORCE -eq 0 ]]; then
    ok "/opt/capa already present"
    record /opt/capa /usr/local/bin/capa
else
    case "$ARCH" in
        arm64) CAPA_ARCH="linux-arm64"; CAPA_SHA="$SHA256_CAPA_ARM64" ;;
        *)     CAPA_ARCH="linux";       CAPA_SHA="$SHA256_CAPA_AMD64" ;;
    esac
    if fetch "https://github.com/mandiant/capa/releases/download/v${CAPA_VERSION}/capa-v${CAPA_VERSION}-${CAPA_ARCH}.zip" "$TMP_DIR/capa.zip"; then
        if verify_sha256 "$TMP_DIR/capa.zip" "$CAPA_SHA" "capa"; then
            mkdir -p /opt/capa
            if unzip -qo "$TMP_DIR/capa.zip" -d /opt/capa; then
                chmod +x /opt/capa/capa
                # binary.py:43 falls back to /usr/local/bin/capa after PATH.
                ln -sfn /opt/capa/capa /usr/local/bin/capa
                record /opt/capa /usr/local/bin/capa
                ok "installed /usr/local/bin/capa"
            else
                warn "capa archive could not be extracted; skipping"
            fi
        fi
    else
        warn "could not download CAPA (offline?)"
    fi
fi

fi  # end gap forensic tools

# ==========================================================================
# 6. EZ Tools — probe, additive only
# ==========================================================================
if [[ "$TIER" == "minimal" || $USER_MODE -eq 1 ]]; then
    :
else
step "EZ Tools (.NET 9)"
if ! command -v dotnet >/dev/null 2>&1; then
    warn "dotnet is not installed; skipping EZ Tools entirely.
      _run_ez_tool already returns 'dotnet not found on PATH'.
      On SIFT: sudo apt-get install dotnet-sdk-9.0"
else
    EZ_TARGET="$EZ_DIR"
    if [[ -d "$EZ_DIR" ]]; then
        # SIFT owns /opt/zimmermantools. Additive only: never modify or delete
        # an existing entry. Its own bash wrappers in /usr/local/bin resolve
        # against the DLLs it shipped, and a net9 DLL dropped beside a net6 one
        # would break them *and* make _find_ez_tool's candidates[0]
        # nondeterministic (rglob order is os.scandir order, not sorted).
        EZ_TARGET="$EZ_DIR/mulder-extra"
        info "$EZ_DIR exists (SIFT); missing DLLs go to $EZ_TARGET"
    fi
    EZ_MISSING=()
    for dll in "${EZ_DLLS[@]}"; do
        if hit="$(ez_find "$dll")"; then
            ok "$dll -> $hit"
        else
            EZ_MISSING+=("${dll%.dll}")
        fi
    done
    if [[ ${#EZ_MISSING[@]} -eq 0 ]]; then
        ok "all six DLLs mulder invokes are already present"
    else
        info "fetching ${#EZ_MISSING[@]} missing tool(s): ${EZ_MISSING[*]}"
        info "deliberately narrower than Dockerfile:80, which fetches eleven"
        mkdir -p "$EZ_TARGET"
        for tool in "${EZ_MISSING[@]}"; do
            # These zips are rebuilt upstream continuously, so there is no
            # stable digest to pin. TLS only.
            if fetch "https://download.ericzimmermanstools.com/net9/${tool}.zip" "$TMP_DIR/${tool}.zip"; then
                unzip -qo "$TMP_DIR/${tool}.zip" -d "$EZ_TARGET" && ok "installed $tool"
            else
                warn "could not download ${tool}.zip (offline?)"
            fi
        done
        [[ "$EZ_TARGET" != "$EZ_DIR" ]] && record "$EZ_TARGET"
    fi
fi
fi

# ==========================================================================
# 7. --full tier assets
# ==========================================================================
if [[ "$TIER" != "full" || $USER_MODE -eq 1 ]]; then
    :
else

step "YARA signature-base"
if [[ $DO_SIGNATURE_BASE -eq 0 ]]; then
    warn "--no-signature-base: run_yara will return 'No YARA rules available'"
elif [[ -d /opt/signature-base/.git && $FORCE -eq 0 ]]; then
    ok "/opt/signature-base already present"
    # Do NOT chown or record a clone we did not create: it may predate us, and
    # recording it would make uninstall.sh delete someone else's data.
    if grep -qxF /opt/signature-base "$PREFIX/MANIFEST" 2>/dev/null; then
        own_by_target /opt/signature-base
        record /opt/signature-base
    else
        info "/opt/signature-base was not installed by mulder; leaving it untouched"
    fi
elif git clone --depth 1 https://github.com/Neo23x0/signature-base.git /opt/signature-base >/dev/null 2>&1; then
    # yara.py:50-60 runs `git -C /opt/signature-base pull --ff-only` as the
    # invoking user with check=False and capture_output=True. A root-owned
    # clone trips git's dubious-ownership guard and fails silently forever.
    own_by_target /opt/signature-base
    record /opt/signature-base
    ok "installed /opt/signature-base, owned by $TARGET_USER"
else
    warn "could not clone signature-base (offline?)"
fi

step "Volatility 3 symbol packs"
if [[ $DO_VOL_SYMBOLS -eq 0 ]]; then
    info "--no-vol-symbols: volatility3 will download symbols on demand"
else
    SYM_DIR="$TARGET_HOME/.cache/volatility3/symbols"
    mkdir -p "$SYM_DIR"
    for pack in windows linux; do
        if [[ -f "$SYM_DIR/${pack}.zip" && $FORCE -eq 0 ]]; then
            ok "${pack}.zip already present"
        elif fetch "https://downloads.volatilityfoundation.org/volatility3/symbols/${pack}.zip" "$TMP_DIR/${pack}.zip"; then
            install -m 0644 "$TMP_DIR/${pack}.zip" "$SYM_DIR/${pack}.zip"
            ok "installed $SYM_DIR/${pack}.zip (unpinned upstream)"
        else
            warn "could not download the ${pack} symbol pack (offline?)"
        fi
    done
    # $TARGET_HOME, never $HOME: under sudo $HOME is /root and volatility3
    # would never look there.
    own_by_target "$TARGET_HOME/.cache/volatility3"
fi

step "FLOSS ${FLOSS_VERSION} and Detect-It-Easy ${DIE_VERSION}"
if [[ "$ARCH" != "amd64" ]]; then
    warn "FLOSS and Detect-It-Easy ship amd64 binaries only; skipping on $ARCH"
else
    if [[ -x /opt/floss/floss && $FORCE -eq 0 ]]; then
        ok "/opt/floss already present"
        record /opt/floss /usr/local/bin/floss
    elif fetch "https://github.com/mandiant/flare-floss/releases/download/v${FLOSS_VERSION}/floss-v${FLOSS_VERSION}-linux.zip" "$TMP_DIR/floss.zip"; then
        if verify_sha256 "$TMP_DIR/floss.zip" "$SHA256_FLOSS_AMD64" "floss"; then
            mkdir -p /opt/floss
            if unzip -qo "$TMP_DIR/floss.zip" -d /opt/floss; then
                chmod +x /opt/floss/floss
                ln -sfn /opt/floss/floss /usr/local/bin/floss
                record /opt/floss /usr/local/bin/floss
                ok "installed /usr/local/bin/floss"
            else
                warn "floss archive could not be extracted; skipping"
            fi
        fi
    else
        warn "could not download FLOSS (offline?)"
    fi

    if command -v diec >/dev/null 2>&1 && [[ $FORCE -eq 0 ]]; then
        ok "diec already installed"
    elif fetch "https://github.com/horsicq/DIE-engine/releases/download/${DIE_VERSION}/die_${DIE_VERSION}_Ubuntu_22.04_amd64.deb" "$TMP_DIR/die.deb"; then
        if verify_sha256 "$TMP_DIR/die.deb" "$SHA256_DIE_AMD64" "die"; then
            # The .deb targets Ubuntu 22.04; on 24.04 dependency resolution can
            # fail. binary.py:45 looks for `diec`, not `die`.
            if dpkg -i "$TMP_DIR/die.deb" >/dev/null 2>&1 \
               || { apt_refresh; apt-get install -yf >/dev/null 2>&1; }; then
                command -v diec >/dev/null 2>&1 \
                    && ok "installed Detect-It-Easy (diec)" \
                    || warn "the DIE package installed but diec is not on PATH"
            else
                warn "Detect-It-Easy ${DIE_VERSION} targets Ubuntu 22.04 and did not install here; run_die unavailable"
            fi
        fi
    else
        warn "could not download Detect-It-Easy (offline?)"
    fi
fi

step "Mobile and document tooling"
if [[ $DO_MOBILE -eq 0 ]]; then
    warn "--no-mobile: ALEAPP and iLEAPP will report themselves unavailable"
else
    for pair in "aleapp:https://github.com/abrignoni/ALEAPP.git" \
                "ileapp:https://github.com/abrignoni/iLEAPP.git"; do
        name="${pair%%:*}"; url="${pair#*:}"
        if [[ -d "/opt/$name/.git" && $FORCE -eq 0 ]]; then
            ok "/opt/$name already present"
            record "/opt/$name"
        elif git clone --depth 1 "$url" "/opt/$name" >/dev/null 2>&1; then
            record "/opt/$name"
            ok "installed /opt/$name at $(git -C "/opt/$name" rev-parse --short HEAD)"
        else
            warn "could not clone $url (offline?)"
        fi
    done
    # Dockerfile:502-505: strip every version pin and drop non-PyPI entries,
    # otherwise ALEAPP's and iLEAPP's requirements conflict with each other.
    if [[ -f /opt/aleapp/requirements.txt || -f /opt/ileapp/requirements.txt ]]; then
        cat /opt/aleapp/requirements.txt /opt/ileapp/requirements.txt 2>/dev/null \
            | sed 's/[;].*//; s/==.*//; s/>=.*//; s/<=.*//; s/~=.*//' \
            | grep -v '^\s*#' | grep -v '^\s*$' | grep -v '/' | sort -u \
            >| "$TMP_DIR/leapp-reqs.txt" || true
        if "$VENV/bin/pip" install -q --no-cache-dir -r "$TMP_DIR/leapp-reqs.txt" >/dev/null 2>&1; then
            ok "installed the pin-stripped ALEAPP/iLEAPP requirements"
        else
            warn "some ALEAPP/iLEAPP requirements did not install; the tools may still work"
        fi
    fi
fi

if [[ -d /opt/didier-stevens/.git && $FORCE -eq 0 ]]; then
    ok "/opt/didier-stevens already present"
    record /opt/didier-stevens
elif git clone --depth 1 https://github.com/DidierStevens/DidierStevensSuite.git /opt/didier-stevens >/dev/null 2>&1; then
    chmod +x /opt/didier-stevens/pdfid.py /opt/didier-stevens/pdf-parser.py 2>/dev/null || true
    record /opt/didier-stevens
    ok "installed /opt/didier-stevens (documents.py:38-39)"
else
    warn "could not clone DidierStevensSuite (offline?)"
fi

step "LiteLLM proxy"
if [[ $DO_LITELLM -eq 0 ]]; then
    info "--no-litellm: non-Anthropic models via the proxy will be unavailable"
elif [[ -x /opt/litellm/bin/litellm && $FORCE -eq 0 ]]; then
    ok "/opt/litellm already present"
    ln -sfn /opt/litellm/bin/litellm /usr/local/bin/litellm
    record /opt/litellm /usr/local/bin/litellm
else
    # Must not share the mulder venv: Dockerfile:521-522 documents a hard
    # conflict with mulder's mcp>=1.27 and rich>=15.0. Built with the same
    # bootstrap as the mulder venv, not a bare `python3 -m venv`.
    if make_venv /opt/litellm; then
        if /opt/litellm/bin/pip install -q --no-cache-dir 'litellm[proxy]' pyyaml >/dev/null 2>&1; then
            # proxy.py:202 uses shutil.which("litellm"): the symlink is the
            # load-bearing part, not the path.
            ln -sfn /opt/litellm/bin/litellm /usr/local/bin/litellm
            chmod -R a+rX /opt/litellm 2>/dev/null || true
            record /opt/litellm /usr/local/bin/litellm
            ok "installed /opt/litellm and linked /usr/local/bin/litellm"
        else
            warn "litellm[proxy] did not install (offline?)"
        fi
    else
        warn "could not create the LiteLLM venv"
    fi
fi

fi  # end --full assets

# ==========================================================================
# 8. Investigation workspace
# ==========================================================================
step "Investigation workspace"
if [[ -d "$WORKSPACE" ]]; then
    # Never clobber an in-flight investigation.
    ok "$WORKSPACE already exists; leaving it alone"
    if [[ -n "$MCP_JSON" && ! -f "$WORKSPACE/.mcp.json" ]]; then
        install -m 0644 "$MCP_JSON" "$WORKSPACE/.mcp.json"
        own_by_target "$WORKSPACE/.mcp.json"
        ok "seeded the missing $WORKSPACE/.mcp.json"
    fi
elif [[ -z "$MCP_JSON" ]]; then
    warn "no staged .mcp.json; skipping workspace creation"
else
    mkdir -p "$WORKSPACE"
    install -m 0644 "$MCP_JSON" "$WORKSPACE/.mcp.json"
    if command -v git >/dev/null 2>&1; then
        (
            cd "$WORKSPACE"
            git init -q >/dev/null 2>&1
            git config user.email "mulder@local"
            git config user.name "mulder"
            git add -A >/dev/null 2>&1
            git commit -q -m "init" >/dev/null 2>&1
        ) || warn "could not git-init $WORKSPACE"
    fi
    own_by_target "$WORKSPACE"
    ok "created $WORKSPACE, owned by $TARGET_USER"
fi

# ==========================================================================
# 9. MCP registration (optional)
# ==========================================================================
step "Claude Code MCP registration"
# Carry a previous run's registration forward. Re-running install.sh without
# --register-mcp must not make uninstall.sh forget to deregister.
if [[ -z "${MCP_REGISTERED:-}" ]] && [[ -f "$PREFIX/VERSION" ]]; then
    MCP_REGISTERED="$(sed -n 's/^MCP_REGISTERED=//p' "$PREFIX/VERSION" | head -n1 || true)"
fi
if [[ $REGISTER_MCP -eq 0 ]]; then
    info "not requested. To register mulder as an MCP server later, run as $TARGET_USER:"
    printf '      claude mcp add mulder %s/mulder serve --scope user\n' "$BINDIR"
else
    CLAUDE_BIN="$(command -v claude || true)"
    # Protocol SIFT installs the CLI here.
    [[ -z "$CLAUDE_BIN" && -x "$TARGET_HOME/.local/bin/claude" ]] && CLAUDE_BIN="$TARGET_HOME/.local/bin/claude"
    if [[ -z "$CLAUDE_BIN" ]]; then
        warn "no claude CLI found; skipping MCP registration"
    else
        as_target "$CLAUDE_BIN" mcp remove mulder --scope user >/dev/null 2>&1 || true
        as_target "$CLAUDE_BIN" mcp add mulder "$BINDIR/mulder" serve --scope user >/dev/null 2>&1 || true
        # Verify after writing — a silent registration failure leaves a hollow
        # Claude that never sees any mulder tool.
        if as_target "$CLAUDE_BIN" mcp list 2>/dev/null | grep -q mulder; then
            ok "registered mulder with the claude CLI (user scope)"
            MCP_REGISTERED=1
        else
            warn "MCP registration did not take; register manually:
      claude mcp add mulder $BINDIR/mulder serve --scope user"
        fi
    fi
fi

# ==========================================================================
# 10. Record the install
# ==========================================================================
step "Recording the install"

{
    printf 'MULDER_VERSION=%s\n' "$MULDER_VERSION"
    printf 'TIER=%s\n' "$TIER"
    printf 'INSTALLED_AT=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf 'TARGET_USER=%s\n' "$TARGET_USER"
    printf 'TARGET_HOME=%s\n' "$TARGET_HOME"
    printf 'PREFIX=%s\n' "$PREFIX"
    printf 'BINDIR=%s\n' "$BINDIR"
    printf 'WORKSPACE=%s\n' "$WORKSPACE"
    printf 'ARCH=%s\n' "$ARCH"
    printf 'USER_MODE=%s\n' "$USER_MODE"
    printf 'MCP_REGISTERED=%s\n' "${MCP_REGISTERED:-0}"
} >| "$PREFIX/VERSION"
chmod 0644 "$PREFIX/VERSION"
record "$PREFIX/VERSION"

# Merge with any previous manifest so a --minimal re-run cannot drop the
# entries a --full run recorded.
{
    [[ -f "$PREFIX/MANIFEST" ]] && cat "$PREFIX/MANIFEST"
    printf '%s\n' "${MANIFEST_PATHS[@]}"
} | grep -v '^$' | sort -u >| "$TMP_DIR/manifest"
install -m 0644 "$TMP_DIR/manifest" "$PREFIX/MANIFEST"
ok "wrote $PREFIX/MANIFEST ($(wc -l < "$PREFIX/MANIFEST" | tr -d ' ') paths)"

chmod -R a+rX "$PREFIX" 2>/dev/null || true

# ==========================================================================
# 11. Verify and runbook
# ==========================================================================
step "Verification"
VERIFY_RC=0
do_verify || VERIFY_RC=$?

RUN_AS_NOTE=""
[[ "$TARGET_USER" == "root" ]] && RUN_AS_NOTE=" (on SIFT this would be sansforensics, not root)"
CWD_NOTE=""
[[ $USER_MODE -eq 1 ]] && CWD_NOTE=" \\
         --cwd $WORKSPACE"

cat <<RUNBOOK

${C_BOLD}Next steps${C_RESET}

  1. Provide credentials for your model provider, for example:

       export ANTHROPIC_API_KEY=sk-ant-...

     Vertex AI, Bedrock and LiteLLM are configured the same way as in the
     container. See docs/usage-guide.md.

  2. Run an investigation as ${TARGET_USER}${RUN_AS_NOTE}:

       mulder investigate /path/to/evidence my-case-id${CWD_NOTE}

  3. Case databases, audit logs and reports land in:

       ${TARGET_HOME}/.mulder/cases

  4. Re-check the install at any time (from the repo checkout):

       ./install.sh --verify            # REQUIRED probes only
       ./install.sh --verify --strict   # also fails on missing SIFT tools

  5. Uninstall:

       sudo mulder-uninstall

  Docs: docs/sift-install.md
RUNBOOK

if [[ $ON_SIFT -eq 0 ]]; then
    printf '\nThis host has no SIFT markers, so the REUSED probes above are expected to\n'
    printf 'miss. On a real SIFT Workstation they resolve to SIFT-provided tools.\n'
fi
if [[ $WARN_COUNT -gt 0 ]]; then
    printf '\n%s%d warning(s) were emitted above.%s\n' "$C_YELLOW" "$WARN_COUNT" "$C_RESET"
fi
exit $VERIFY_RC
