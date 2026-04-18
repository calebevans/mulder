#!/usr/bin/env bash
# Mulder MCP Server — bare-metal installer for Debian / Ubuntu hosts.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/calebdevans/mulder/main/install.sh | sudo bash
#
# Re-running is safe: every section is idempotent.
# Tested on Ubuntu 22.04 / 24.04 (amd64 & arm64).

set -euo pipefail

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

LIBEWF_VERSION="20240506"
LIBEWF_URL="https://github.com/libyal/libewf/releases/download/${LIBEWF_VERSION}/libewf-experimental-${LIBEWF_VERSION}.tar.gz"
BULK_EXTRACTOR_REPO="https://github.com/simsong/bulk_extractor.git"
STEGDETECT_REPO="https://github.com/redNixon/stegdetect.git"
HAYABUSA_VERSION="3.8.1"
DOTNET_CHANNEL="8.0"
DOTNET_INSTALL_DIR="/usr/local/share/dotnet"
EZ_TOOLS_DIR="/opt/zimmermantools"
EZ_TOOLS=(
    AmcacheParser AppCompatCacheParser EvtxECmd JLECmd LECmd
    MFTECmd PECmd RBCmd RECmd SBECmd SrumECmd
)
YARA_RULES_DIR="/opt/yara-rules"
SIGNATURE_BASE_DIR="/opt/signature-base"
ATTACK_DIR="/opt/attack"
HAYABUSA_DIR="/opt/hayabusa"
VOL_SYMBOLS_DIR="/root/.cache/volatility3/symbols"
PROFILE_SCRIPT="/etc/profile.d/mulder.sh"

BUILD_DIR="$(mktemp -d /tmp/mulder-install.XXXXXX)"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_RED='\033[0;31m'
_GREEN='\033[0;32m'
_YELLOW='\033[0;33m'
_CYAN='\033[0;36m'
_BOLD='\033[1m'
_RESET='\033[0m'

log_info()  { printf "${_CYAN}[INFO]${_RESET}  %s\n" "$*"; }
log_ok()    { printf "${_GREEN}[ OK ]${_RESET}  %s\n" "$*"; }
log_warn()  { printf "${_YELLOW}[WARN]${_RESET}  %s\n" "$*"; }
log_error() { printf "${_RED}[ERR ]${_RESET}  %s\n" "$*" >&2; }
log_section() { printf "\n${_BOLD}==> %s${_RESET}\n" "$*"; }

command_exists() { command -v "$1" &>/dev/null; }

ensure_dir() {
    for d in "$@"; do
        [ -d "$d" ] || mkdir -p "$d"
    done
}

cleanup() {
    rm -rf "$BUILD_DIR"
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# Pre-flight checks
# ---------------------------------------------------------------------------

log_section "Pre-flight checks"

if [ "$(id -u)" -ne 0 ]; then
    log_error "This script must be run as root (or via sudo)."
    exit 1
fi

if [ ! -f /etc/os-release ]; then
    log_error "Cannot detect OS — /etc/os-release not found."
    exit 1
fi

# shellcheck source=/dev/null
. /etc/os-release

case "${ID:-}${ID_LIKE:-}" in
    *debian*|*ubuntu*) ;;
    *)
        log_error "Unsupported OS: ${PRETTY_NAME:-unknown}. This script requires a Debian/Ubuntu-based system."
        exit 1
        ;;
esac

ARCH="$(uname -m)"
case "$ARCH" in
    x86_64)  NORM_ARCH="x64"  ;;
    aarch64) NORM_ARCH="arm64" ;;
    *)
        log_error "Unsupported architecture: $ARCH"
        exit 1
        ;;
esac

log_ok "OS: ${PRETTY_NAME} | Arch: ${ARCH} (${NORM_ARCH})"

# ---------------------------------------------------------------------------
# 1. System packages (apt)
# ---------------------------------------------------------------------------

log_section "Installing system packages"

export DEBIAN_FRONTEND=noninteractive

apt-get update -qq

apt-get install -y --no-install-recommends \
    software-properties-common \
    gnupg \
    ca-certificates \
    curl \
    wget \
    git \
    unzip \
    build-essential \
    autoconf \
    automake \
    libtool \
    flex \
    pkg-config \
    afflib-tools \
    sleuthkit \
    yara \
    libssl3 \
    libssl-dev \
    fuse3 \
    libfuse3-dev \
    regripper \
    clamav clamav-freshclam \
    hashdeep \
    foremost \
    libimage-exiftool-perl \
    binutils \
    libvshadow-utils \
    libbde-utils \
    libfvde-utils \
    dc3dd \
    libguestfs-tools \
    pasco \
    tshark \
    tcpdump \
    ssdeep \
    scalpel \
    binwalk \
    testdisk \
    chkrootkit \
    outguess \
    libheif-examples \
    p7zip-full \
    zlib1g-dev \
    libbz2-dev \
    libjpeg-dev \
    libsqlcipher-dev \
    libre2-dev \
    libsqlite3-dev \
    libffi-dev

log_ok "System packages installed"

# ---------------------------------------------------------------------------
# 2. Python 3.12 (deadsnakes PPA)
# ---------------------------------------------------------------------------

log_section "Setting up Python 3.12"

if ! command_exists python3.12; then
    add-apt-repository -y ppa:deadsnakes/ppa
    apt-get update -qq
    apt-get install -y --no-install-recommends \
        python3.12 \
        python3.12-dev \
        python3.12-venv
    log_ok "Python 3.12 installed via deadsnakes PPA"
else
    log_ok "Python 3.12 already installed"
fi

update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.12 1 2>/dev/null || true
update-alternatives --install /usr/bin/python  python  /usr/bin/python3.12 1 2>/dev/null || true

# ---------------------------------------------------------------------------
# 3. uv (Python package manager)
# ---------------------------------------------------------------------------

log_section "Installing uv"

if ! command_exists uv; then
    curl -LsSf https://astral.sh/uv/install.sh | env UV_INSTALL_DIR="/usr/local/bin" sh
    log_ok "uv installed"
else
    log_ok "uv already installed ($(uv --version))"
fi

# ---------------------------------------------------------------------------
# 4. libewf (build from source)
# ---------------------------------------------------------------------------

log_section "Installing libewf"

if ! ldconfig -p | grep -q libewf; then
    log_info "Building libewf ${LIBEWF_VERSION} from source..."
    curl -fsSL "$LIBEWF_URL" -o "${BUILD_DIR}/libewf.tar.gz"
    tar xzf "${BUILD_DIR}/libewf.tar.gz" -C "$BUILD_DIR"
    (
        cd "${BUILD_DIR}/libewf-${LIBEWF_VERSION}"
        ./configure --prefix=/usr/local --quiet
        make -j"$(nproc)" --quiet
        make install --quiet
    )
    ldconfig
    log_ok "libewf ${LIBEWF_VERSION} installed"
else
    log_ok "libewf already installed"
fi

# ---------------------------------------------------------------------------
# 5. bulk_extractor (build from source with libewf)
# ---------------------------------------------------------------------------

log_section "Installing bulk_extractor"

if ! command_exists bulk_extractor; then
    log_info "Building bulk_extractor from source..."
    git clone --recursive --depth 1 \
        "$BULK_EXTRACTOR_REPO" "${BUILD_DIR}/bulk_extractor"
    (
        cd "${BUILD_DIR}/bulk_extractor"
        export PKG_CONFIG_PATH="/usr/local/lib/pkgconfig:${PKG_CONFIG_PATH:-}"
        export CPPFLAGS="-I/usr/local/include"
        export LDFLAGS="-L/usr/local/lib"
        export LD_LIBRARY_PATH="/usr/local/lib:${LD_LIBRARY_PATH:-}"
        ./bootstrap.sh
        ./configure --prefix=/usr/local --with-libewf=/usr/local --quiet
        make -j"$(nproc)" --quiet
        make install --quiet
    )
    ldconfig
    log_ok "bulk_extractor installed"
else
    log_ok "bulk_extractor already installed ($(bulk_extractor -V 2>&1 | head -1))"
fi

# ---------------------------------------------------------------------------
# 6. stegdetect / stegbreak (build from source)
# ---------------------------------------------------------------------------

log_section "Installing stegdetect"

if ! command_exists stegdetect; then
    log_info "Building stegdetect from source..."
    git clone --depth 1 "$STEGDETECT_REPO" "${BUILD_DIR}/stegdetect"
    (
        cd "${BUILD_DIR}/stegdetect"
        autoreconf -ivf
        CFLAGS="-O2 -fcommon" ./configure --prefix=/usr/local --quiet
        make -j"$(nproc)" --quiet
        mkdir -p /usr/local/bin /usr/local/share /usr/local/man/man1
        make install --quiet
    )
    log_ok "stegdetect installed"
else
    log_ok "stegdetect already installed"
fi

# ---------------------------------------------------------------------------
# 7. .NET 8 Runtime
# ---------------------------------------------------------------------------

log_section "Installing .NET 8 runtime"

if [ ! -x "${DOTNET_INSTALL_DIR}/dotnet" ]; then
    log_info "Installing .NET ${DOTNET_CHANNEL} runtime..."
    curl -fsSL https://dot.net/v1/dotnet-install.sh -o "${BUILD_DIR}/dotnet-install.sh"
    chmod +x "${BUILD_DIR}/dotnet-install.sh"
    "${BUILD_DIR}/dotnet-install.sh" \
        --channel "$DOTNET_CHANNEL" \
        --runtime dotnet \
        --install-dir "$DOTNET_INSTALL_DIR"
    log_ok ".NET ${DOTNET_CHANNEL} runtime installed"
else
    log_ok ".NET runtime already installed"
fi

export DOTNET_ROOT="$DOTNET_INSTALL_DIR"
export PATH="${DOTNET_INSTALL_DIR}:${PATH}"

# ---------------------------------------------------------------------------
# 8. Eric Zimmerman tools
# ---------------------------------------------------------------------------

log_section "Installing Eric Zimmerman tools"

ensure_dir "$EZ_TOOLS_DIR"

for tool in "${EZ_TOOLS[@]}"; do
    if [ -z "$(find "$EZ_TOOLS_DIR" -maxdepth 2 \( -name "${tool}.dll" -o -name "${tool}.exe" \) -print -quit 2>/dev/null)" ]; then
        log_info "Downloading ${tool}..."
        wget -q "https://download.ericzimmermanstools.com/${tool}.zip" \
            -O "${BUILD_DIR}/${tool}.zip"
        unzip -qo "${BUILD_DIR}/${tool}.zip" -d "$EZ_TOOLS_DIR"
        rm -f "${BUILD_DIR}/${tool}.zip"
    else
        log_ok "${tool} already present"
    fi
done

log_ok "Eric Zimmerman tools installed to ${EZ_TOOLS_DIR}"

# ---------------------------------------------------------------------------
# 9. Hayabusa
# ---------------------------------------------------------------------------

log_section "Installing Hayabusa"

if ! command_exists hayabusa && [ ! -x "${HAYABUSA_DIR}/hayabusa" ]; then
    ensure_dir "$HAYABUSA_DIR"

    case "$NORM_ARCH" in
        x64)    HAYABUSA_SUFFIX="lin-x64-musl" ;;
        arm64)  HAYABUSA_SUFFIX="lin-aarch64-musl" ;;
    esac

    HAYABUSA_ZIP="hayabusa-${HAYABUSA_VERSION}-${HAYABUSA_SUFFIX}.zip"
    HAYABUSA_BIN="hayabusa-${HAYABUSA_VERSION}-${HAYABUSA_SUFFIX}"
    HAYABUSA_URL="https://github.com/Yamato-Security/hayabusa/releases/download/v${HAYABUSA_VERSION}/${HAYABUSA_ZIP}"

    log_info "Downloading Hayabusa v${HAYABUSA_VERSION} (${HAYABUSA_SUFFIX})..."
    curl -fsSL "$HAYABUSA_URL" -o "${BUILD_DIR}/hayabusa.zip"
    unzip -qo "${BUILD_DIR}/hayabusa.zip" -d "$HAYABUSA_DIR"
    chmod +x "${HAYABUSA_DIR}/${HAYABUSA_BIN}"
    ln -sf "${HAYABUSA_DIR}/${HAYABUSA_BIN}" "${HAYABUSA_DIR}/hayabusa"
    log_ok "Hayabusa v${HAYABUSA_VERSION} installed"
else
    log_ok "Hayabusa already installed"
fi

# ---------------------------------------------------------------------------
# 10. YARA rule libraries
# ---------------------------------------------------------------------------

log_section "Fetching YARA rules"

if [ ! -d "${SIGNATURE_BASE_DIR}/.git" ]; then
    log_info "Cloning Neo23x0/signature-base..."
    rm -rf "$SIGNATURE_BASE_DIR"
    git clone --depth 1 https://github.com/Neo23x0/signature-base.git "$SIGNATURE_BASE_DIR"
else
    log_info "Updating signature-base..."
    git -C "$SIGNATURE_BASE_DIR" pull --ff-only --quiet || true
fi

if [ ! -d "${YARA_RULES_DIR}/.git" ]; then
    log_info "Cloning Yara-Rules/rules..."
    rm -rf "$YARA_RULES_DIR"
    git clone --depth 1 https://github.com/Yara-Rules/rules.git "$YARA_RULES_DIR"
else
    log_info "Updating yara-rules..."
    git -C "$YARA_RULES_DIR" pull --ff-only --quiet || true
fi

log_ok "YARA rules installed"

# ---------------------------------------------------------------------------
# 11. MITRE ATT&CK STIX data
# ---------------------------------------------------------------------------

log_section "Fetching MITRE ATT&CK data"

ensure_dir "$ATTACK_DIR"

if [ ! -f "${ATTACK_DIR}/enterprise-attack.json" ]; then
    curl -fsSL \
        "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json" \
        -o "${ATTACK_DIR}/enterprise-attack.json"
    log_ok "ATT&CK STIX bundle downloaded"
else
    log_ok "ATT&CK STIX bundle already present"
fi

# ---------------------------------------------------------------------------
# 12. Volatility 3 symbol tables
# ---------------------------------------------------------------------------

log_section "Fetching Volatility 3 symbol tables"

ensure_dir "$VOL_SYMBOLS_DIR"

for sym in windows linux; do
    if [ ! -f "${VOL_SYMBOLS_DIR}/${sym}.zip" ]; then
        log_info "Downloading ${sym}.zip (this may take a while)..."
        wget -q "https://downloads.volatilityfoundation.org/volatility3/symbols/${sym}.zip" \
            -O "${VOL_SYMBOLS_DIR}/${sym}.zip"
    else
        log_ok "${sym}.zip already present"
    fi
done

log_ok "Volatility 3 symbols installed"

# ---------------------------------------------------------------------------
# 13. Python forensic packages
# ---------------------------------------------------------------------------

log_section "Installing Python forensic packages"

uv pip install --system --no-cache \
    volatility3 \
    plaso \
    mvt \
    pysqlcipher3

log_ok "Python forensic packages installed"

# ---------------------------------------------------------------------------
# 14. ClamAV signature update
# ---------------------------------------------------------------------------

log_section "Updating ClamAV signatures"

freshclam --quiet 2>/dev/null || log_warn "freshclam update failed (non-fatal — may need manual run)"

# ---------------------------------------------------------------------------
# 15. Install Mulder
# ---------------------------------------------------------------------------

log_section "Installing Mulder"

MULDER_GIT_URL="git+https://github.com/calebevans/mulder.git"

# When run from a local clone, prefer editable install; otherwise pull from git.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd || echo "")"

if [ -n "$SCRIPT_DIR" ] && [ -f "${SCRIPT_DIR}/pyproject.toml" ]; then
    log_info "Installing mulder from local source (${SCRIPT_DIR})..."
    uv pip install --system --no-cache -e "$SCRIPT_DIR"
else
    log_info "Installing mulder from git..."
    uv pip install --system --no-cache "mulder @ ${MULDER_GIT_URL}"
fi

log_ok "Mulder installed"

# ---------------------------------------------------------------------------
# 16. PATH and environment (persistent)
# ---------------------------------------------------------------------------

log_section "Configuring environment"

cat > "$PROFILE_SCRIPT" << 'ENVEOF'
# Mulder MCP Server — environment setup (managed by install.sh)
export DOTNET_ROOT="/usr/local/share/dotnet"

for _d in "/usr/local/share/dotnet" "/opt/hayabusa"; do
    case ":${PATH}:" in
        *":${_d}:"*) ;;
        *) export PATH="${_d}:${PATH}" ;;
    esac
done
unset _d
ENVEOF

chmod 644 "$PROFILE_SCRIPT"
log_ok "Environment variables written to ${PROFILE_SCRIPT}"

# ---------------------------------------------------------------------------
# 17. Verification
# ---------------------------------------------------------------------------

log_section "Verification"

_check() {
    local name="$1"
    local bin="${2:-$1}"
    if command_exists "$bin"; then
        printf "  ${_GREEN}%-22s${_RESET} %s\n" "$name" "$(command -v "$bin")"
    elif [ -x "/opt/hayabusa/$bin" ] || [ -x "/opt/zimmermantools/$bin" ]; then
        printf "  ${_GREEN}%-22s${_RESET} %s\n" "$name" "(found in /opt)"
    else
        printf "  ${_YELLOW}%-22s${_RESET} %s\n" "$name" "NOT FOUND"
    fi
}

printf "\n  ${_BOLD}%-22s %s${_RESET}\n" "TOOL" "LOCATION"
printf "  %-22s %s\n" "----------------------" "--------------------"

_check "python3.12"        "python3.12"
_check "uv"                "uv"
_check "mulder"            "mulder"
_check "sleuthkit (fls)"   "fls"
_check "sleuthkit (icat)"  "icat"
_check "sleuthkit (mmls)"  "mmls"
_check "mactime"           "mactime"
_check "yara"              "yara"
_check "bulk_extractor"    "bulk_extractor"
_check "ewfmount"          "ewfmount"
_check "volatility3 (vol)" "vol"
_check "log2timeline.py"   "log2timeline.py"
_check "psort.py"          "psort.py"
_check "pinfo.py"          "pinfo.py"
_check "hayabusa"          "hayabusa"
_check "dotnet"            "dotnet"
_check "regripper"         "regripper"
_check "clamscan"          "clamscan"
_check "exiftool"          "exiftool"
_check "tshark"            "tshark"
_check "foremost"          "foremost"
_check "hashdeep"          "hashdeep"
_check "ssdeep"            "ssdeep"
_check "binwalk"           "binwalk"
_check "7z"                "7z"
_check "strings"           "strings"
_check "stegdetect"        "stegdetect"
_check "stegbreak"         "stegbreak"
_check "outguess"          "outguess"
_check "heif-convert"      "heif-convert"
_check "scalpel"           "scalpel"
_check "photorec"          "photorec"
_check "chkrootkit"        "chkrootkit"
_check "guestmount"        "guestmount"
_check "dc3dd"             "dc3dd"
_check "mvt"               "mvt-android"

printf "\n"

_data_check() {
    local name="$1"
    local path="$2"
    if [ -e "$path" ]; then
        printf "  ${_GREEN}%-22s${_RESET} %s\n" "$name" "$path"
    else
        printf "  ${_YELLOW}%-22s${_RESET} %s\n" "$name" "MISSING ($path)"
    fi
}

printf "  ${_BOLD}%-22s %s${_RESET}\n" "DATA ASSET" "LOCATION"
printf "  %-22s %s\n" "----------------------" "--------------------"

_data_check "EZ Tools"          "$EZ_TOOLS_DIR"
_data_check "YARA rules"        "$YARA_RULES_DIR"
_data_check "signature-base"    "$SIGNATURE_BASE_DIR"
_data_check "ATT&CK STIX"      "${ATTACK_DIR}/enterprise-attack.json"
_data_check "Vol symbols (win)" "${VOL_SYMBOLS_DIR}/windows.zip"
_data_check "Vol symbols (lin)" "${VOL_SYMBOLS_DIR}/linux.zip"

printf "\n"
log_ok "Installation complete."
log_info "Run 'source ${PROFILE_SCRIPT}' or start a new shell to pick up PATH changes."
log_info "Start the server with: mulder serve"
