#!/usr/bin/env bash
# Mulder installer.
#
#   curl -fsSL https://raw.githubusercontent.com/calebevans/mulder/main/install.sh | bash
#
# Installs, in one pass:
#   1. the OS packages mulder cannot run without   (apt, needs sudo)
#   2. mulder itself                               (pipx, no sudo)
#   3. the forensic data and helper tools          (mulder setup, no sudo)
#
# It asks once, up front, listing exactly what it will do. Nothing is installed
# before you answer.
#
# This script deliberately implements none of that itself: apt owns the system
# packages, pipx owns the virtualenv and the entry point, and `mulder setup`
# owns the assets. It has no uninstaller because `pipx uninstall mulder-dfir`
# already is one.
#
# Options (after `| bash -s --`):
#   --yes           do not prompt
#   --skip-setup    stop after installing mulder; skip the ~2.1 GB asset download
#   --ref REF       install from this git ref instead of PyPI (for testing)

set -euo pipefail

PACKAGE="mulder-dfir[forensics]"
REPO="https://github.com/calebevans/mulder"
ASSUME_YES=0
SKIP_SETUP=0
GIT_REF="${MULDER_INSTALL_REF:-}"

while [ $# -gt 0 ]; do
    case "$1" in
        --yes|-y)     ASSUME_YES=1 ;;
        --skip-setup) SKIP_SETUP=1 ;;
        --ref)        GIT_REF="${2:-}"; shift ;;
        -h|--help)    sed -n '2,24p' "$0"; exit 0 ;;
        *)            echo "unknown option: $1" >&2; exit 2 ;;
    esac
    shift
done

red()  { printf '\033[31m%s\033[0m\n' "$*"; }
bold() { printf '\033[1m%s\033[0m\n' "$*"; }
dim()  { printf '\033[2m%s\033[0m\n' "$*"; }
die()  { red "$*" >&2; exit 1; }

# --------------------------------------------------------------- preflight ---

[ "$(uname -s)" = "Linux" ] || die "Mulder's forensic toolchain is Linux-only (found $(uname -s)).
  On macOS or Windows, use the container: docker pull ghcr.io/calebevans/mulder:dev"

# Running as root would put the asset clones under root ownership; git then
# refuses to operate on them as your normal user ("detected dubious ownership")
# and YARA rule updates stop permanently and silently. `mulder setup` enforces
# this too -- catching it here just gives a better message.
[ "$(id -u)" != "0" ] || die "Do not run this as root or with sudo.
  Run it as the user who will run mulder; it will ask for sudo only for apt."

command -v apt-get >/dev/null 2>&1 || die "This installer supports apt-based systems (Debian, Ubuntu, SIFT).
  Elsewhere, install the equivalents of: git sleuthkit yara p7zip-full binutils
  then run: pipx install \"$PACKAGE\" && mulder setup"

# ------------------------------------------------- what is actually missing ---

# Only mulder's FATAL requirements are listed. The wider forensic toolchain
# (tshark, Zeek, Suricata, radare2, ...) is optional: each tool that needs one
# reports it at call time with the apt line to fix it. Installing 30 packages
# nobody asked for is not this script's job.
#
# command -> apt package
REQUIRED="git:git fls:sleuthkit icat:sleuthkit mmls:sleuthkit fsstat:sleuthkit \
istat:sleuthkit yara:yara 7z:p7zip-full strings:binutils"

missing_pkgs=""
for pair in $REQUIRED; do
    cmd="${pair%%:*}"
    pkg="${pair##*:}"
    if ! command -v "$cmd" >/dev/null 2>&1; then
        case " $missing_pkgs " in
            *" $pkg "*) ;;
            *) missing_pkgs="$missing_pkgs $pkg" ;;
        esac
    fi
done
missing_pkgs="${missing_pkgs# }"

need_pipx=0
command -v pipx >/dev/null 2>&1 || need_pipx=1

if [ -n "$GIT_REF" ]; then
    SPEC="$PACKAGE @ git+${REPO}@${GIT_REF}"
else
    SPEC="$PACKAGE"
fi

# ------------------------------------------------------------------- plan ----

echo
bold "Mulder installer"
echo
step1="$missing_pkgs"
if [ "$need_pipx" = "1" ]; then step1="$step1 pipx"; fi
step1="$(echo "$step1" | tr -s " " | sed "s/^ //;s/ $//")"

if [ -n "$step1" ]; then
    echo "  1. apt install   $step1"
    dim "     (asks for your sudo password)"
else
    echo "  1. apt install   nothing -- you already have everything mulder requires"
fi
echo "  2. pipx install  $SPEC"
if [ "$SKIP_SETUP" = "1" ]; then
    echo "  3. mulder setup  skipped (--skip-setup)"
else
    echo "  3. mulder setup  forensic data, rule sets and helper tools (~2.1 GB)"
fi
echo
dim "  Everything except step 1 installs under \$HOME. Nothing is written to /opt."
echo

if [ "$ASSUME_YES" != "1" ]; then
    # stdin is the script itself under `curl | bash`, so read from the terminal.
    if [ -r /dev/tty ]; then
        printf 'Proceed? [Y/n] '
        read -r reply < /dev/tty
    else
        die "No terminal available to confirm. Re-run with --yes:
  curl -fsSL ${REPO}/raw/main/install.sh | bash -s -- --yes"
    fi
    case "${reply:-y}" in
        [Yy]|[Yy][Ee][Ss]|"") ;;
        *) echo "Aborted."; exit 0 ;;
    esac
fi

# ------------------------------------------------------------- 1. packages ---

apt_targets="$missing_pkgs"
if [ "$need_pipx" = "1" ]; then
    # 24.04 ships python3-pipx as `pipx`; 22.04 does not package it at all.
    if apt-cache show pipx >/dev/null 2>&1; then
        apt_targets="$apt_targets pipx"
    fi
fi
apt_targets="$(echo "$apt_targets" | tr -s ' ' | sed 's/^ //;s/ $//')"

if [ -n "$apt_targets" ]; then
    bold "==> Installing system packages: $apt_targets"
    sudo apt-get update -qq
    # shellcheck disable=SC2086 -- deliberate word splitting into package args
    sudo apt-get install -y $apt_targets
fi

if ! command -v pipx >/dev/null 2>&1; then
    # 22.04 and anything else without the package: PEP 668 does not apply there,
    # so a --user install is the supported path.
    bold "==> Installing pipx for this user"
    python3 -m pip install --user pipx || die "Could not install pipx.
  Install it however your distribution prefers, then re-run this script."
fi

export PATH="$HOME/.local/bin:$PATH"
pipx ensurepath >/dev/null 2>&1 || true

# --------------------------------------------------------------- 2. mulder ---

bold "==> Installing mulder"
pipx install --force "$SPEC"
hash -r

command -v mulder >/dev/null 2>&1 || die "mulder installed but is not on \$PATH.
  Add this to your shell profile, then re-run:
    export PATH=\"\$HOME/.local/bin:\$PATH\""

mulder --version

# ---------------------------------------------------------------- 3. assets ---

if [ "$SKIP_SETUP" != "1" ]; then
    bold "==> Downloading forensic data and helper tools"
    mulder setup --yes
fi

# ----------------------------------------------------------------- finish ----

echo
bold "Done."
echo
if ! echo ":$PATH:" | grep -q ":$HOME/.local/bin:"; then
    red "  \$HOME/.local/bin is not on your PATH in new shells."
    echo "  Add this to your shell profile:"
    echo "      export PATH=\"\$HOME/.local/bin:\$PATH\""
    echo
fi
echo "  Set a credential, then start an investigation:"
echo
echo "      export ANTHROPIC_API_KEY=sk-ant-..."
echo "      mulder investigate /path/to/evidence my-case-id"
echo
dim "  Check an existing install with: mulder setup --verify"
dim "  Remove mulder with:             pipx uninstall mulder-dfir"
