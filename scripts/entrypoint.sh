#!/usr/bin/env bash
set -e

MULDER_HOME="/home/mulder"
MULDER_CONFIG="$MULDER_HOME/.config"
mkdir -p "$MULDER_CONFIG"

# Copy mounted credential files to a mulder-accessible location so the
# non-root user can read them without modifying host file permissions.
if [ -f /tmp/gcloud-creds.json ]; then
    cp /tmp/gcloud-creds.json "$MULDER_CONFIG/gcloud-creds.json"
    chown mulder:mulder "$MULDER_CONFIG/gcloud-creds.json"
    export GOOGLE_APPLICATION_CREDENTIALS="$MULDER_CONFIG/gcloud-creds.json"
fi

# Ensure Claude Code project settings enable the mulder MCP server.
PROJ_DIR="$MULDER_HOME/.claude/projects/-mulder-investigation"
mkdir -p "$PROJ_DIR"
if [ ! -f "$PROJ_DIR/settings.local.json" ]; then
    cat > "$PROJ_DIR/settings.local.json" <<'SETTINGS'
{
  "enabledMcpjsonServers": ["mulder"],
  "enableAllProjectMcpServers": true
}
SETTINGS
fi

chown -R mulder:mulder "$MULDER_CONFIG" 2>/dev/null || true
chown -R mulder:mulder "$MULDER_HOME/.mulder" 2>/dev/null || true
# Ensure the cases directory is writable (may be a bind mount from host)
chmod -R a+rwX "$MULDER_HOME/.mulder/cases" 2>/dev/null || true

exec gosu mulder "$@"
