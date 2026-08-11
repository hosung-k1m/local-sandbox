#!/bin/sh
set -eu

# `boxedai build-image` npm-installs Claude Code/Codex inside a fresh guest.
# On Block's network, the guest must trust Cloudflare Gateway's intercepting
# CA and use Block's npm virtual registry because public registry.npmjs.org is
# blocked by dependency-confusion policy. Lima's provision.system mode only
# warns and continues on a script failure, so a missing setting surfaces later,
# at build-image's Verify step, as "Claude Code executable verification failed"
# rather than as the underlying npm error. Run this once to configure both
# settings, then retry build-image.
#
# Usage: scripts/trust-corporate-ca.sh ["Certificate Common Name"]
# Defaults to "Cloudflare Gateway CA" (Block's WARP Gateway cert). Pass a
# different name if your keychain's corporate CA is labeled differently.

CERT_NAME="${1:-Cloudflare Gateway CA}"
BOXEDAI_HOME="${BOXEDAI_HOME:-$HOME/.boxedai}"

command -v python3 >/dev/null 2>&1 || {
  echo "trust-corporate-ca: python3 not found" >&2
  exit 1
}

mkdir -p "$BOXEDAI_HOME"

CERT_NAME="$CERT_NAME" CONFIG_PATH="$BOXEDAI_HOME/config.json" python3 <<'PYEOF'
import json
import os
import subprocess

cert_name = os.environ["CERT_NAME"]
config_path = os.environ["CONFIG_PATH"]

try:
    pem = subprocess.check_output(
        ["security", "find-certificate", "-c", cert_name, "-p",
         "/Library/Keychains/System.keychain"],
        text=True,
    )
except (subprocess.CalledProcessError, FileNotFoundError):
    raise SystemExit(
        f"trust-corporate-ca: no certificate named {cert_name!r} in the System keychain"
    )

config = {}
if os.path.exists(config_path):
    with open(config_path) as f:
        config = json.load(f)

# Merge rather than overwrite: config.json also carries model upstream refs
# and adapter allowlists (session.HostConfig) that this script must not drop.
config["extra_ca_pem"] = pem
config["npm_registry"] = "https://global.block-artifacts.com/artifactory/api/npm/square-npm/"

with open(config_path, "w") as f:
    json.dump(config, f, indent=2)
    f.write("\n")
os.chmod(config_path, 0o600)

print(
    f"trust-corporate-ca: configured {cert_name!r} and Block's npm virtual registry "
    f"in {config_path}"
)
PYEOF

echo "Retry: dist/boxedai build-image"
