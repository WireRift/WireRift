#!/bin/sh
set -eu

generated_token_file=$(mktemp)
config_file=$(mktemp)
trap 'rm -f "$generated_token_file" "$config_file"' EXIT
printf '%s\n' 'compose-contract-check-only' > "$generated_token_file"

image=${WIRERIFT_IMAGE:-ghcr.io/wirerift/wirerift@sha256:0000000000000000000000000000000000000000000000000000000000000000}
domain=${WIRERIFT_DOMAIN:-compose-check.example}
acme_email=${WIRERIFT_ACME_EMAIL:-ops@compose-check.example}
token_file=${WIRERIFT_TOKEN_FILE:-$generated_token_file}

if [ ! -r "$token_file" ]; then
  printf 'compose security contract: token file is not readable: %s\n' "$token_file" >&2
  exit 1
fi

WIRERIFT_DOMAIN="$domain" \
WIRERIFT_ACME_EMAIL="$acme_email" \
WIRERIFT_TOKEN_FILE="$token_file" \
WIRERIFT_IMAGE="$image" \
  docker compose --profile example config --format json > "$config_file"

python3 - "$config_file" "$image" <<'PY'
import json
import re
import sys

with open(sys.argv[1], encoding="utf-8") as config_file:
    services = json.load(config_file)["services"]
service = services["wirerift-server"]
webapp = services["webapp"]

expected_image = sys.argv[2]
errors = []

def require(condition, message):
    if not condition:
        errors.append(message)

require(service.get("image") == expected_image, "image must preserve the approved digest")
require(re.fullmatch(r".+@sha256:[0-9a-fA-F]{64}", expected_image) is not None,
        "WIRERIFT_IMAGE must be a full immutable image@sha256 digest")
require(service.get("read_only") is True, "root filesystem must be read-only")
require("ALL" in service.get("cap_drop", []), "all Linux capabilities must be dropped")
require(any(option.startswith("no-new-privileges") for option in service.get("security_opt", [])),
        "no-new-privileges must be enabled")
require(service.get("init") is True, "container init must be enabled")
require(any(mount.split(":", 1)[0] == "/tmp" for mount in service.get("tmpfs", [])),
        "/tmp must be a tmpfs")
require(bool(service.get("stop_grace_period")), "stop grace period must be explicit")
require(float(service.get("cpus", 0)) > 0, "CPU ceiling must be positive")
require(int(service.get("mem_limit", 0)) > 0, "memory ceiling must be positive")
require(int(service.get("pids_limit", 0)) > 0, "PID ceiling must be positive")
require(not service.get("privileged", False), "privileged mode must remain disabled")
require(not service.get("cap_add", []), "capabilities must not be added")
require(any(str(port.get("target")) == "4040" and port.get("host_ip") == "127.0.0.1"
            for port in service.get("ports", [])), "dashboard must remain loopback-only")
require(any(secret.get("source") == "wirerift_token" and
            secret.get("target") == "/run/secrets/wirerift_token"
            for secret in service.get("secrets", [])), "token must remain a mounted secret")
require(any(volume.get("target") == "/data/certs" and volume.get("type") == "volume"
            for volume in service.get("volumes", [])), "certificate data must remain writable storage")
require(any(str(port.get("target")) == "80" and port.get("host_ip") == "127.0.0.1"
            for port in webapp.get("ports", [])), "example upstream must remain loopback-only")

if errors:
    for error in errors:
        print(f"compose security contract: {error}", file=sys.stderr)
    raise SystemExit(1)
PY

if env -u WIRERIFT_IMAGE \
  WIRERIFT_DOMAIN=compose-check.example \
  WIRERIFT_ACME_EMAIL=ops@compose-check.example \
  WIRERIFT_TOKEN_FILE="$token_file" \
  docker compose config >/dev/null 2>&1; then
  printf '%s\n' 'compose security contract: WIRERIFT_IMAGE must be required' >&2
  exit 1
fi

printf '%s\n' 'Compose security contract verified'
